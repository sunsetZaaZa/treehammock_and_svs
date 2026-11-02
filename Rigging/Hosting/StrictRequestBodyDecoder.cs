using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;

namespace treehammock.Rigging.Hosting;

internal static class StrictRequestBodyDecoder
{
    // Input is already fully buffered and bounded. Exhaustion while the codec still
    // needs input is invalid data, never a clean EOF (including on .NET 8).
    private sealed class CompleteInput(byte[] bytes, int offset, int count) : Stream
    {
        private readonly MemoryStream _input = new(bytes, offset, count, writable: false);
        public override bool CanRead => true; public override bool CanSeek => true; public override bool CanWrite => false;
        public override long Length => _input.Length;
        public override long Position { get => _input.Position; set => _input.Position = value; }
        public override long Seek(long offset, SeekOrigin origin) => _input.Seek(offset, origin);
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] bytes, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _input.Dispose(); base.Dispose(disposing); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (!buffer.IsEmpty && Position == Length) throw new InvalidDataException("Incomplete compressed frame.");
            long remaining = Length - Position;
            // Keep a short tail unread by bulk reads. Bytewise terminal reads let us
            // detect unconsumed/trailing frames without codec-private reflection.
            int size = (int)Math.Min(buffer.Length, remaining > 256 ? remaining - 256 : Math.Min(remaining, 1));
            return _input.Read(buffer[..size]);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
            => Task.FromResult(ReadChecked(buffer.AsSpan(offset, count), token));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
            => ValueTask.FromResult(ReadChecked(buffer.Span, token));
        private int ReadChecked(Span<byte> buffer, CancellationToken token)
        { token.ThrowIfCancellationRequested(); return Read(buffer); }
    }
    internal static async Task<int> DecodeAsync(string encoding, byte[] input, int length, byte[] output, CancellationToken token)
    {
        if (encoding == "br") return DecodeBrotli(input, length, output, token);
        int offset = 0, count = length;
        if (encoding == "gzip")
        {
            offset = GzipPayloadOffset(input, length);
            count = length - offset - 8;
            if (count <= 0) throw new InvalidDataException("Missing compressed payload.");
        }
        using var source = new CompleteInput(input, offset, count);
        // HTTP deflate uses the RFC 1950 zlib wrapper, including its Adler checksum.
        using Stream decoder = encoding == "gzip"
            ? new DeflateStream(source, CompressionMode.Decompress, leaveOpen: true)
            : new ZLibStream(source, CompressionMode.Decompress, leaveOpen: true);
        int written = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            int size = Math.Min(16 * 1024, output.Length - written);
            int read = await decoder.ReadAsync(output.AsMemory(written, size), token);
            written += read;
            if (written == output.Length) throw new RequestBodyFailure(413, RequestBodyMiddleware.DecodedTooLarge);
            if (read == 0) break;
        }
        if (source.Position != source.Length) throw new InvalidDataException("Trailing compressed data.");
        if (encoding == "gzip")
        {
            var expectedCrc = BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(length - 8, 4));
            var expectedLength = BinaryPrimitives.ReadUInt32LittleEndian(input.AsSpan(length - 4, 4));
            if (expectedLength != (uint)written || expectedCrc != Crc32(output.AsSpan(0, written)))
                throw new InvalidDataException("Invalid gzip trailer.");
        }
        return written;
    }
    private static int DecodeBrotli(byte[] input, int length, byte[] output, CancellationToken token)
    {
        var decoder = new BrotliDecoder();
        try
        {
            int consumed = 0, written = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                var status = decoder.Decompress(input.AsSpan(consumed, length - consumed),
                    output.AsSpan(written, Math.Min(16 * 1024, output.Length - written)), out int used, out int produced);
                consumed += used; written += produced;
                if (written == output.Length) throw new RequestBodyFailure(413, RequestBodyMiddleware.DecodedTooLarge);
                if (status == OperationStatus.Done)
                {
                    if (consumed != length) throw new InvalidDataException("Trailing Brotli data.");
                    return written;
                }
                if (status != OperationStatus.DestinationTooSmall || (used == 0 && produced == 0))
                    throw new InvalidDataException("Incomplete or invalid Brotli frame.");
            }
        }
        finally { decoder.Dispose(); }
    }
    private static int GzipPayloadOffset(byte[] bytes, int length)
    {
        if (length < 18 || bytes[0] != 0x1f || bytes[1] != 0x8b || bytes[2] != 8 || (bytes[3] & 0xe0) != 0)
            throw new InvalidDataException("Invalid gzip header.");
        int end = length - 8, cursor = 10;
        if ((bytes[3] & 4) != 0)
        {
            Require(cursor + 2 <= end);
            int extra = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(cursor, 2));
            cursor += 2 + extra; Require(cursor <= end);
        }
        foreach (int flag in new[] { 8, 16 })
            if ((bytes[3] & flag) != 0)
            {
                while (cursor < end && bytes[cursor] != 0) cursor++;
                Require(cursor < end); cursor++;
            }
        if ((bytes[3] & 2) != 0)
        {
            Require(cursor + 2 <= end);
            Require(BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(cursor, 2)) == (ushort)Crc32(bytes.AsSpan(0, cursor)));
            cursor += 2;
        }
        return cursor;
    }
    private static void Require(bool valid)
    { if (!valid) throw new InvalidDataException("Incomplete gzip header."); }
    private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(value =>
    {
        uint crc = (uint)value;
        for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
        return crc;
    }).ToArray();
    private static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in bytes) crc = CrcTable[(crc ^ value) & 255] ^ (crc >> 8);
        return ~crc;
    }
}
