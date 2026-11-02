using System.Text;
using System.Text.Json;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Treehammock.SessionValidation.Contracts.V1;

namespace Treehammock.SessionValidation.Contracts;

// Required at raw-message boundaries. Generated protobuf parsers alone allow unknown fields
// and collapse duplicate fields; they are not the v1 admission policy.
public static class ContractCodec
{
    public static ContractError DecodeRequestBinary(byte[] bytes, AdmissionContext context, CallerPolicy policy, out ValidateRequest? request)
    {
        request = null;
        var error = CheckWire(bytes, ValidateRequest.Descriptor, ContractLimits.BinaryRequestBytes);
        if (error != ContractError.None) return error;
        try
        {
            var parsed = ValidateRequest.Parser.ParseFrom(bytes);
            error = ContractRules.CheckRequest(parsed, context, policy);
            if (error == ContractError.None) request = parsed;
            return error;
        }
        catch (InvalidProtocolBufferException) { return ContractError.Malformed; }
    }

    public static ContractError DecodeReplyBinary(byte[] bytes, ReplyContext context, out ValidateReply? reply)
    {
        reply = null;
        var error = CheckWire(bytes, ValidateReply.Descriptor, ContractLimits.BinaryReplyBytes);
        if (error != ContractError.None) return error;
        try
        {
            var parsed = ValidateReply.Parser.ParseFrom(bytes);
            error = ContractRules.CheckReply(parsed, context);
            if (error == ContractError.None) reply = parsed;
            return error;
        }
        catch (InvalidProtocolBufferException) { return ContractError.Malformed; }
    }

    // JSON is a serialization conformance surface only; no second JSON transport/endpoint.
    public static ContractError DecodeRequestJson(string json, AdmissionContext context, CallerPolicy policy, out ValidateRequest? request)
    {
        request = null;
        var error = CheckJson(json, ValidateRequest.Descriptor, ContractLimits.JsonRequestBytes);
        if (error != ContractError.None) return error;
        try
        {
            var parsed = ValidateRequest.Parser.ParseJson(json);
            error = ContractRules.CheckRequest(parsed, context, policy);
            if (error == ContractError.None) request = parsed;
            return error;
        }
        catch (InvalidProtocolBufferException) { return ContractError.Malformed; }
        catch (FormatException) { return ContractError.Malformed; }
    }

    public static ContractError DecodeReplyJson(string json, ReplyContext context, out ValidateReply? reply)
    {
        reply = null;
        var error = CheckJson(json, ValidateReply.Descriptor, ContractLimits.JsonReplyBytes);
        if (error != ContractError.None) return error;
        try
        {
            var parsed = ValidateReply.Parser.ParseJson(json);
            error = ContractRules.CheckReply(parsed, context);
            if (error == ContractError.None) reply = parsed;
            return error;
        }
        catch (InvalidProtocolBufferException) { return ContractError.Malformed; }
        catch (FormatException) { return ContractError.Malformed; }
    }

    private static ContractError CheckWire(byte[] bytes, MessageDescriptor descriptor, int maximum)
    {
        if (bytes.Length > maximum) return ContractError.TooLarge;
        if (bytes.Length == 0) return ContractError.Malformed;
        try
        {
            using var input = new CodedInputStream(bytes);
            ulong seen = 0;
            uint tag;
            while ((tag = input.ReadTag()) != 0)
            {
                int number = WireFormat.GetTagFieldNumber(tag);
                var field = descriptor.FindFieldByNumber(number);
                if (field is null || number > 63) return ContractError.UnknownField;
                ulong bit = 1UL << number;
                if ((seen & bit) != 0) return ContractError.DuplicateField;
                seen |= bit;
                var expected = field.FieldType is FieldType.String or FieldType.Bytes
                    ? WireFormat.WireType.LengthDelimited : WireFormat.WireType.Varint;
                if (WireFormat.GetTagWireType(tag) != expected) return ContractError.WrongWireType;
                input.SkipLastField();
            }
            return ContractError.None;
        }
        catch (InvalidProtocolBufferException) { return ContractError.Malformed; }
    }

    private static ContractError CheckJson(string json, MessageDescriptor descriptor, int maximum)
    {
        if (json.Length > maximum || Encoding.UTF8.GetByteCount(json) > maximum) return ContractError.TooLarge;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return ContractError.Malformed;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (!descriptor.Fields.InFieldNumberOrder().Any(f => f.JsonName == property.Name)) return ContractError.UnknownField;
                if (!seen.Add(property.Name)) return ContractError.DuplicateField;
            }
            return ContractError.None;
        }
        catch (JsonException) { return ContractError.Malformed; }
    }
}
