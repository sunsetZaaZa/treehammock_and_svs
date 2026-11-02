using System.Text;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.Rigging.Hosting;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

// Run the same boundary + real MVC over TestServer and owned loopback Kestrel.
public sealed class Cor23FBodyHttpTests
{
    [Theory]
    [InlineData(false,"gzip")] [InlineData(true,"gzip")]
    [InlineData(false,"deflate")] [InlineData(true,"deflate")]
    [InlineData(false,"br")] [InlineData(true,"br")]
    public async Task Supported_complete_frames_reach_MVC_with_rewindable_canonical_input(bool kestrel,string encoding)
    {
        await using var host=await Cor23FBodyFixture.StartAsync(kestrel,new());
        var bytes=Cor23FBodyFixture.JsonBytes(128);
        using var request=Cor23FBodyFixture.Request(Cor23FBodyFixture.Encode(bytes,encoding),encoding);
        using var response=await host.Client.SendAsync(request);Assert.Equal(200,(int)response.StatusCode);
        Cor23ENoStoreHttpTests.AssertPrivate(response);Assert.Equal(1,host.Visits.Accepted);
        Assert.Contains(new string('a',120),await response.Content.ReadAsStringAsync());
    }
    [Theory]
    [InlineData(false,"gzip")] [InlineData(true,"gzip")]
    [InlineData(false,"deflate")] [InlineData(true,"deflate")]
    [InlineData(false,"br")] [InlineData(true,"br")]
    public async Task Malformed_and_every_truncated_frame_return_exact_errors_before_endpoint_execution(bool kestrel,string encoding)
    {
        await using var host=await Cor23FBodyFixture.StartAsync(kestrel,new());
        var complete=Cor23FBodyFixture.Encode(Cor23FBodyFixture.JsonBytes(48),encoding);
        for(int length=0;length<complete.Length;length++)
        {
            using var request=Cor23FBodyFixture.Request(complete[..length],encoding,length%2==0);
            using var response=await host.Client.SendAsync(request);
            await Cor23FBodyFixture.AssertError(response,400,RequestBodyMiddleware.InvalidCompression);
        }
        using var malformed=Cor23FBodyFixture.Request(new byte[]{0xff,0xff,0xff,0xff},encoding);
        using var invalid=await host.Client.SendAsync(malformed);await Cor23FBodyFixture.AssertError(invalid,400,RequestBodyMiddleware.InvalidCompression);
        Assert.Equal(0,host.Visits.Accepted);
    }
    [Theory]
    [InlineData(false,false)] [InlineData(false,true)] [InlineData(true,false)] [InlineData(true,true)]
    public async Task Encoded_and_decoded_limits_accept_below_and_at_and_reject_over_with_or_without_length(bool kestrel,bool chunked)
    {
        // Derive a real compressed-byte boundary from a valid frame, not padding/invalid input.
        byte[] exact=Cor23FBodyFixture.Encode(Cor23FBodyFixture.JsonBytes(128),"gzip");
        foreach(int offset in new[]{-1,0,1})
        {
            await using var wire=await Cor23FBodyFixture.StartAsync(kestrel,new(){EncodedBytes=exact.Length+offset,DecodedBytes=256});
            using var request=Cor23FBodyFixture.Request(exact,"gzip",chunked);using var response=await wire.Client.SendAsync(request);
            if(offset<0) { await Cor23FBodyFixture.AssertError(response,413,RequestBodyMiddleware.EncodedTooLarge);Assert.Equal(0,wire.Visits.Accepted); }
            else { Assert.Equal(200,(int)response.StatusCode);Assert.Equal(1,wire.Visits.Accepted); }
        }
        await using var expanded=await Cor23FBodyFixture.StartAsync(kestrel,new(){EncodedBytes=512,DecodedBytes=128});
        foreach(int length in new[]{127,128,129})
        {
            using var request=Cor23FBodyFixture.Request(Cor23FBodyFixture.Encode(Cor23FBodyFixture.JsonBytes(length),"br"),"br",chunked);
            using var response=await expanded.Client.SendAsync(request);
            if(length==129) await Cor23FBodyFixture.AssertError(response,413,RequestBodyMiddleware.DecodedTooLarge);
            else Assert.Equal(200,(int)response.StatusCode);
        }
        Assert.Equal(2,expanded.Visits.Accepted);
        await using var plain=await Cor23FBodyFixture.StartAsync(kestrel,new(){EncodedBytes=128,DecodedBytes=256});
        using var over=Cor23FBodyFixture.Request(Cor23FBodyFixture.JsonBytes(129),chunked:chunked);
        using var denied=await plain.Client.SendAsync(over);await Cor23FBodyFixture.AssertError(denied,413,RequestBodyMiddleware.EncodedTooLarge);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Encoding_policy_JSON_validation_and_unrelated_IO_keep_separate_contracts(bool kestrel)
    {
        await using var host=await Cor23FBodyFixture.StartAsync(kestrel,new());
        foreach(string encoding in new[]{"compress","identity","", "gzip, br"})
        {
            using var request=Cor23FBodyFixture.Request(Encoding.UTF8.GetBytes("{}"),encoding);
            using var response=await host.Client.SendAsync(request);
            await Cor23FBodyFixture.AssertError(response,415,encoding.Contains(',')?RequestBodyMiddleware.MultipleEncodings:RequestBodyMiddleware.UnsupportedEncoding);
        }
        using var repeated=Cor23FBodyFixture.Request(Encoding.UTF8.GetBytes("{}"));
        repeated.Content!.Headers.TryAddWithoutValidation("Content-Encoding",new[]{"gzip","br"});
        using var multiple=await host.Client.SendAsync(repeated);await Cor23FBodyFixture.AssertError(multiple,415,RequestBodyMiddleware.MultipleEncodings);
        using var badJson=Cor23FBodyFixture.Request(Encoding.UTF8.GetBytes("{\"v\": private-proof"));
        using var validation=await host.Client.SendAsync(badJson);Assert.Equal(400,(int)validation.StatusCode);
        Assert.Contains("VALIDATION_FAILED",await validation.Content.ReadAsStringAsync());Cor23ENoStoreHttpTests.AssertPrivate(validation);
        using var failure=Cor23FBodyFixture.Request(Encoding.UTF8.GetBytes("{}"),route:"/fixture/unrelated");
        using var error=await host.Client.SendAsync(failure);await Cor23FBodyFixture.AssertError(error,500,HttpExceptionFallbackMiddleware.UnexpectedErrorCode);
        Assert.DoesNotContain("private-credential-proof",await error.Content.ReadAsStringAsync());Assert.Equal(0,host.Visits.Accepted);
    }
    [Theory]
    [InlineData("gzip")] [InlineData("deflate")] [InlineData("br")]
    public async Task Actual_Program_owns_compression_errors_and_preserves_ordinary_validation(string encoding)
    {
        var authority=new Cor23EAuthorityFixture();using var factory=new TreehammockWebApplicationFactory(Cor23EAuthorityFixture.Settings(),authority.Configure);
        using var client=factory.CreateClient();
        using var malformed=Cor23FBodyFixture.Request(new byte[]{0xff,0xff,0xff},encoding,route:SessionProtocol.RefreshPath);
        using var bad=await client.SendAsync(malformed);await Cor23FBodyFixture.AssertError(bad,400,RequestBodyMiddleware.InvalidCompression);
        using var plain=Cor23FBodyFixture.Request(Encoding.UTF8.GetBytes("{"),route:SessionProtocol.RefreshPath);
        using var validation=await client.SendAsync(plain);Assert.Equal(400,(int)validation.StatusCode);Assert.Contains("VALIDATION_FAILED",await validation.Content.ReadAsStringAsync());
        using var compressed=Cor23FBodyFixture.Request(Cor23FBodyFixture.Encode(Encoding.UTF8.GetBytes("{"),encoding),encoding,route:SessionProtocol.RefreshPath);
        using var same=await client.SendAsync(compressed);Assert.Equal(validation.StatusCode,same.StatusCode);Assert.Contains("VALIDATION_FAILED",await same.Content.ReadAsStringAsync());
        var endpoints=factory.Services.GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>().Endpoints;
        Assert.Contains(endpoints,endpoint=>endpoint.Metadata.GetMetadata<RequestBodyPolicyMetadata>() is {EncodedBytes:262144,DecodedBytes:1048576});
    }
}
