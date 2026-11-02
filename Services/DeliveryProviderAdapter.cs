using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
namespace treehammock.Services;

// SMTP/SNS/Twilio do not expose provider idempotency in this project. Unknown
// acceptance stops retry/fallback; job identity and encrypted code remain stable.
public sealed class DeliveryProviderAdapter(ISMTPService smtp, ISmsSender sms) : IDeliveryProvider
{
    public async Task<DeliverySendResult> SendAsync(Guid jobId,DeliveryPayload p,CancellationToken token)
    {
        if(p.Channel=="sms")
        {
            var result=await sms.SendDurable(jobId,p,token);
            return result.Outcome;
        }
        token.ThrowIfCancellationRequested();
        if(p.Channel!="email")return new(DeliverySendState.NotSubmitted,"DELIVERY_INVALID_CHANNEL");
        return (await smtp.SendDurable(jobId,p,token)).Normalize();
    }
}
