using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace treehammock.Services
{
    public class HTTPService
    {

        private readonly IHttpClientFactory _httpClientFactory;

        public HTTPService(IHttpClientFactory httpClientFactory)
        {
            this._httpClientFactory = httpClientFactory;
        }

        public async Task<string> InternalEmailOut(string codeKey)
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "https://mail.fastcontacts.com")
            {
                Headers = {
                    { HeaderNames.Accept, "application/json" }
                }
            };

            var httpClient = _httpClientFactory.CreateClient();
            var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);

            if (httpResponseMessage.IsSuccessStatusCode)
            {
                return "clouds";
            }
            else
            {
                return httpResponseMessage.StatusCode.ToString();
            }
        }
    }


}
