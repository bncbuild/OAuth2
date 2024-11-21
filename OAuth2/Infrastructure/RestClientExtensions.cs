using System.Net;
using OAuth2.Client;
using RestSharp;

namespace OAuth2.Infrastructure
{
    public static class RestClientExtensions
    {
        public static IRestResponse ExecuteAndVerify(this IRestClient client, IRestRequest request)
        {
            // add header
            //request.AddHeader("X-Authorization-Key", "5ed2149a-e2ba-4a40-9df0-94057d1942fb");
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            var response = client.Execute(request);
            if (response.StatusCode != HttpStatusCode.OK || response.Content.IsEmpty())
            {
                throw new UnexpectedResponseException(response);
            }
            return response;
        }
    }
}