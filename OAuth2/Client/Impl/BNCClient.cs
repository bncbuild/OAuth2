using System.Collections.Specialized;
using System.Linq;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp;

namespace OAuth2.Client.Impl
{
    /// <summary>
    /// BNC authentication client.
    /// </summary>
    public class BNCClient : OAuth2Client
    {

       // private const string AUTH_SERVER = "https://secure.berkerynoyes.com";//"http://bncauth-dev.herokuapp.com";
        private static string mAUTH_SERVER = null;
        private static string mX_AUTH_KEY = null;

        private static string AUTH_SERVER
        {
            get
            {
                if (string.IsNullOrEmpty(mAUTH_SERVER))
                {
#if TESTSECURE
                    mAUTH_SERVER = System.Configuration.ConfigurationManager.AppSettings["AUTH_SERVER_test"];
#else
               mAUTH_SERVER = System.Configuration.ConfigurationManager.AppSettings["AUTH_SERVER"];
#endif
                }

                return mAUTH_SERVER;
            }
        }

        public BNCClient(IRequestFactory factory, IClientConfiguration configuration)
            : base(factory, configuration)
        {
        }

        protected override void BeforeGetAccessToken(BeforeAfterRequestArgs args)
        {
            args.Request.AddObject(new
            {
                code = args.Parameters.GetOrThrowUnexpectedResponse("code"),
                client_id = args.Configuration.ClientId,
                client_secret = args.Configuration.ClientSecret,
                redirect_uri = args.Configuration.RedirectUri,
                state = State,
                grant_type = "authorization_code"
            });
        }


        /// <summary>
        /// Called just before issuing request to third-party service when everything is ready.
        /// Allows to add extra parameters to request or do any other needed preparations.
        /// </summary>
        protected override void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
            // workaround for current design, oauth_token is always present in URL, so we need emulate it for correct request signing 
            var accessToken = new Parameter { Name = "access_token", Value = AccessToken };
            args.Request.AddParameter(accessToken);

        }

        /// <summary>
        /// Should return parsed <see cref="UserInfo"/> from content received from third-party service.
        /// </summary>
        /// <param name="content">The content which is received from third-party service.</param>
        protected override UserInfo ParseUserInfo(string content)
        {

            
            var cnt = JObject.Parse(content);
            //var names = cnt["name"].Value<string>().Split(' ').ToList();
            //const string avatarUriTemplate = "{0}&s={1}";
            //var avatarUri = cnt["avatar_url"].Value<string>();
            JArray roles = cnt["roles"].SafeGet(x => x.Value<JArray>());
            var result = new UserInfo
                {
                    Email = cnt["email"].SafeGet(x => x.Value<string>()),
                    VerifiedEmail = cnt["verifiedEmailAddress"].SafeGet(x => x.Value<bool>()),
                    //ProviderName = this.Name,
                    Id = cnt["userId"].SafeGet(x => x.Value<string>()),
                    FirstName = cnt["firstName"].SafeGet(x => x.Value<string>()),
                    LastName = cnt["lastName"].SafeGet(x => x.Value<string>()),
                    userName = cnt["username"].SafeGet(x => x.Value<string>()),
                    Roles = roles.Select(r => r.ToString()).ToArray()
                    //AvatarUri =
                    //    {
                    //        Small = !string.IsNullOrWhiteSpace(avatarUri) ? string.Format(avatarUriTemplate, avatarUri, AvatarInfo.SmallSize) : string.Empty,
                    //        Normal = avatarUri,
                    //        Large = !string.IsNullOrWhiteSpace(avatarUri) ? string.Format(avatarUriTemplate, avatarUri, AvatarInfo.LargeSize) : string.Empty
                    //    }
                };
            return result;
        }

        /// <summary>
        /// Friendly name of provider (OAuth2 service).
        /// </summary>
        public override string Name
        {
            get { return "Berkery Noyes Accounts"; }
        }

        /// <summary>
        /// Defines URI of service which issues access code.
        /// </summary>
        protected override Endpoint AccessCodeServiceEndpoint
        {
            get { return new Endpoint { BaseUri = AUTH_SERVER, Resource = "/oauth/authorize" }; }
        }

        /// <summary>
        /// Defines URI of service which issues access token.
        /// </summary>
        protected override Endpoint AccessTokenServiceEndpoint
        {
            get { return new Endpoint { BaseUri = AUTH_SERVER, Resource = "/oauth/token" }; }
        }

        /// <summary>
        /// Defines URI of service which allows to obtain information about user which is currently logged in.
        /// </summary>
        protected override Endpoint UserInfoServiceEndpoint
        {
            get { return new Endpoint { BaseUri = AUTH_SERVER, Resource = "/api/me" }; }
        }
    }
}
