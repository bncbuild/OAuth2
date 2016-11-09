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
    /// CMDM authentication client.
    /// </summary>
    class CMDMClient : OAuth2Client
    {
         private const string AUTH_SERVER = "http://bncauth-dev.herokuapp.com";// "https://secure.berkerynoyes.com";

         public CMDMClient(IRequestFactory factory, IClientConfiguration configuration)
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
            var result = new UserInfo
                {
                    Email = cnt["email"].SafeGet(x => x.Value<string>()),
                    VerifiedEmail = cnt["verifiedEmailAddress"].SafeGet(x => x.Value<bool>()),
                    //ProviderName = this.Name,
                    //Id = cnt["id"].Value<string>(),
                    FirstName = cnt["firstName"].SafeGet(x => x.Value<string>()),
                    LastName = cnt["lastName"].SafeGet(x => x.Value<string>())
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
            get { return "CMDM"; }
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
