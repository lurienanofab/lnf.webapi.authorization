using LNF.WebApi.Authorization.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Configuration;

[assembly: OwinStartup(typeof(LNF.WebApi.Authorization.Startup))]

namespace LNF.WebApi.Authorization
{
    public class Startup : ApiOwinStartup
    {
        public override void Configuration(IAppBuilder app)
        {
            base.Configuration(app);
            ConfigureOAuth(app);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            var issuer = ConfigurationManager.AppSettings["as:Issuer"];

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = !LNF.Providers.IsProduction(),
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(24),
                Provider = new CustomOAuthProvider(),
                AccessTokenFormat = new CustomJwtFormat(issuer),
                AuthorizationCodeProvider = new CustomAuthorizationCodeProvider(),
                RefreshTokenProvider = new CustomRefreshTokenProvider()
            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
        }
    }
}