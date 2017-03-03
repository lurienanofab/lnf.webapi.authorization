using LNF.Data;
using LNF.WebApi.Authorization.Models;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Threading.Tasks;

namespace LNF.WebApi.Authorization.Providers
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (string.IsNullOrEmpty(clientId))
                context.SetError("invalid_client_id", "client_id is not set");
            else
            {
                OAuthClientAudience aud = OAuthManager.FindAudience(clientId);

                if (aud == null)
                    context.SetError("invalid_client_id", string.Format("Invalid client_id: {0}", context.ClientId));
                else
                {
                    if (string.IsNullOrEmpty(clientSecret))
                        context.SetError("invalid_client_secret", "client_secret is not set");
                    else
                    {
                        if (aud.AudienceSecret == clientSecret)
                            context.Validated();
                        else
                            context.SetError("invalid_client_secret", "client_secret is incorrect");
                    }
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            // we already know the clientId and clientSecret are good

            // create a service identity
            OAuthIdentity identity = OAuthIdentity.CreateServiceIdentity();
            AuthenticationTicket ticket = identity.CreateTicket(context.ClientId);

            context.Validated(ticket);

            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var client = ClientUtility.Login(context.UserName, context.Password);

            if (client != null)
            {
                OAuthIdentity identity = OAuthIdentity.CreateOwnerIdentity(client);
                AuthenticationTicket ticket = identity.CreateTicket(context.ClientId);
                context.Validated(ticket);
            }
            else
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
            }

            return Task.FromResult<object>(null);
        }
        
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_id"];
            var currentClient = context.ClientId;

            // enforce client binding of refresh token
            if (originalClient != currentClient)
            {
                context.Rejected();
                return Task.FromResult<object>(null);
            }

            context.Validated(context.Ticket);

            return Task.FromResult<object>(null);
        }
    }
}