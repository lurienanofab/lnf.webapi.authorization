using LNF.Data;
using LNF.WebApi.Authorization.Models;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System.Threading.Tasks;

namespace LNF.WebApi.Authorization.Providers
{
    public class CustomAuthorizationCodeProvider : AuthenticationTokenProvider
    {
        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            //The client_id and client_secret have already been validated at this point. Now we just need to exchange the code for a token.

            IFormCollection form = await context.OwinContext.Request.ReadFormAsync();
            
            if (form != null)
            {
                string clientId = form.Get("client_id");
                string grantType = form.Get("grant_type");

                if (grantType == "authorization_code")
                {
                    OAuthClientAudience aud = OAuthManager.FindAudience(clientId);

                    if (aud != null)
                    {
                        OAuthClientAuthorization auth = OAuthManager.TakeAuthorization(context.Token, aud);

                        if (auth != null)
                        {
                            OAuthIdentity identity = OAuthIdentity.CreateOwnerIdentity(auth.Client);
                            AuthenticationTicket ticket = identity.CreateTicket(clientId);
                            context.SetTicket(ticket);
                        }
                    }
                }
            }
        }
    }
}