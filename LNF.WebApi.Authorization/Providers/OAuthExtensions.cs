using LNF.WebApi.Authorization.Models;
using Microsoft.Owin.Security;
using System;

namespace LNF.WebApi.Authorization.Providers
{
    public static class OAuthExtensions
    {
        public static AuthenticationTicket CreateTicket(this OAuthIdentity identity, string clientId)
        {
            AuthenticationProperties props = new AuthenticationProperties();

            // Required. The request is rejected if it's not provided
            props.Dictionary.Add("client_id", clientId);

            // Required, must be in the future
            props.ExpiresUtc = DateTimeOffset.UtcNow.AddYears(1);
            props.IssuedUtc = DateTimeOffset.UtcNow;

            AuthenticationTicket ticket = new AuthenticationTicket(identity, props);

            return ticket;
        }
    }
}