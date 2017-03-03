using LNF.Data;
using LNF.WebApi.Authorization.Models;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using System;
using System.IdentityModel.Tokens;
using Thinktecture.IdentityModel.Tokens;

namespace LNF.WebApi.Authorization.Providers
{
    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private const string AUDIENCE_PROPERTY_KEY = "client_id";

        private readonly string _issuer = string.Empty;

        public CustomJwtFormat(string issuer)
        {
            _issuer = issuer;
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            string audienceId = data.Properties.Dictionary.ContainsKey(AUDIENCE_PROPERTY_KEY) ? data.Properties.Dictionary[AUDIENCE_PROPERTY_KEY] : null;

            if (string.IsNullOrWhiteSpace(audienceId)) throw new InvalidOperationException(string.Format("AuthenticationTicket.Properties does not include {0}", AUDIENCE_PROPERTY_KEY));

            OAuthClientAudience audience = OAuthManager.FindAudience(audienceId);

            string symmetricKeyAsBase64 = audience.AudienceSecret;

            var keyByteArray = TextEncodings.Base64Url.Decode(symmetricKeyAsBase64);

            var signingKey = new HmacSigningCredentials(keyByteArray);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;

            var token = new JwtSecurityToken(_issuer, audienceId, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingKey);

            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.WriteToken(token);

            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}