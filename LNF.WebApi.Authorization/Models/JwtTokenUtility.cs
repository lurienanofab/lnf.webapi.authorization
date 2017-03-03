using Microsoft.Owin.Security.DataHandler.Encoder;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace LNF.WebApi.Authorization.Models
{
    public static class JwtTokenUtility
    {
        public static ClaimsPrincipal GetPrincipal(string securityToken, string clientId, string clientSecret, string issuer)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            SecurityToken token;

            byte[] secretBytes = TextEncodings.Base64Url.Decode(clientSecret);
            var signingKey = new InMemorySymmetricSecurityKey(secretBytes);

            var validationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = signingKey,
                ValidAudience = clientId,
                ValidIssuer = issuer
            };

            return tokenHandler.ValidateToken(securityToken, validationParameters, out token);
        }
    }
}
