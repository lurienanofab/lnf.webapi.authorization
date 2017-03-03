using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Xml.Linq;
using LNF.Data;
using LNF.Repository;
using LNF.Repository.Data;

namespace LNF.WebApi.Authorization.Models
{
    public static class OAuthManager
    {
        private static readonly ConcurrentDictionary<string, OAuthRequest> _requests;

        static OAuthManager()
        {
            _requests = new ConcurrentDictionary<string, OAuthRequest>();
        }

        public static OAuthClientAuthorization TakeAuthorization(string code, OAuthClientAudience audience)
        {
            var result = DA.Current.Query<OAuthClientAuthorization>().FirstOrDefault(x =>
                x.AuthorizationCode == code
                && x.OAuthClientAudience == audience
                && x.Expires > DateTime.Now
                && !x.IsExchanged);

            if (result != null)
            {
                result.IsExchanged = true;
                result.ExchangedOn = DateTime.Now;
                DA.Current.SaveOrUpdate(result);
            }

            return result;
        }

        public static OAuthClientAuthorization AddAuthorization(OAuthClientAudience audience, Client client, string redirect, string state)
        {
            var result = new OAuthClientAuthorization()
            {
                OAuthClientAudience = audience,
                Client = client,
                AuthorizationCode = Guid.NewGuid().ToString("N"),
                RedirectUri = redirect,
                State = state,
                Expires = DateTime.Now.AddHours(1),

            };

            DA.Current.SaveOrUpdate(result);

            return result;
        }

        public static OAuthValidationResult Validate(string clientId, string redirectUri)
        {
            Uri uri;

            if (Uri.TryCreate(redirectUri, UriKind.Absolute, out uri))
            {
                var aud = DA.Current.Query<OAuthClientAudience>().Where(x => x.AudienceId == clientId).FirstOrDefault();
                if (aud != null)
                {
                    if (!string.IsNullOrEmpty(redirectUri) && aud.IsAllowed(uri))
                        return OAuthValidationResult.Create(HttpStatusCode.OK, string.Empty, aud);
                    else
                        return OAuthValidationResult.Create(HttpStatusCode.BadRequest, "invalid redirect_uri", aud);
                }
                else
                    return OAuthValidationResult.Create(HttpStatusCode.BadRequest, "invalid client_id", null);
            }
            else
                return OAuthValidationResult.Create(HttpStatusCode.BadRequest, "invalid redirect_uri", null);
        }

        public static OAuthClientAudience FindAudience(string client_id)
        {
            return DA.Current.Query<OAuthClientAudience>().FirstOrDefault(x => x.AudienceId == client_id);
        }

        public static OAuthClientAudience AddAudience(OAuthClient client, string name, string description, string[] allowedRedirectUris, string allwedOriginUris, string audienceId, string audienceSecret)
        {
            //this should be called when setting up a new client_id/client_secrect pair, for example someone is developing a new application and has requested
            //api access, and needs a new client_id/client_secret to authenticate requests.

            XElement xdoc = OAuthClientAudience.CreateConfiguration(allowedRedirectUris, allowedRedirectUris);

            OAuthClientAudience audience = new OAuthClientAudience()
            {
                OAuthClient = client,
                ApplicationName = name,
                ApplicationDescription = description,
                Configuration = xdoc,
                AudienceId = audienceId,
                AudienceSecret = audienceSecret,
                CreatedDateTime = DateTime.Now,
                Active = true,
                Deleted = false
            };

            DA.Current.SaveOrUpdate(audience);

            return audience;
        }
    }
}
