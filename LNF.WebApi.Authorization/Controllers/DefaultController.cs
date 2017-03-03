using LNF.Data;
using LNF.Repository.Data;
using LNF.WebApi.Authorization.Models;
using System.Net;
using System.Web.Http;

namespace LNF.WebApi.Authorization.Controllers
{
    [AllowAnonymous]
    public class DefaultController : ApiController
    {
        [Route("")]
        public string Get()
        {
            return "authorization-api";
        }

        [HttpGet, Route("authorize")]
        public string Authorize(string client_id, string redirect_uri, string state)
        {
            //always validate the client_id
            OAuthValidationResult validateResult = OAuthManager.Validate(client_id, redirect_uri);
            
            if (validateResult.StatusCode == HttpStatusCode.OK)
            {
                //need to get this somehow
                Client client = null;

                OAuthClientAuthorization auth = OAuthManager.AddAuthorization(validateResult.Audience, client, redirect_uri, state);
                return auth.AuthorizationCode;
            }
            else
                throw new HttpResponseException(validateResult.StatusCode);
        }
    }
}
