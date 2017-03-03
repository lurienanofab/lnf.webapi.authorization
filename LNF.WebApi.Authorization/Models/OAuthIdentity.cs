using LNF.Models.Data;
using LNF.Repository.Data;
using System.Security.Claims;

namespace LNF.WebApi.Authorization.Models
{
    public class OAuthIdentity : ClaimsIdentity
    {
        private bool _IsAuthenticated = false;

        public Client Client { get; private set; }

        public bool IsServiceIdentity{get;private set;}

        public override bool IsAuthenticated
        {
            get { return _IsAuthenticated; }
        }

        public override string AuthenticationType
        {
            get { return "JWT"; }
        }

        private OAuthIdentity() { }

        public static OAuthIdentity CreateOwnerIdentity(Client client)
        {
            OAuthIdentity result = new OAuthIdentity();
            result.Client = client;
            result.IsServiceIdentity = false;
            result._IsAuthenticated = true;
            result.AddClaim(new Claim(ClaimTypes.Name, client.UserName));
            result.AddClaim(new Claim("sub", client.UserName));
            foreach (string r in client.Roles())
                result.AddClaim(new Claim(ClaimTypes.Role, r));
            return result;
        }

        public static OAuthIdentity CreateServiceIdentity()
        {
            OAuthIdentity result = new OAuthIdentity();
            result.Client = null;
            result.IsServiceIdentity = true;
            result.AddClaim(new Claim("sub", "service"));
            result.AddClaim(new Claim(ClaimTypes.Role, "Service"));
            return result;
        }
    }
}