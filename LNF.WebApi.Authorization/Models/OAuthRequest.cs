using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LNF.WebApi.Authorization.Models
{
    public struct OAuthRequest
    {
        public string Code { get; private set; }
        public string Redirect { get; private set; }
        public string State { get; private set; }
        public DateTime Expires { get; private set; }
    }
}
