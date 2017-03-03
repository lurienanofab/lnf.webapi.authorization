using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using LNF.Data;
using LNF.Repository;
using LNF.Repository.Data;

namespace LNF.WebApi.Authorization.Models
{
    public struct OAuthValidationResult
    {
        public HttpStatusCode StatusCode { get; private set; }
        public string ErrorMessage { get; private set; }
        public OAuthClientAudience Audience { get; private set; }

        public static OAuthValidationResult Create(HttpStatusCode statusCode, string errorMessage, OAuthClientAudience audience)
        {
            return new OAuthValidationResult()
            {
                StatusCode = statusCode,
                ErrorMessage = errorMessage,
                Audience = audience
            };
        }
    }
}
