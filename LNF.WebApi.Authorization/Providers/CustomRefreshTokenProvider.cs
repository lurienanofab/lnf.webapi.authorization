using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace LNF.WebApi.Authorization.Providers
{
    public class CustomRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private static ConcurrentDictionary<string, AuthenticationTicket> _refreshTokens = new ConcurrentDictionary<string, AuthenticationTicket>();

        public void Create(AuthenticationTokenCreateContext context)
        {
            var guid = Guid.NewGuid().ToString("n");

            DateTimeOffset refreshTokenExpiration = DateTimeOffset.UtcNow.AddMonths(3);

            var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
            {
                IssuedUtc = context.Ticket.Properties.IssuedUtc,
                ExpiresUtc = refreshTokenExpiration
            };

            var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

            _refreshTokens.TryAdd(guid, context.Ticket);

            context.SetToken(guid);
        }

        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            Create(context);
            return Task.FromResult<object>(null);
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;

            if (_refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
            }
        }

        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            Receive(context);
            return Task.FromResult<object>(null);
        }
    }
}