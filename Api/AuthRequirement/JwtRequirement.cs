using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Api.AuthRequirement
{
    public class JwtRequirement  : IAuthorizationRequirement
    {
        
    }

    public class JwtRequirementHandler : AuthorizationHandler<JwtRequirement>
    {
        private readonly HttpClient _client;
        private readonly HttpContext _httpContext; // Try to extract token from url as well as Auth headers

        public JwtRequirementHandler(
            IHttpClientFactory client,
            IHttpContextAccessor httpContext)
        {
            _client = client.CreateClient();
            _httpContext = httpContext.HttpContext;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtRequirement requirement)
        {
            if (_httpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                var token = authHeader.ToString().Split(" ")[1];

                var response = await _client.GetAsync($"https://localhost:44372/oauth/validate?access_token={token}");

                if (response.StatusCode == HttpStatusCode.OK) 
                {
                    context.Succeed(requirement);
                }
            }
        }
    }
}
