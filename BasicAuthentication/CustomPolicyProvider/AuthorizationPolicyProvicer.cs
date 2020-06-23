using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


// Custom authorization policy provider to restrict actions based on "SecurityLevel" or "Rank"
namespace BasicAuthentication.CustomPolicyProvider
{

    public class SecurityLevelAttribute : AuthorizeAttribute
    {
        public SecurityLevelAttribute(int level)
        {
            Policy = $"{DynamicPolicies.SecurityLevel}.{level}";
        }
    }
    // This represents the {type} part... Ex: [Authorize(Policy = 'SecurityLevel.5')]
    public static class DynamicPolicies
    {
        // returns the list of dynamic policies
        public static IEnumerable<string> Get()
        {
            yield return SecurityLevel;
            yield return Rank;
        }

        public const string SecurityLevel = "SecurityLevel";
        public const string Rank = "Rank";
    }

    public static class DynamicAuthorizationPolicyFactory
    {
        public static AuthorizationPolicy Create(string policyName)
        {
            var parts = policyName.Split(".");
            var type = parts.First();
            var value = parts.Last();

            return type switch
            {
                DynamicPolicies.Rank =>
                    new AuthorizationPolicyBuilder()
                        .RequireClaim("Rank", value)
                        .Build(),
                DynamicPolicies.SecurityLevel =>
                    new AuthorizationPolicyBuilder()
                        .AddRequirements(new SecurityLevelRequirement(Convert.ToInt32(value)))
                        .Build(),
                _ => null
            };
        }
    }

    public class SecurityLevelRequirement : IAuthorizationRequirement
    {
        public int Level { get; }
        public SecurityLevelRequirement(int level)
        {
            Level = level;
        }
    }

    public class SecurityLevelRequirementHandler : AuthorizationHandler<SecurityLevelRequirement>
    {
        // If [Authorize(Policy = "SecurityLevel.5")] is set on controller action,
        // handler compare the security level attached to user claimsList to [Authorize(Policy = "SecurityLevel.5")]
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SecurityLevelRequirement requirement)
        {
            var claimValue = Convert.ToInt32(context.User.Claims.FirstOrDefault(x => x.Type == DynamicPolicies.SecurityLevel)?.Value ?? "0");

            if(requirement.Level <= claimValue) 
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }

    public class CustomAuthorizationPolicyProvicer : DefaultAuthorizationPolicyProvider
    {
        public CustomAuthorizationPolicyProvicer(IOptions<AuthorizationOptions> options) : base(options)
        {
        }

        // {type}.{value} EX: [Authorize(Policy = "SecurityLevel.5")]
        public override Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            foreach(var customPolicy in DynamicPolicies.Get())
            {
                if (policyName.StartsWith(customPolicy))
                {
                    var policy = DynamicAuthorizationPolicyFactory.Create(policyName);

                    return Task.FromResult(policy);
                }
            }

            return base.GetPolicyAsync(policyName);
        }
    }
}
