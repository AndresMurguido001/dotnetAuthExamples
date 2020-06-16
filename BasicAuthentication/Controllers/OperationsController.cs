using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BasicAuthentication.Controllers
{

    public class OperationsController : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public OperationsController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }


        // 1. Because we want specific authorization requirements for this action
        public async Task<IActionResult> Open()
        {
            // *THIS IS OUR PROTECTED RESOURCE*
            var cookieJar = new CookieJar(); // get cookie jar from db

            // 6. Check to see if user meets specific requirement for the specified resource
            await _authorizationService.AuthorizeAsync(User, cookieJar, CookieJarAuthOperations.Open);
            return View();
        }
    }

    // Class for centralizing requirements
    // 2. We create an Authorization Handler specifically for handling operations
    public class CookieJarAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, CookieJar>
    {
        // 4. Customize the handler for each possible action
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            OperationAuthorizationRequirement requirement,
            CookieJar cookieJar)
        {
            if (requirement.Name == CookieJarOperations.Look)
            {
                if (context.User.Identity.IsAuthenticated)
                {
                    //Specified requirement is successfully evaluated
                    context.Succeed(requirement);
                }
            }
            else if (requirement.Name == CookieJarOperations.ComeNear)
            {
                if (context.User.HasClaim("Friend", "Good"))
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }

    // 3. List all the possible operations
    public static class CookieJarOperations
    {
        public static string Open = "Open";
        public static string TakeCookie = "TakeCookie";
        public static string ComeNear = "ComeNear";
        public static string Look = "Look";
    }

    // This is our resource that is protected
    public class CookieJar
    {
        public string Name { get; set; }
    }

    public static class CookieJarAuthOperations
    {
        public static OperationAuthorizationRequirement Open => new OperationAuthorizationRequirement() { Name = CookieJarOperations.Open };
    }
}
