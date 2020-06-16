using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BasicAuthentication.CustomPolicyProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BasicAuthentication.Controllers
{
    public class HomeController : Controller
    {
        //private readonly IAuthorizationService _authorizationService;

        //public HomeController(IAuthorizationService authorizationService)
        //{
        //    _authorizationService = authorizationService;
        //}
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }
        
        [Authorize(Policy = "Claim.DoB")]
        public IActionResult SecretPolicy()
        {
            return View(nameof(Secret));
        }
        
        // Same as [Authorize(Policy = "SecurityLevel.5")]
        [SecurityLevel(5)]
        public IActionResult SecretLevel()
        {
            return View(nameof(Secret));
        }
       
        [SecurityLevel(10)]
        public IActionResult SecretHigherLevel()
        {
            return View(nameof(Secret));
        }

        [Authorize(Roles = "Admin")]
        public IActionResult SecretRole()
        {
            return View(nameof(Secret));
        }

        // Adds all claims attached to user
        public IActionResult Authenticate()
        {
            // Requirements for GrandmasClaims
            var grandmasClaim = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@bob.com"),
                new Claim(ClaimTypes.DateOfBirth, "09/30/1985"),
                new Claim(DynamicPolicies.SecurityLevel, "6"),
                new Claim("Grandma.Says", "Good-boy")
            };
            // Requirements for license claim
            var licenseClaim = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob K foo"),
                new Claim("DriversLicense", "A+")
            };

            var grandmaIdentity = new ClaimsIdentity(grandmasClaim, "Grandma Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaim, "Government");

            var usersPrinciple = new ClaimsPrincipal(new[] { grandmaIdentity, licenseIdentity });

            HttpContext.SignInAsync(usersPrinciple);

            return RedirectToAction("Index");
        }

        public async Task<IActionResult> DoStuff([FromServices] IAuthorizationService _authorizationService)
        {
            // Dynamically adding authentication policies. Can be done within views.

            // We do non-authenticated stuff here

            // Within this function, we perform a task that requires a custom claim only used
            // in this function. So we build the policy first.
            var builder = new AuthorizationPolicyBuilder("CustomSchema");
            var customPolicy = builder.RequireClaim("Hello").Build();


            // Then we check if the user is able to perform task according to policy
            var authResult = await _authorizationService.AuthorizeAsync(HttpContext.User, customPolicy);

            if (authResult.Succeeded)
            {
                // If the user is successfully authorized (He has claim types attached)
                // Continue to perform authorized actions
                return View(nameof(Secret));
            }

            return View(nameof(Index));
        }
    }
}
