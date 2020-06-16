using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<HomeController> _logger;

        public HomeController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ILogger<HomeController> logger
            )
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }
        public IActionResult Index()
        {
            _logger.LogWarning("HIT INDEX ROUTE");
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        public IActionResult Login()
        {
            // returns view for "GET"
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            // Functionality processed when "POST"
            var user = await _userManager.FindByNameAsync(username);


            if (user != null)
            {
                // Result successful - Attempt to Sign user in
                return await SignInAndRedirect(user, password);
            }

            return RedirectToAction(nameof(Index));
        }

        public IActionResult Register()
        {
            // returns view for "GET"
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new IdentityUser
            {
                UserName = username
            };
            var result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                // Result is successful - Attempt to Sign user in
                return await SignInAndRedirect(user, password);
                
            }
            // Functionality processed when "POST"
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Index));
        }

        private async Task<IActionResult> SignInAndRedirect(IdentityUser user, string password)
        {
            _logger.LogWarning("Signin Method Running.....");

            var signInResult = await _signInManager.PasswordSignInAsync(user, password, false, false);

            if (signInResult.Succeeded)
            {
                _logger.LogWarning("Login Successful...");
                return RedirectToAction(nameof(Secret));
            }
            else
            {
                return NotFound();
            }
        }
    }
}
