using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Client.Controllers
{
    public class HomeController : Controller
    {
        private readonly HttpClient _client;

        public HomeController(IHttpClientFactory httpContext)
        {
            _client = httpContext.CreateClient();
        }
        public IActionResult Index()
        {
            return View();
        }

        // Authorized using Cookie. We will use "access_token" to access secured api.
        [Authorize]
        public async Task<IActionResult> Secret()
        {

            // extract token from context
            var token = await HttpContext.GetTokenAsync("access_token");

            _client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            var serverResponse = await _client.GetAsync("https://localhost:44372/secret/index");

            var apiResponse = await _client.GetAsync("https://localhost:44320/secret/index");

            return View();
        }

    }
}
