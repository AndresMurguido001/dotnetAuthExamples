using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
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
        private readonly IHttpClientFactory _httpClientFactory;
        //private readonly HttpClient _client;

        public HomeController(IHttpClientFactory httpContext)
        {
            _httpClientFactory = httpContext;
            //_client = httpContext.CreateClient();
        }
        public IActionResult Index()
        {
            return View();
        }

        // Authorized using Cookie. We will use "access_token" to access secured api.
        [Authorize]
        public async Task<IActionResult> Secret()
        {
            var serverResponse = await AccessTokenRefreshWrapper(
                () => SecuredGetRequest("https://localhost:44372/secret/index"));

            var apiResponse = await AccessTokenRefreshWrapper(
                () => SecuredGetRequest("https://localhost:44320/secret/index"));

            return View();
        }

        private async Task<HttpResponseMessage> SecuredGetRequest(string url)
        {
            // extract token from context
            var token = await HttpContext.GetTokenAsync("access_token");

            var client = _httpClientFactory.CreateClient();

            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            var apiResponse = await client.GetAsync(url);

            return apiResponse;
        }

        // Request new access token using refreshToken
        public async Task<HttpResponseMessage> AccessTokenRefreshWrapper(
            Func<Task<HttpResponseMessage>> initialRequest)
        {

            var response = await initialRequest();

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                await RefreshAccessToken();
                response = await initialRequest();
            }
            return response;
        } 

        private async Task RefreshAccessToken()
        {
            var refresh_token = await HttpContext.GetTokenAsync("refresh_token");

            var refreshTokenClient = _httpClientFactory.CreateClient();

            var data = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refresh_token
            };

            var requestData = new HttpRequestMessage(HttpMethod.Post, "https://localhost:44372/oauth/token")
            {
                Content = new FormUrlEncodedContent(data),
            };

            var basicCredentials = "username:password";
            var encodedCreds = Encoding.UTF8.GetBytes(basicCredentials);
            var base64Creds = Convert.ToBase64String(encodedCreds);

            requestData.Headers.Add("Authorization", $"Basic {base64Creds}");

            var response = await refreshTokenClient.SendAsync(requestData);

            var responseString = await response.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);

            var newAccessToken = responseData.GetValueOrDefault("access_token");
            var newRefreshToken = responseData.GetValueOrDefault("refresh_token");

            var authInfo = await HttpContext.AuthenticateAsync("ClIeNtCoOkIe");

            authInfo.Properties.UpdateTokenValue("access_token", newAccessToken);
            authInfo.Properties.UpdateTokenValue("refresh_token", newRefreshToken);

            await HttpContext.SignInAsync("ClIeNtCoOkIe", authInfo.Principal, authInfo.Properties);
        }

    }
}
