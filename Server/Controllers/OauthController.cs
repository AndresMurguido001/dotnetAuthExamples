using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Server.Controllers
{
    public class OauthController : Controller
    {
        // For all Oauth Specs visit https://tools.ietf.org/html/rfc6749
        [HttpGet]
        public IActionResult Authorize(
            string response_type, // auth flow type
            string client_id, 
            string redirect_uri,
            string scope, // what info i want ex: "email,firstname,lastname,tel"
            string state) // string generated to confirm we are returning to the same client
        {

            var query = new QueryBuilder();
            query.Add("redirect_uri", redirect_uri);
            query.Add("state", state);

            return View(model: query.ToString());
        }

        [HttpPost]
        public IActionResult Authorize(
            string username,
            string redirect_uri,
            string state)
        {
            const string code = "FDLSLKFJLKSJDFlskdflksdlsL"; // used to confirm state when returning to client

            var query = new QueryBuilder();
            query.Add("code", code);
            query.Add("state", state);

            return Redirect($"{redirect_uri}{query.ToString()}");
        }
        
        public async Task<IActionResult> Token(
            string grant_type, // flow of access_token request
            string code, // confirmation of auth process 
            string redirect_uri, 
            string client_id,
            string refresh_token
            )
        {
            // some mechanism to validate the code
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("Granny", "cookie"),
            };

            var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);

            var key = new SymmetricSecurityKey(secretBytes);

            var algorithm = SecurityAlgorithms.HmacSha256;

            var signingCreds = new SigningCredentials(key, algorithm);

            var token = new JwtSecurityToken(
                    Constants.Issuer,
                    Constants.Audience,
                    claims,
                    DateTime.Now, // when token becomes valid
                    expires: grant_type == "refresh_token" ? DateTime.Now.AddMinutes(5) : DateTime.Now.AddMilliseconds(1), // when token expires. If refresh_Token exp in 5, regular token exp right away
                    signingCreds);

            var access_token = new JwtSecurityTokenHandler().WriteToken(token);

            var response = new
            {
                access_token,
                token_type = "Bearer",
                raw_claim = "oauthTutorial",
                refresh_token = "SampleRefreshToken"
            };

            var responseJson = JsonConvert.SerializeObject(response);

            await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(responseJson), 0, responseJson.Length);

            return Redirect(redirect_uri);
        }

        [Authorize]
        public IActionResult Validate()
        {
            // If access_token contained in URL
            if (HttpContext.Request.Query.TryGetValue("access_token", out var access_token))
            {
                return Ok();
            }
            // If token is contained in Authorization Header
            else if (HttpContext.Request.Headers.ContainsKey("Authorization"))
            {
                return Ok();
            }
            else
            {
                return BadRequest(new UnauthorizedResult());
            }
        }
    }
}
