using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;

namespace Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(config =>
            {
                // check cookie to confirm that we are authenticated (Authenticated)
                config.DefaultAuthenticateScheme = "ClIeNtCoOkIe";
                // when we sign in we will give out cookie
                config.DefaultSignInScheme = "ClIeNtCoOkIe";
                // use this to check if we are allowed to do something (Authorized)
                config.DefaultChallengeScheme = "OurServer";
            })
                .AddCookie("ClIeNtCoOkIe")
                .AddOAuth("OurServer", config =>
                {
                    config.ClientId = "Client_id";
                    config.ClientSecret = "Client_Secret";
                    config.CallbackPath = "/oauth/callback";
                    config.AuthorizationEndpoint = "https://localhost:44372/oauth/authorize";
                    config.TokenEndpoint = "https://localhost:44372/oauth/token";

                    config.SaveTokens = true;

                    config.Events = new OAuthEvents()
                    {
                        OnCreatingTicket = context =>
                        {
                            var access_token = context.AccessToken;
                            var base64payload = access_token.Split(".")[1];

                            var bytes = Convert.FromBase64String(base64payload);
                            var jsonPayload = Encoding.UTF8.GetString(bytes);

                            var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonPayload);

                            foreach (var claim in claims)
                            {
                                context.Identity.AddClaim(new Claim(claim.Key, claim.Value));
                            }

                            return Task.CompletedTask;
                        }
                    };

                });

            services.AddHttpClient();

            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            // who are you?
            app.UseAuthentication();

            // are you allowed?
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
