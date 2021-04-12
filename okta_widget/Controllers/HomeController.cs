using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using okta_aspnetcore_mvc_example.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Okta.AspNetCore;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using RestSharp;

namespace okta_aspnetcore_mvc_example.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _config;

        public HomeController(ILogger<HomeController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
        }

        public IActionResult Index()
        {
            return View();
        }


        public IActionResult Login()
        {
            ViewBag.Message = "Okta Login Widget page.";

            //return View("authnLogin");

            //return View("oidcSessionTokenLogin");

            //return RedirectToAction("SignIn", "Account");

            TempData["redirectUri"] = "https://localhost:44305/implicit/callback";
            return View("oidcImplicitLogin");

            //TempData["redirectUri"] = "https://localhost:44305/implicit/callback";
            //return View("oidcGetTokensLogin");

            //return View("oidcAuthCodeLogin");
            //return View("oidcAuthCode_SSreg");


            //return View("oidcPkceClientLogin");
        }

        [HttpPost]
        public async  Task<IActionResult> LogOut()
        {

            //return new SignOutResult(
            //    new[]
            //    {
            //        //OktaDefaults.MvcAuthenticationScheme,
            //        CookieAuthenticationDefaults.AuthenticationScheme,
            //    },
            //    new AuthenticationProperties { RedirectUri = "/Home/PostLogOut" });

            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("PostLogOut", "Home");

        }

        public IActionResult PostLogOut()
        {
            return View();
        }

        public IActionResult GetTokensLanding()
        {
            return View();
        }


        public IActionResult GetTokenWidget()
        {
            return View();
        }

        public IActionResult GetTokenSdk()
        {
            return View();
        }

        public IActionResult AuthCodeLanding()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ImplicitLanding(string accessToken, string idToken)
        {
            System.Security.Claims.ClaimsPrincipal claimPrincipal = null;

            Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false
                };

            System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken;
            System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

            jwtSecurityToken = handler.ReadJwtToken(idToken);
            List<System.Security.Claims.Claim> claims = jwtSecurityToken.Claims.ToList();    
            claims.Add(new Claim("idToken", idToken));
            claims.Add(new Claim("accessToken", accessToken));

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                //AllowRefresh = <bool>,
                // Refreshing the authentication session should be allowed.

                //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                // The time at which the authentication ticket expires. A 
                // value set here overrides the ExpireTimeSpan option of 
                // CookieAuthenticationOptions set with AddCookie.

                //IsPersistent = true,
                // Whether the authentication session is persisted across 
                // multiple requests. When used with cookies, controls
                // whether the cookie's lifetime is absolute (matching the
                // lifetime of the authentication ticket) or session-based.

                //IssuedUtc = <DateTimeOffset>,
                // The time at which the authentication ticket was issued.

                //RedirectUri = <string>
                // The full path or absolute URI to be used as an http 
                // redirect response value.
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);



            return View();
        }


        public IActionResult UnprotectedLanding()
        {
            return View();
        }

        [Authorize]
        public IActionResult ProtectedLanding()
        {



            return View();
        }

        [Authorize]
        public IActionResult Profile()
        {
            return View(HttpContext.User.Claims);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost]
        public IActionResult SendApi()
        {
            string myAccessToken = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "accessToken").Value;

            bool rspSendApiA = SendTokenToWebApi(myAccessToken, _config.GetValue<string>("SendApi:BackendApi"));

            return RedirectToAction("ProtectedLanding", "Home");
        }


        public bool SendTokenToWebApi(string access_token, string destPage)
        {

            IRestResponse response = null;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.GET);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Bearer " + access_token);
            response = client.Execute(request);

            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {
                return false;
            }


            if (response.StatusDescription == "OK")
            {
                return true;
            }
            else
            {
                return false;
            }
        }



    }
}
