using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Newtonsoft.Json.Linq;

namespace aspnetcore_linenotify
{
    public class LineNotify
    {
        public const string TARGET = "line_notify_target";
        public const string TARGET_TYPE = "line_notify_target_type";

        public const string ACCESS_TOKEN = "line_notify_access_token";
        public const string AUTHROIZATION_ENDPOINT = "https://notify-bot.line.me/oauth/authorize";
        public const string TOKEN_ENDPOINT = "https://notify-bot.line.me/oauth/token";
        public const string USERINFO_ENDPONT = "https://notify-api.line.me/api/status";
        public const string NOTIFY_ENDPOINT = "https://notify-api.line.me/api/notify";
        public const string ROVOKE_ENDPOINT = "https://notify-api.line.me/api/revoke";
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly LinkGenerator _linkGenerator;

        public LineNotify(IHttpContextAccessor httpContextAccessor,
                          UserManager<IdentityUser> userManager,
                          SignInManager<IdentityUser> signInManager,
                          LinkGenerator linkGenerator)
        {
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _linkGenerator = linkGenerator;
            _signInManager = signInManager;



        }

        public IActionResult Authorize()
        {
            string provider = "LineNotify";

            var redirectUrl = _linkGenerator.GetUriByAction(_httpContextAccessor.HttpContext, "LineNotifyCallback", "Home");
            var User = _httpContextAccessor.HttpContext.User;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
            return new ChallengeResult(provider, properties);
        }


        [HttpGet]
        public async Task<bool> CallBack()
        {
            var User = _httpContextAccessor.HttpContext.User;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var info = await _signInManager.GetExternalLoginInfoAsync(userId);
            if (info == null)
            {
                return false;
            }

            var user = await _userManager.GetUserAsync(User);

            await _userManager.RemoveClaimsAsync(user, info.Principal.Claims);
            await _userManager.AddClaimsAsync(user, info.Principal.Claims);
            return true;
        }

        public async Task Revoke()
        {
            var user = _httpContextAccessor.HttpContext.User;
            var appUser = await _userManager.GetUserAsync(user);
            var claims = await _userManager.GetClaimsAsync(appUser);
            var accessToken = claims.FirstOrDefault(c => c.Type == ACCESS_TOKEN).Value ??
                throw new ArgumentNullException("There is no token associated with this user.");
            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            var response = await client.PostAsync(ROVOKE_ENDPOINT, null);
            response.EnsureSuccessStatusCode();
            await _userManager.RemoveClaimsAsync(appUser, claims.Where(c => c.Type == ACCESS_TOKEN));
            await _userManager.RemoveClaimsAsync(appUser, claims.Where(c => c.Type == TARGET));
            await _userManager.RemoveClaimsAsync(appUser, claims.Where(c => c.Type == TARGET_TYPE));
        }

        public async Task<bool> IsValid()
        {
            try
            {
                var user = _httpContextAccessor.HttpContext.User;
                var appUser = await _userManager.GetUserAsync(user);
                var claims = await _userManager.GetClaimsAsync(appUser);
                var accessToken = claims.FirstOrDefault(c => c.Type == ACCESS_TOKEN).Value ??
                    throw new ArgumentNullException("There is no token associated with this user.");
                var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                var response = await client.GetAsync(USERINFO_ENDPONT);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadAsStringAsync();
                dynamic json = JObject.Parse(result);
                int status = json.status;
                if (status == 200)
                {
                    return true;
                }
                else
                {
                    return false;
                }

            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public async Task<bool> SendNotify(string message)
        {
            try
            {
                var user = _httpContextAccessor.HttpContext.User;
                var appUser = await _userManager.GetUserAsync(user);
                var claims = await _userManager.GetClaimsAsync(appUser);
                var accessToken = claims.FirstOrDefault(c => c.Type == ACCESS_TOKEN).Value ?? throw new ArgumentNullException("There is no token associated with this user.");
                var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                var data = new List<KeyValuePair<string, string>>();
                data.Add(new KeyValuePair<string, string>("message", message));
                var response = await client.PostAsync(NOTIFY_ENDPOINT, new FormUrlEncodedContent(data));
                response.EnsureSuccessStatusCode();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}