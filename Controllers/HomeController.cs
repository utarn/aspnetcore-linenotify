using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using aspnetcore_linenotify.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace aspnetcore_linenotify.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly LineNotify _lineNotify;
        public HomeController(ILogger<HomeController> logger,
                              SignInManager<IdentityUser> signInManager,
                              UserManager<IdentityUser> userManager,
                              LineNotify lineNotify)
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
            _lineNotify = lineNotify;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Index(string message)
        {
            await _lineNotify.SendNotify(message);
            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult LineNotify(string provider)
        {
            var redirectUrl = Url.Action("LineNotifyCallback", "Home");
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> LineNotifyCallback(string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                ModelState.AddModelError(string.Empty, "Error from Line provider");
                return View("Index");
            }
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var info = await _signInManager.GetExternalLoginInfoAsync(userId);
            if (info == null)
            {
                return RedirectToAction("Index");
            }

            var user = await _userManager.GetUserAsync(User);

            await _userManager.RemoveClaimsAsync(user, info.Principal.Claims);
            foreach (var claim in info.Principal.Claims)
            {
                await _userManager.AddClaimAsync(user, claim);
            }
            // await _userManager.AddClaimsAsync(user, info.Princial.Claims)
            return RedirectToAction("Index");
        }


    }
}
