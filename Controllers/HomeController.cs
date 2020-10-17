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
        private readonly LineNotify _lineNotify;
        public HomeController(ILogger<HomeController> logger,
                              LineNotify lineNotify)
        {
            _logger = logger;
            _lineNotify = lineNotify;
        }

        public async Task<IActionResult> Index()
        {
            ViewData["IsValid"] = await _lineNotify.IsValid();
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
            return _lineNotify.Authorize();
        }

        [HttpGet]
        public async Task<IActionResult> LineNotifyCallback(string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                ModelState.AddModelError(string.Empty, "Error from Line provider");
                return View("Index");
            }
            var callBackResponse = await _lineNotify.CallBack();
            if (callBackResponse)
            {
                return RedirectToAction("Index");
            }
            else
            {
                return RedirectToAction("Index");
            }
        }

        public async Task<IActionResult> Revoke()
        {
            await _lineNotify.Revoke();
            return RedirectToAction("Index");
        }

    }
}
