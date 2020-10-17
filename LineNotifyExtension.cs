using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace aspnetcore_linenotify
{
    public static class LineNotifyExtension
    {
        public static void AddLineNotify(this IServiceCollection services, IConfiguration Configuration)
        {
            services.AddAuthentication().AddOAuth("LineNotify", "แจ้งเตือนผ่าน Line", options =>
      {
          options.ClientId = Configuration["Authentication:LineNotify:ClientID"];
          options.ClientSecret = Configuration["Authentication:LineNotify:ClientSecret"];
          options.AuthorizationEndpoint = LineNotify.AUTHROIZATION_ENDPOINT;
          options.TokenEndpoint = LineNotify.TOKEN_ENDPOINT;
          options.UserInformationEndpoint = LineNotify.USERINFO_ENDPONT;
          options.CallbackPath = new Microsoft.AspNetCore.Http.PathString("/notify-line");
          options.Scope.Add("notify");
          options.ClaimActions.MapJsonKey(LineNotify.TARGET, "target");
          options.ClaimActions.MapJsonKey(LineNotify.TARGET_TYPE, "targetType");

          options.Events = new Microsoft.AspNetCore.Authentication.OAuth.OAuthEvents
          {
              OnCreatingTicket = async context =>
              {
                  var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                  request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.AccessToken);
                  request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                  var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                  response.EnsureSuccessStatusCode();

                  var json = await response.Content.ReadAsStringAsync();
                  var user = JsonDocument.Parse(json).RootElement;
                  var userId = context.Properties.Items["XsrfId"];

                  context.RunClaimActions(user);
                  var identity = new ClaimsIdentity();
                  identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
                  identity.AddClaim(new Claim(LineNotify.ACCESS_TOKEN, context.AccessToken));
                  context.Principal.AddIdentity(identity);
              },
              OnRemoteFailure = context =>
              {
                  context.Response.Redirect("/");
                  context.HandleResponse();
                  return Task.CompletedTask;
              }
          };
      });
            services.AddTransient<LineNotify>();

        }
    }
}