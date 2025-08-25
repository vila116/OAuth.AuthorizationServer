using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OAuth.AuthorizationServer
{
    public class AuthService
    {
        public static List<string> GetDestinations(Claim claim)
        {
            var destination = new List<string>();
            if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
            {
                destination.Add(OpenIddictConstants.Destinations.AccessToken);
            }
            return destination;
        }

        public string BuilderRedirectUrl(HttpRequest request, IDictionary<String,StringValues> parameter)
        {
            var url = request.PathBase + request.Path + QueryString.Create(parameter);
            return url;
        }
        public IDictionary<string, StringValues> ParseOAuthparameters(HttpContext httpContext,List<string?> excluding = null)
        {
            excluding ??= new List<string?>();
            var parameters = httpContext.Request.HasFormContentType ?
                 httpContext.Request.Form
                 .Where(parameter =>!excluding.Contains(parameter.Key))
                 .ToDictionary(Kvp =>Kvp.Key , Kvp=> Kvp.Value) 
                 :httpContext.Request.Query.Where(parameter => !excluding.Contains(parameter.Key))
                 .ToDictionary(Kvp => Kvp.Key, Kvp => Kvp.Value);
            return parameters;
        }
        public bool IsAuthenticated(AuthenticateResult authenticateResult,OpenIddictRequest request)
        {
            if (!authenticateResult.Succeeded)
                return false;
            if (request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);
                // check if cookie expired
                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSeconds;
                if (expired)
                {
                    return false;
                }
            }
            return true; 
        }
    }
}
