using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using Core.Security.Configuration;

namespace Core.Security
{
    public static class IdentityManager
    {
        public static string GetClientMachine(ClaimsPrincipal user)
        {
            //var client = "";
            //if (HttpContext.Current == null) client = Environment.MachineName;
            //else if (!string.IsNullOrEmpty(HttpContext.Current.Request.UserHostName))
            //    client = HttpContext.Current.Request.UserHostName;
            //else if (!string.IsNullOrEmpty(HttpContext.Current.Request.UserHostAddress))
            //    client = HttpContext.Current.Request.UserHostAddress;

            //if (HttpContext.Current != null && IdentityConfig.Current.TransformXForwardedFor)
            //{
            //    // x-forwarded-for check
            //    foreach (var key in HttpContext.Current.Request.Headers.AllKeys)
            //    {
            //        if (key.ToLowerInvariant() == "x-forwarded-for")
            //        {
            //            client = HttpContext.Current.Request.Headers[key];
            //            break;
            //        }
            //    }
            //}

            var client = GetClaimValue(StandardClaimTypes.CLIENT_IP);

            if (client == "::1") client = Environment.MachineName;
            if (string.IsNullOrEmpty(client)) client = "Unknown";
            return client;
        }

        public static string GetUsername(IPrincipal user)
        {
            return IdentityConfig.Current.UsernameHasDomain ? GetUsernameWithDomain(user) : GetUsernameOnly(user);
        }

        public static string GetUsernameWithDomain(IPrincipal user)
        {
            if (user?.Identity == null || !user.Identity.IsAuthenticated) return "UNK";
            return user.Identity.Name;
        }


        public static string GetUsernameOnly(IPrincipal user)
        {
            var username = GetUsernameWithDomain(user);
            if (!string.IsNullOrEmpty(username))
            {
                var parts = username.Split('\\');
                return parts[parts.Length - 1];
            }

            return "UNK";
        }

        public static string GetClaimValue(ClaimsPrincipal identity, string claimName)
        {
            // Get the claims values
            return (identity.Identity as ClaimsIdentity).Claims.Where(c => c.Type == claimName)
                .Select(c => c.Value).SingleOrDefault();
        }

        public static string GetClaimValue(string claimName)
        {
            // Get the claims values
            return GetClaimValue((ClaimsPrincipal) Thread.CurrentPrincipal, claimName);
        }
    }
}
