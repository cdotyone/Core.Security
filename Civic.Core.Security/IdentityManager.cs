using System.Dynamic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Web;
using Civic.Core.Security.Configuration;

namespace Civic.Core.Security
{
    public static class IdentityManager
    {
        public static string Username
        {
            get
            {
                return IdentityConfig.Current.UsernameHasDomain ? UsernameWithDomain : UsernameOnly;
            }
        }

        public static string UsernameWithDomain
        {
            get
            {
                if (HttpContext.Current == null || HttpContext.Current.User == null || HttpContext.Current.User.Identity == null || !HttpContext.Current.User.Identity.IsAuthenticated) return "UNK";
                return HttpContext.Current.User.Identity.Name;
            }
        }

        public static string UsernameOnly
        {
            get
            {
                var username = UsernameWithDomain;
                if (!string.IsNullOrEmpty(username))
                {
                    var parts = username.Split('\\');
                    return parts[parts.Length - 1];
                }
                return "UNK";
            }
        }

        public static string GetClaimValue(string claimName)
        {
            //Get the current claims principal
            var identity = (ClaimsPrincipal)Thread.CurrentPrincipal;

            // Get the claims values
            return identity.Claims.Where(c => c.Type == ClaimTypes.Name)
                .Select(c => c.Value).SingleOrDefault();
        }

        public static string ClientMachine
        {
            get
            {
                var client = "";
                if (HttpContext.Current == null) client = System.Environment.MachineName;
                else 
                if (!string.IsNullOrEmpty(HttpContext.Current.Request.UserHostName))
                    client = HttpContext.Current.Request.UserHostName;
                else if (!string.IsNullOrEmpty(HttpContext.Current.Request.UserHostAddress))
                    client = HttpContext.Current.Request.UserHostAddress;

                if (HttpContext.Current != null && IdentityConfig.Current.TransformXForwardedFor)
                {
                    // x-forwarded-for check
                    foreach (var key in HttpContext.Current.Request.Headers.AllKeys)
                    {
                        if (key.ToLowerInvariant() == "x-forwarded-for")
                        {
                            client = HttpContext.Current.Request.Headers[key];
                            break;
                        }
                    }
                }

                if (client == "::1") client = System.Environment.MachineName;
                if (string.IsNullOrEmpty(client)) client = "Unknown";
                return client;
            }
        }  
    }
}
