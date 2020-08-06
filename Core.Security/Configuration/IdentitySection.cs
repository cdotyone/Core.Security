using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;

namespace Core.Security.Configuration
{
    public static class IdentityConfig
    {
        private static ConcurrentDictionary<string,string> _claims= new ConcurrentDictionary<string, string>();
        public static void Init(IConfiguration config)
        {
            bool.TryParse(config.GetSection("Core:Security:XForwardedFor").Value, out _transformXForwardedFor);
            bool.TryParse(config.GetSection("Core:Security:UsernameHasDomain").Value, out _usernameHasDomain);

            var claims = config.GetSection("Core:Security:Claims").GetChildren();
            foreach (var claim in claims)
            {
                var name = claim.Key;
                if (!name.StartsWith("@")) name = "@" + name;
                _claims[name] = claim.Value;
            }
        }

        /// <summary>
        /// True if IdentityHelp should translate the x-forwarded-for header to get client ip
        /// </summary>
		public static bool TransformXForwardedFor
		{
            get { return _transformXForwardedFor; }
            set { _transformXForwardedFor = value; }
		}
        private static bool _transformXForwardedFor = false;

        public static bool UsernameHasDomain
        {
            get { return _usernameHasDomain; }
            set { _usernameHasDomain = value; }
        }
        private static bool _usernameHasDomain = true;

        public static ConcurrentDictionary<string, string> GetClaimsDefaultForDataConfig()
        {
            if (_claims.Count <= 0)
            {
                _claims["@ouid"] = StandardClaimTypes.ORGANIZATION_ID;
                _claims["@personuid"] = StandardClaimTypes.PERSON_ID;
            };

            return _claims;
        }
    }
}