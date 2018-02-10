﻿using Civic.Core.Configuration;

namespace Civic.Core.Security.Configuration
{
    public class IdentityConfig : NamedConfigurationElement
    {
        #region Members

        private const string IDENTITY_CONFIG_SECTION = "identity";

        #endregion

        public IdentityConfig(INamedElement element)
        {
            if (element == null) element = new NamedConfigurationElement() { Name = SectionName };
            Children = element.Children;
            Attributes = element.Attributes;
            Name = element.Name;

            _transformXForwardedFor = Attributes.ContainsKey("xforward") && bool.Parse(Attributes["xforward"]);
        }

        /// <summary>
        /// Property to return the Section Name 
        /// </summary>
        public static string SectionName
        {
            get { return IDENTITY_CONFIG_SECTION; }
        }

        /// <summary>
        /// To Return the Current iddenty configuration Section
        /// </summary>
        internal static IdentityConfig Current
        {
            get
            {
                if (_current != null) return _current;

                if (_coreConfig == null) _coreConfig = CivicSection.Current;
                _current = new IdentityConfig(_coreConfig.Children.ContainsKey(SectionName) ? _coreConfig.Children[SectionName] : null);

                return _current;
            }
        }
        private static CivicSection _coreConfig;
        private static IdentityConfig _current;

        /// <summary>
        /// True if IdentityHelp should translate the x-forwarded-for header to get client ip
        /// </summary>
		public bool TransformXForwardedFor
		{
            get { return _transformXForwardedFor; }
            set {
                Attributes["xforward"] = value.ToString();
                _transformXForwardedFor = value;
            }
		}
        private bool _transformXForwardedFor;

        public bool UsernameHasDomain
        {
            get
            {
                if (Attributes.ContainsKey(Constants.CONFIG_USERNAMEHASDOMAIN_PROP))
                    return bool.Parse(Attributes[Constants.CONFIG_USERNAMEHASDOMAIN_PROP]);
                return Constants.CONFIG_USERNAMEHASDOMAIN_DEFAULT;
            }
            set { Attributes[Constants.CONFIG_USERNAMEHASDOMAIN_PROP] = value.ToString(); }
        }
    }
}