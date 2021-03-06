﻿namespace Core.Security
{
    public static class StandardClaimTypes
    {
        public static bool IsGroup(string type)
        {
            var group = new[] { "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid" };
            type = type.ToLower();
            return (group[0] == type || group[1] == type);
        }

        public const string ROLE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
        public const string USERNAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
        public const string EMAIL = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
        public const string FIRST_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
        public const string LAST_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
        public const string DISPLAY_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname";
        public const string WINDOWS_ACCOUNT = "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname";
        public const string COMPANY_NAME = "http://www.tencodigo.com/companyname";
        public const string PERSON_ID = "http://www.tencodigo.com/personuid";
        public const string USER_ID = "http://www.tencodigo.com/useruid";
        public const string ACCOUNT_ID = "http://www.tencodigo.com/accountuid";
        public const string ACCOUNT_LIST = "http://www.tencodigo.com/accountlist";
        public const string ORGANIZATION_ID = "http://www.tencodigo.com/ouid";
        public const string TOKEN = "http://www.tencodigo.com/token";
        public const string CLIENT_IP = "http://www.tencodigo.com/clientip";
        public const string PHOTOTYPE = "http://www.tencodigo.com/profilePhotoType";

        public const string HOME_PHONE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone";
        public const string MOBILE_PHONE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone";
        public const string OTHER_PHONE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone";

        public const string COUNTRY_CODE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/country";
        public const string STATE_CODE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/stateorprovince";
        public const string ADDRESS = "http://schemas.microsoft.com/ws/2008/06/identity/claims/streetaddress";
        public const string CITY = "http://schemas.microsoft.com/ws/2008/06/identity/claims/locality";
        public const string POSTAL_CODE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/postalcode";
    }
}
