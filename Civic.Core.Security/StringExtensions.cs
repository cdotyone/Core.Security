using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Civic.Core.Security
{
    public static class StringExtensions
    {
        [DebuggerStepThrough]
        public static string ToHash(this string data)
        {
            if(string.IsNullOrEmpty(data))
                return "";

            var sha = SHA512.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));

            return BitConverter.ToString(hash);
        }
    }
}

