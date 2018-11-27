using System;
using System.Diagnostics;
using System.IO;
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

        [DebuggerStepThrough]
        public static string ToHash(this FileInfo file)
        {
            if (!file.Exists)
                return "";

            using (var fs = new FileStream(file.FullName, FileMode.Open))
            using (var sha = SHA512.Create())
            {
                sha.Initialize();
                var hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash);
            }
        }

        [DebuggerStepThrough]
        public static string ToHash(this StringBuilder data)
        {
            if(data==null || data.Length == 0)
                return "";

            return data.ToString().ToHash();
        }


    }
}

