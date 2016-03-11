﻿using System;
using System.Configuration;
using System.IO;
using System.Web;
using Civic.Core.Framework.Configuration;

namespace Civic.Core.Framework.Web
{
    public static class TemplateHelper
    {
        public static String GetAbsolutePath(String relativePath, String basePath)
        {
            if (relativePath == null)
                return null;
            if (basePath == null)
                basePath = Path.GetFullPath("."); // quick way of getting current working directory
            else
                basePath = GetAbsolutePath(basePath, null); // to be REALLY sure ;)
                                                            // specific for windows paths starting on \ - they need the drive added to them.
                                                            // I constructed this piece like this for possible Mono support.
            if (!Path.IsPathRooted(relativePath) || "\\".Equals(Path.GetPathRoot(relativePath)))
            {
                if (relativePath.StartsWith(Path.DirectorySeparatorChar.ToString()))
                    return Path.GetFullPath(Path.Combine(Path.GetPathRoot(basePath), relativePath.TrimStart(Path.DirectorySeparatorChar)));
                return Path.GetFullPath(Path.Combine(basePath, relativePath));
            }
            return Path.GetFullPath(relativePath); // resolves any internal "..\" to get the true full path.
        }

        private static string GetPageTemplate(HttpRequest request, string appname, bool development)
        {
            string page;

            var path1 = request.MapPath("~/" + appname + ".thtml");
            if (File.Exists(path1))
            {
                page = File.ReadAllText(path1);
            }
            else
            {
                if (development)
                {
                    var path2 = path1.Replace(appname + ".thtml", "");
                    var siteConfig = DevAppProxySection.Current.Paths.Get(appname);
                    if (siteConfig != null)
                    {
                        path2 = GetAbsolutePath(siteConfig.DevRoot + Path.DirectorySeparatorChar + "index.html", path2);
                    }

                    if (siteConfig != null && File.Exists(path2))
                    {
                        page = File.ReadAllText(path2);

                        if (!string.IsNullOrEmpty(siteConfig.ReloadPort))
                        {
                            var autoreload =
                                "<script type = \"text/javascript\">document.write('<script src=\"' + (location.protocol || 'http:') + '//' + (location.hostname || 'localhost') + ':" +
                                siteConfig.ReloadPort + 
                                "/livereload.js?snipver=1\" type=\"text/javascript\"><\\/script>')</script>";
                            page = page.Replace("</body>", autoreload + "</body>");
                        }
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(
                            string.Format("unable to locate {0}.(t)html, looked in {1} and {2}", appname, path1, path2));
                    }
                }
                else
                {
                    throw new ConfigurationErrorsException(string.Format("unable to locate {0}.(t)html, looked in {1}", appname,
                        path1));
                }
            }

            return page;
        }
    }
}