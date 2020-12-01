using System;
using System.Collections.Generic;
using System.IO;
using static SharpMapExec.Helpers.SecurityContext;
using static SharpMapExec.Lib.ntlmwinrm;

namespace SharpMapExec.Commands
{
    public class NtlmWinrm : ICommand
    {
        public static string CommandName => "ntlmwinrm";

        public void Execute(Dictionary<string, string> arguments)
        {
            string[] user;
            string domain = "";
            string path = "";
            string destination = "";
            string[] computernames;
            var hash = new NTHash();
            var password = new ClearText();
            string module = "";
            string moduleargument = "";
            List<string> flags = new List<string>();

            if (arguments.ContainsKey("/d"))
            {
                destination = arguments["/d"];
            }
            if (arguments.ContainsKey("/destination"))
            {
                destination = arguments["/destination"];
            }
            if (arguments.ContainsKey("/p"))
            {
                path = arguments["/p"];
            }
            if (arguments.ContainsKey("/path"))
            {
                path = arguments["/path"];
            }
            if (arguments.ContainsKey("/m"))
            {
                module = arguments["/m"];
            }
            if (arguments.ContainsKey("/module"))
            {
                module = arguments["/module"];
            }
            if (arguments.ContainsKey("/a"))
            {
                moduleargument = arguments["/a"];
            }
            if (arguments.ContainsKey("/argument"))
            {
                moduleargument = arguments["/argument"];
            }
            if (arguments.ContainsKey("/assystem") || arguments.ContainsKey("/system"))
            {
                flags.Add("system");
            }

            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            else
            {
                domain = ".";
            }

            if (arguments.ContainsKey("/user"))
            {
                if (File.Exists(arguments["/user"]))
                {
                    user = File.ReadAllLines(arguments["/user"]);
                }
                else
                {
                    string[] parts = arguments["/user"].Split('\\');
                    if (parts.Length == 2)
                    {
                        domain = parts[0];
                        user = parts[1].Split(',');
                    }
                    else
                    {
                        user = arguments["/user"].Split(',');
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] /user must be supplied!");
                return;
            }

            if (arguments.ContainsKey("/computername"))
            {
                if (File.Exists(arguments["/computername"]))
                {
                    computernames = File.ReadAllLines(arguments["/computername"]);
                }
                else
                {
                    computernames = arguments["/computername"].Split(',');
                }
            }
            else
            {
                Console.WriteLine("[-] /computername must be supplied!");
                return;
            }

            if (arguments.ContainsKey("/password"))
            {
                if (File.Exists(arguments["/password"]))
                {
                    password.Cleartext = File.ReadAllLines(arguments["/password"]);
                }
                else
                {
                    password.Cleartext = arguments["/password"].Split(',');
                }
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                if (File.Exists(arguments["/ntlm"]))
                {
                    hash.Nthash = File.ReadAllLines(arguments["/ntlm"]);
                }
                else
                {
                    hash.Nthash = arguments["/ntlm"].Split(',');
                }
            }
            else
            {
                Console.WriteLine("[-] /password or /ntlm must be supplied");
                return;
            }
            if (password.Cleartext != null)
            {
                NtlmWinRm(user, domain, password, computernames, module, moduleargument, path, destination, flags);
            }
            else
            {
                NtlmWinRm(user, domain, hash, computernames, module, moduleargument, path, destination, flags);
            }
        }
    }
}