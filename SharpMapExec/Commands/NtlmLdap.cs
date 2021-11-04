using System;
using System.Collections.Generic;
using System.IO;
using static SharpMapExec.Helpers.SecurityContext;

namespace SharpMapExec.Commands
{
    public class NtlmLdap : ICommand
    {
        public static string CommandName => "ntlmldap";

        public void Execute(Dictionary<string, string> arguments)
        {
            string[] user;
            string domain = "";
            string path = "";
            string destination = "";
            string domainController = "";
            string[] computernames = null;
            string[] hashes = null;
            string[] passwords = null;
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
            else if (arguments.ContainsKey("/module"))
            {
                module = arguments["/module"];
            }
            else
            {
                Console.WriteLine("[-] /m or /module must be supplied");
                return;
            }
            if (arguments.ContainsKey("/a"))
            {
                moduleargument = arguments["/a"];
            }
            if (arguments.ContainsKey("/argument"))
            {
                moduleargument = arguments["/argument"];
            }


            //
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            else
            {
                Console.WriteLine("[-] /domain must be supplied");
                return;
            }

            if (arguments.ContainsKey("/dc"))
            {
                domainController = arguments["/dc"];
            }
            else if (arguments.ContainsKey("/domaincontroller"))
            {
                domainController = arguments["/domaincontroller"];
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


            if (arguments.ContainsKey("/password"))
            {
                if (File.Exists(arguments["/password"]))
                {
                    passwords = File.ReadAllLines(arguments["/password"]);
                }
                else
                {
                    passwords = arguments["/password"].Split(',');
                }
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                if (File.Exists(arguments["/ntlm"]))
                {
                    hashes = File.ReadAllLines(arguments["/ntlm"]);
                }
                else
                {
                    hashes = arguments["/ntlm"].Split(',');
                }
            }
            else
            {
                Console.WriteLine("[-] /password or /ntlm must be supplied");
                return;
            }


            Lib.ntlm.Ntlm(user, domain, passwords, hashes, computernames, domainController, module, moduleargument, path, destination, flags, "domain");
        }
    }
}