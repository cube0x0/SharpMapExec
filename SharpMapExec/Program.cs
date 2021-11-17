using SharpMapExec.args;
using System;
using System.IO;

namespace SharpMapExec
{
    internal class Program
    {
        // TOOD:
        //  computer list
        //  more ldap data
        //  smb null scan 
        //  smb file scan

        private static void Main(string[] args)
        {
            if (!Directory.Exists("loot"))
            {
                Directory.CreateDirectory("loot");
            }
            string commandName = "";
            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Console.WriteLine("\r\n[!] bad parameters:\r\n");
                Info.ShowUsage();
                return;
            }
            if (args.Length != 0 && args[1].Contains("/"))
            {
                commandName = args[0];
            }
            else if (args.Length != 0 && !(args[1].Contains("/")))
            {
                commandName = args[0] + args[1];
            }
            Console.WriteLine(commandName);
            try
            {
                var commandFound = new CommandCollection().ExecuteCommand(commandName.ToLower(), parsed.Arguments);
                if (commandFound == false)
                {
                    Console.WriteLine("\r\n[!] bad command:\r\n");
                    Info.ShowUsage();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled exception:\r\n");
                Console.WriteLine(e);
            }
        }
    }
}