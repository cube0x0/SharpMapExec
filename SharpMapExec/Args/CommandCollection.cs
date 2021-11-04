using SharpMapExec.Commands;
using System;
using System.Collections.Generic;

namespace SharpMapExec.args
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //  2. That class must have a CommandName static property that has the Command's name
        //      and must also Implement the ICommand interface
        //  3. Put the code that does the work into the Execute() method
        //  4. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(kerbspray.CommandName, () => new kerbspray());
            _availableCommands.Add(kerberosSmb.CommandName, () => new kerberosSmb());
            _availableCommands.Add(kerberosWinrm.CommandName, () => new kerberosWinrm());
            _availableCommands.Add(kerberosReg32.CommandName, () => new kerberosReg32());
            _availableCommands.Add(kerberosLdap.CommandName, () => new kerberosLdap());
            _availableCommands.Add(NtlmWinrm.CommandName, () => new NtlmWinrm());
            _availableCommands.Add(NtlmSmb.CommandName, () => new NtlmSmb());
            _availableCommands.Add(NtlmCim.CommandName, () => new NtlmCim());
            _availableCommands.Add(NtlmReg32.CommandName, () => new NtlmReg32());
            _availableCommands.Add(NtlmLdap.CommandName, () => new NtlmLdap());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound = false;
            else
            {
                // Create the command object
                var command = _availableCommands[commandName].Invoke();
                // and execute it with the arguments from the command line
                command.Execute(arguments);
                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}