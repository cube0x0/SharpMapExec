using System.Collections.Generic;

namespace SharpMapExec.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}