using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzTokenFinder
{
    internal class Options
    {
        [Option("processname", Required = false, HelpText = "Names of process you want to parse. Please omit the \".exe\".")]
        public IEnumerable<string> ProcessNames { get; set; }

        [Option("processids", Required = false, HelpText = "ProcessIDs you want to parse.")]
        public IEnumerable<int> ProcessIDs { get; set; }

        [Option("default", Required = false, HelpText = "Enumerate Edge, Excel, Word, PowerShell, Teams, Onedrive and PowerPoint.")]
        public bool Default { get; set; }
        [Option("showexpiredtokes", Required = false, HelpText = "Shows expired tokens.", Default = false)]
        public bool ShowExpiredTokens { get; set; }

    }
}
