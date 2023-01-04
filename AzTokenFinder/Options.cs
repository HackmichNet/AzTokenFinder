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
        [Option("mode", Required = true, HelpText = "Use mode 'online' for parsing processes or use mode offline to decode TokenBroker Cache", Default = "Online")]
        public String Mode { get; set; }
        [Option("filename", Required = false, HelpText = "Set path to a BrokerCache File.")]
        public String Filename { get; set; }
        [Option("processname", Required = false, HelpText = "Names of process you want to parse. Please omit the \".exe\".")]
        public IEnumerable<string> ProcessNames { get; set; }

        [Option("processids", Required = false, HelpText = "ProcessIDs you want to parse.")]
        public IEnumerable<int> ProcessIDs { get; set; }

        [Option("default", Required = false, HelpText = "Enumerate Edge, Excel, Word, PowerShell, Teams, Onedrive and PowerPoint.")]
        public bool Default { get; set; }
        [Option("showexpiredtokens", Required = false, HelpText = "Shows expired tokens.", Default = false)]
        public bool ShowExpiredTokens { get; set; }

        [Option("targetapp", Required = false, HelpText = "Parses the files where Office, Azure CLI or Azure PowerShell stores its data. Can be Office (TokenCache), AZCLI (Azure CLI) or AzPWSH (Azure Powershell)")]
        public string targetapp { get; set; }

    }
}
