# AzTokenFinder

Is a small tool to extract JWT (or JWT like looking data) from different processes, like PowerShell, Excel, Word or others. The idea was inspired from the blog post [https://mrd0x.com/stealing-tokens-from-office-applications/](https://mrd0x.com/stealing-tokens-from-office-applications/) from the amazing [@mrd0x](https://twitter.com/mrd0x).

In the new release, I added the research from the fabulous [@\_xpn\_](https://twitter.com/_xpn_) and his post [https://blog.xpnsec.com/wam-bam/](https://blog.xpnsec.com/wam-bam/).

```cmd
AzTokenFinder.exe --help

   --mode                 Required. (Default: Online) Use mode 'online' for parsing processes or use mode offline to decode TokenBroker Cache

  --filename             Set path to a BrokerCache File.

  --processname          Names of process you want to parse. Please omit the ".exe".

  --processids           ProcessIDs you want to parse.

  --default              Enumerate Edge, Excel, Word, PowerShell, Teams, Onedrive and PowerPoint.

  --showexpiredtokens    (Default: false) Shows expired tokens.

  --targetapp            (Default: false) Parses the files where Office, Azure CLI or Azure PowerShell stores its data. Can be Office
                         (TokenCache), AZCLI (Azure CLI) or AzPWSH (Azure Powershell)

  --help                 Display this help screen.

  --version              Display version information.
```

## How does it work

There is nothing special in it. It simply opens the processes you provide and searches through the memory for JWT like looking data and extracts them. 

## Note 

It currently only works with x64 processes.