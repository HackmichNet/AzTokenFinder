# AzTokenFinder

Is a small tool to extract JWT (or JWT like looking data) from different processes, like PowerShell, Excel, Word or others. The idea was inspired from the blogpost [https://mrd0x.com/stealing-tokens-from-office-applications/](https://mrd0x.com/stealing-tokens-from-office-applications/) from the amazing [@mrd0x](https://twitter.com/mrd0x).

```cmd
AzTokenFinder.exe --help

  --processname         Names of process you want to parse. Please omit the ".exe".

  --processids          ProcessIDs you want to parse.

  --default             Enumerate Edge, Excel, Word, PowerShell, Teams, Onedrive and PowerPoint.

  --showexpiredtokes    (Default: false) Shows expired tokens.

  --help                Display this help screen.

  --version             Display version information.
```

## How does it work

There is nothing special in it. It simply opens the processes you provide and searches through the memory for JWT like looking data and extracts them. 

## Note 

It currently only works with x64 processes and it does not extract refresh tokens currently. Maybe I'll change this later.