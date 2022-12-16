using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;


namespace wanderer
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public Int32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    // The SafeTokenHandle class is designed to automatically release the handle
    // to a Windows token object when the SafeTokenHandle object is no longer needed.
    // This can help prevent resource leaks and other issues that can arise
    // when handles are not properly released, especially where we are accessing a
    // large number of processes.
    public class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle() : base(true)
        {
        }

        internal SafeTokenHandle(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(base.handle);
        }
    }

    // I'm using this class just to house the imports for the native Windows API
    // functions to help keep the code organized apart from the custom functions
    // that I use within this program.
    public class NativeMethod
    {
        // Import the necessary Windows API functions
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 desiredAccess, out SafeTokenHandle hToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(SafeTokenHandle hToken, TOKEN_INFORMATION_CLASS tokenInfoClass,
        IntPtr pTokenInfo, Int32 tokenInfoLength, out Int32 returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, UInt32 nSubAuthority);

        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        // Token Specific Access Rights
        public const UInt32 TOKEN_QUERY = 0x0008;

        // Set the error code returned from GetTokenInformation due to null buffer
        public const Int32 ERROR_INSUFFICIENT_BUFFER = 122;

        // Process integrity rid values
        public const Int32 SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
        public const Int32 SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public const Int32 SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public const Int32 SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public const Int32 SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;
    }

    internal class Program
    {
        public static string GetAmsiStatus(Process process)
        {
            try
            {
                bool loaded = process.Modules.Cast<ProcessModule>().Any(module => module.ModuleName == "amsi.dll");
                return loaded ? "Yes" : "No";
            }
            catch (Exception ex)
            {
                if (ex.Message == "Access is denied")
                {
                    return "Access Denied";
                }
                else if (ex.Message == $"[Cannot process request because the process ({process.Id}) has exited.")
                {
                    return "Process Exited";
                }
                else
                {
                    return ex.Message;
                }
            }
        }
        public static string GetProcessIntegrityLevel(int pid)
        {
            int rid = -1;
            SafeTokenHandle hToken = null;
            int cbTokenIL = 0;
            IntPtr pTokenIL = IntPtr.Zero;
            string integrity = "";

            try
            {
                // Open the access token of the given process with TOKEN_QUERY by it's PID
                Process process = Process.GetProcessById(pid);
                IntPtr processHandle = process.Handle;

                bool success = NativeMethod.OpenProcessToken(processHandle, NativeMethod.TOKEN_QUERY, out hToken);
                if (!success)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Note that we expect GetTokenInformation to return false with
                // the ERROR_INSUFFICIENT_BUFFER error code because we've given it a null buffer
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0,
                    out cbTokenIL))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != NativeMethod.ERROR_INSUFFICIENT_BUFFER)
                    {
                        throw new Win32Exception(error);
                    }
                }

                // Now we allocate a buffer for the integrity level information.
                pTokenIL = Marshal.AllocHGlobal(cbTokenIL);
                if (pTokenIL == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Now we ask for the integrity level information again
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenIL, cbTokenIL,
                    out cbTokenIL))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Marshal the TOKEN_MANDATORY_LABEL struct from native to .NET object.
                TOKEN_MANDATORY_LABEL tokenIL = (TOKEN_MANDATORY_LABEL)
                    Marshal.PtrToStructure(pTokenIL, typeof(TOKEN_MANDATORY_LABEL));

                IntPtr pIL = NativeMethod.GetSidSubAuthority(tokenIL.Label.Sid, 0);
                rid = Marshal.ReadInt32(pIL);

                // Identify the integrity lab from it's rid
                switch (rid)
                {
                    case NativeMethod.SECURITY_MANDATORY_UNTRUSTED_RID:
                        integrity = "Untrusted"; break;
                    case NativeMethod.SECURITY_MANDATORY_LOW_RID:
                        integrity = "Low"; break;
                    case NativeMethod.SECURITY_MANDATORY_MEDIUM_RID:
                        integrity = "Medium"; break;
                    case NativeMethod.SECURITY_MANDATORY_HIGH_RID:
                        integrity = "High"; break;
                    case NativeMethod.SECURITY_MANDATORY_SYSTEM_RID:
                        integrity = "System"; break;
                    default:
                        integrity = "Unknown"; break;
                }
            }
            catch (Exception ex)
            {
                if (ex.Message == "Access is denied")
                {
                    integrity = "Access Denied";
                }

                if (ex.Message == $"Cannot process request because the process ({pid}) has exited.")
                {
                    integrity = ex.Message;
                }
            }
            finally
            {
                // Clean up
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }
                if (pTokenIL != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTokenIL);
                    pTokenIL = IntPtr.Zero;
                    cbTokenIL = 0;
                }
            }
            return integrity;
        }

        public static string GetElevationStatus()
        {
            // Get the process identity
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);

            // Check if the process is elevation
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return "Yes";
            }
            else
            {
                return "No";
            }
        }

        public static string GetProcessArchitecture(Process process)
        {
            string architecture = "";
            bool isWow64;
            try
            {
                // Call the IsWow64Process function to determine whether the process is running in a 32-bit or 64-bit environment.
                if (!NativeMethod.IsWow64Process(process.Handle, out isWow64))
                {
                    throw new System.ComponentModel.Win32Exception();
                }

                if (isWow64)
                {
                    architecture = "32-bit";
                }
                else
                {
                    architecture = "64-bit";
                }

            }
            catch (Exception ex)
            {
                if (ex.Message == "Access is denied")
                {
                    architecture = "Access Denied";
                }
            }
            return architecture;
        }

        public static void OutputColor(string name, int id, string integrity, string amsi, string architecture, string elevation, string view)
        {
            ConsoleColor GetIntegrityColor(string level)
            {
                switch (level)
                {
                    case "Untrusted": return ConsoleColor.Blue;
                    case "Low": return ConsoleColor.Green;
                    case "Medium": return ConsoleColor.DarkYellow;
                    case "High": return ConsoleColor.Red;
                    case "System": return ConsoleColor.DarkRed;
                    case "Access Denied": return ConsoleColor.Red;
                    default: return ConsoleColor.DarkGray;
                }
            }

            // Output the process data in a list view
            if (view == "list")
            {
                // Process name
                Console.Write($"[*] Process Name [");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(name);
                Console.ResetColor();
                Console.Write("] ");

                // Process ID
                Console.Write($"ID [");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(id);
                Console.ResetColor();
                Console.Write("] ");

                // Process Architecture
                Console.Write($"Architecture [");
                Console.ForegroundColor = (architecture == "64-bit" ? ConsoleColor.Green : ConsoleColor.Red);
                Console.Write(architecture);
                Console.ResetColor();
                Console.Write("] ");

                // Process elevation
                if (elevation != null)
                {
                    Console.Write($"Elevated [");
                    Console.ForegroundColor = (elevation == "No" ? ConsoleColor.Green : ConsoleColor.Red);
                    Console.Write(elevation);
                    Console.ResetColor();
                    Console.Write("] ");
                }
 
                // Process Integrity
                Console.Write($"Integrity [");
                Console.ForegroundColor = GetIntegrityColor(integrity);
                Console.Write(integrity);
                Console.ResetColor();
                Console.Write("] ");
                

                // AMSI
                Console.Write($"AMSI [");
                Console.ForegroundColor = (amsi == "No" ? ConsoleColor.Green : ConsoleColor.Red);
                Console.Write(amsi);
                Console.ResetColor();
                Console.Write("] ");
            }

            // Output the data in a nested view
            if (view == "nested")
            {
                // Process name
                Console.Write($"[*] Process Name [");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(name);
                Console.ResetColor();
                Console.Write("] ");

                // Process ID
                Console.Write($"ID [");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(id);
                Console.ResetColor();
                Console.Write("] \n    [+] ");

                // Process Architecture
                Console.Write($"Architecture [");
                Console.ForegroundColor = (architecture == "64-bit" ? ConsoleColor.Green : ConsoleColor.Red);
                Console.Write(architecture);
                Console.ResetColor();
                Console.Write("] \n    [+] ");

                if (elevation != null)
                {
                    // Process elevation
                    Console.Write($"Elevated [");
                    Console.ForegroundColor = (elevation == "No" ? ConsoleColor.Green : ConsoleColor.Red);
                    Console.Write(elevation);
                    Console.ResetColor();
                    Console.Write("] \n    [+] ");
                }

                // Process Integrity
                Console.Write($"Integrity [");
                Console.ForegroundColor = GetIntegrityColor(integrity);
                Console.Write(integrity);
                Console.ResetColor();
                Console.Write("] \n    [+] ");

                // AMSI
                Console.Write($"AMSI [");
                Console.ForegroundColor = (amsi == "No" ? ConsoleColor.Green : ConsoleColor.Red);
                Console.Write(amsi);
                Console.ResetColor();
                Console.Write("]\n");
            }
            Console.WriteLine();
        }

        public static bool FilterProcessData(bool includeDenied, bool exclude64, bool exclude32, string[] excludeIntegrity, bool excludeAmsiLoaded, bool excludeAmsiUnloaded, string integrity, string amsi, string architecture)
        {
            // Assume we're going to output everything unless it's been filtered out
            bool outputData = true;

            // Do we want to include instances where our access is denied?
            if (!includeDenied && (architecture == "Access Denied" || integrity == "Access Denied" || amsi == "Access Denied"))
            {
                outputData = false;
            }

            // Do we only want instances where amsi is loaded?
            if (outputData != false && (excludeAmsiUnloaded && amsi == "No"))
            {
                outputData = false;
            }

            // Do we only want instances where amsi is unloaded?
            if (outputData != false && (excludeAmsiLoaded && amsi == "Yes"))
            {
                outputData = false;
            }

            // Do we only want instances where the integrity level doesn't include a specific level(s)?
            if (outputData != false && excludeIntegrity.Contains(integrity, StringComparer.OrdinalIgnoreCase))
            {
                outputData = false;
            }

            // Do we only want results where the the architecture is 64-bit?
            if (outputData != false && (exclude64 && architecture == "64-bit"))
            {
                outputData = false;
            }

            // Do we only want results where the the architecture is 32-bit?
            if (outputData != false && (exclude32 && architecture == "32-bit"))
            {
                outputData = false;
            }

            return outputData;
        }

        static void Main(string[] args)
        {
            // Print banner if the quiet parameter isn't supplied
            if (Array.IndexOf(args, "--quiet") == -1 && Array.IndexOf(args, "-q") == -1)
            {
                Console.WriteLine();
                Console.WriteLine("     >> Process Injection Enumeration");
                Console.WriteLine("     >> https://github.com/gh0x0st");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine();
            }

            // Parse through our given arguments regardless of their position in the args array
            if (args.Length > 0)
            {
                // Define empty variables processes, intregrity levels and amsi status
                Process[] processes = new Process[0];
                string[] excludedIntegrity = new string[] { "" };
                string excludedAmsi = "";
                bool onlyCurrent = false;

                // Are we targeting processes by their id?
                int idIndex = -1;
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "--id" || args[i] == "-i")
                    {
                        idIndex = i;
                        break;
                    }
                }

                if (idIndex != -1 && idIndex + 1 < args.Length)
                {
                    if (args[idIndex + 1].Contains(","))
                    {
                        string[] ids = args[idIndex + 1].Split(',');
                        foreach (string id in ids)
                        {
                            Process[] process = { Process.GetProcessById(int.Parse(id)) };
                            processes = processes.Concat(process).ToArray();
                        }
                    }
                    else
                    {
                        int id = int.Parse(args[idIndex + 1]);
                        processes = new Process[] { Process.GetProcessById(id) };
                    }
                }

                // Are we targeting processes by their name?
                int nameIndex = -1;
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "--name" || args[i] == "-n")
                    {
                        nameIndex = i;
                        break;
                    }
                }

                if (nameIndex != -1 && nameIndex + 1 < args.Length)
                {
                    if (args[nameIndex + 1].Contains(","))
                    {
                        string[] names = args[nameIndex + 1].Split(',');
                        foreach (string name in names)
                        {
                            Process[] process = Process.GetProcessesByName(name);
                            processes = processes.Concat(process).ToArray();
                        }
                    }
                    else
                    {
                        string name = args[nameIndex + 1];
                        processes = Process.GetProcessesByName(name);
                    }
                }

                // Are we targeting the current process?
                if (args.Any(arg => arg == "--current" || arg == "-c"))
                {
                    processes = new Process[] { Process.GetCurrentProcess() };
                    onlyCurrent = true;
                }

                // Are we targeting all processes?
                if (args.Any(arg => arg == "--all" || arg == "-a"))
                {
                    processes = Process.GetProcesses();
                    processes = processes.OrderBy(p => p.ProcessName).ToArray();
                }

                // Are we excluding specific intregrity levels?
                int integrityIndex = -1;
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "--exclude-integrity")
                    {
                        integrityIndex = i;
                        break;
                    }
                }

                if (integrityIndex != -1 && integrityIndex + 1 < args.Length)
                {
                    if (args[integrityIndex + 1].Contains(","))
                    {
                        excludedIntegrity = args[integrityIndex + 1].Split(',');
                    }
                    else
                    {
                        excludedIntegrity = new string[] { args[integrityIndex + 1] };
                    }
                }

                // Are we excluding specific amsi status?
                int amsiIndex = -1;
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "--exclude-amsi")
                    {
                        amsiIndex = i;
                        break;
                    }
                }

                if (amsiIndex != -1 && amsiIndex + 1 < args.Length)
                {
                    excludedAmsi = args[amsiIndex + 1];
                }

                // Are we including the instances where our process access is denied?
                bool includeDenied = (args.Any(arg => arg == "--include-denied") ? true : false);

                // Are we excluding instances where AMSI is loaded or unloaded?
                bool excludeAmsiLoaded = (args.Any(arg => arg == "--exclude-amsiloaded") ? true : false);
                bool excludeAmsiUnloaded = (args.Any(arg => arg == "--exclude-amsiunloaded") ? true : false);

                // Are we excluding instances where the process architecture is 32-bit or 64-bit?
                bool exclude64 = (args.Any(arg => arg == "--exclude-64") ? true : false);
                bool exclude32 = (args.Any(arg => arg == "--exclude-32") ? true : false);

                // Are we outputting the data in a nested view or keeping the default list style?
                string outputType;
                if ((args.Contains("--output-nested")))
                {
                    outputType = "nested";
                }
                else
                {
                    outputType = "list";
                }

                // If our processes array is empty, assume something bad happened
                if (processes.Length == 0)
                {
                    Console.WriteLine("[-] Unable to find any processes with the given set of target options.\n");
                    return;
                }



                // Obtain information about each targeted process
                foreach (Process process in processes)
                {
                    // Obtain injection data points
                    string integrity = GetProcessIntegrityLevel(process.Id);
                    string amsi = GetAmsiStatus(process);
                    string architecture = GetProcessArchitecture(process);

                    // Check if we're only looking at the current process so we can include current privilege status
                    if (onlyCurrent)
                    {
                        string elevation = GetElevationStatus();
                        OutputColor(process.ProcessName, process.Id, integrity, amsi, architecture, elevation, outputType);
                    }
                    else
                    {
                        // We are not bothering with processes that have exited since they were initially collected
                        string procExited = $"Cannot process request because the process ({process.Id}) has exited.";
                        if ((architecture != procExited && integrity != procExited && amsi != procExited))
                        {
                            // Write the process data for the given process if it hasn't been filtered out
                            if (FilterProcessData(includeDenied, exclude64, exclude32, excludedIntegrity, excludeAmsiLoaded, excludeAmsiUnloaded, integrity, amsi, architecture))
                            {
                                OutputColor(process.ProcessName, process.Id, integrity, amsi, architecture, null, outputType);
                            }
                        }
                    }
                }

                // Add a new line to make it look better in list view
                if (outputType == "currentList" || outputType == "list")
                {
                    Console.WriteLine();
                }
            }
            else
            {
                Console.WriteLine("Wanderer is an open-source program that collects information about running processes. " +
                                  "This information includes the integrity level, the presence of the AMSI as a loaded module, " +
                                  "whether it is running as 64-bit or 32-bit as well as the privilege level of the current process. " +
                                  "This information is extremely helpful when building payloads catered to the ideal candidate for process injection.");
                Console.WriteLine();
                Console.WriteLine("Usage: wanderer [target options] <value> [filter options] <value> [output options] <value>");
                Console.WriteLine();
                Console.WriteLine("Target Options:\n");
                Console.WriteLine("-i, --id, Target a single or group of processes by their id number");
                Console.WriteLine("-n, --name, Target a single or group of processes by their name");
                Console.WriteLine("-c, --current, Target the current process and reveal the current privilege level");
                Console.WriteLine("-a, --all, Target every running process");
                Console.WriteLine();
                Console.WriteLine("Filter Options:\n");
                Console.WriteLine("--include-denied, Include instances where process access is denied");
                Console.WriteLine("--exclude-32, Exclude instances where the process architecture is 32-bit");
                Console.WriteLine("--exclude-64, Exclude instances where the process architecture is 64-bit");
                Console.WriteLine("--exclude-amsiloaded, Exclude instances where amsi.dll is a loaded process module");
                Console.WriteLine("--exclude-amsiunloaded, Exclude instances where amsi is not loaded process module");
                Console.WriteLine("--exclude-integrity, Exclude instances where the process integrity level is a specific value");
                Console.WriteLine();
                Console.WriteLine("Output Options:\n");
                Console.WriteLine("--output-nested, Output the results in a nested style view");
                Console.WriteLine("-q, --quiet, Do not output the banner");
                Console.WriteLine();
                Console.WriteLine("Examples:\n");
                Console.WriteLine("Enumerate the process with id 12345");
                Console.WriteLine("C:\\> wanderer --id 12345\n");
                Console.WriteLine("Enumerate all processes with the names process1 and processs2");
                Console.WriteLine("C:\\> wanderer --name process1,process2\n");
                Console.WriteLine("Enumerate the current process privilege level");
                Console.WriteLine("C:\\> wanderer --current\n");
                Console.WriteLine("Enumerate all 32-bit processes");
                Console.WriteLine("C:\\wanderer --all --exclude-64\n");
                Console.WriteLine("Enumerate all processes where is AMSI is loaded");
                Console.WriteLine("C:\\> wanderer --all --exclude-amsiunloaded\n");
                Console.WriteLine("Enumerate all processes with the names pwsh,powershell,spotify and exclude instances where the integrity level is untrusted or low and exclude 32-bit processes");
                Console.WriteLine("C:\\> wanderer --name pwsh,powershell,spotify --exclude-integrity untrusted,low --exclude-32\n");
            }
        }
    }
}
