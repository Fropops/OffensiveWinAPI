using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestForBlog
{
    internal class CreateProcessWithOutputImpersonated
    {
        [Flags]
        public enum LOGON_FlAGS : uint
        {
            LogonWithProfile = 0x00000001,
            LogonNetCredentialsOnly = 0x00000002,
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            LOGON_FlAGS dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum PROCESS_CREATION_FLAGS : uint
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
       ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);


        [Flags]
        public enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        const uint USE_STD_HANDLES = 0x00000100;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);


        public static byte[] ReadFromPipe(IntPtr pipe, uint buffSize = 1024)
        {
            byte[] chBuf = new byte[buffSize];
            bool bSuccess = ReadFile(pipe, chBuf, (uint)buffSize, out var nbBytesRead, IntPtr.Zero);
            if (!bSuccess)
            {
                int lastError = Marshal.GetLastWin32Error();
                if (lastError == 109) //Broken Pipe
                    return null;
                throw new InvalidOperationException($"Failed reading pipe : {lastError}");
            }

            byte[] ret = new byte[nbBytesRead];
            Array.Copy(chBuf, ret, nbBytesRead);
            return ret;
        }

        public static void Run()
        {
            //prepare cmd parameters
            string cmd = @"c:\windows\system32\cmd.exe /c whoami";

            var startupInfoEx = new STARTUPINFOEX();
            startupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfoEx);
            var pInfo = new PROCESS_INFORMATION();
            var outPipe_w = IntPtr.Zero;
            PROCESS_CREATION_FLAGS creationFlags = 0;
            creationFlags |= PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW;
            //creationFlags |= PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT;


            SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
            saAttr.bInheritHandle = true;
            saAttr.lpSecurityDescriptor = IntPtr.Zero;
            saAttr.nLength = Marshal.SizeOf(saAttr);
            CreatePipe(out var outPipe_rd, out outPipe_w, ref saAttr, 0);

            // Ensure the read handle to the pipe for STDOUT is not inherited.
            SetHandleInformation(outPipe_rd, HANDLE_FLAGS.INHERIT, 0);

            startupInfoEx.StartupInfo.hStdError = outPipe_w;
            startupInfoEx.StartupInfo.hStdOutput = outPipe_w;

            startupInfoEx.StartupInfo.dwFlags |= USE_STD_HANDLES;
            creationFlags |= PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW;

            string username = "pparker";
            string domain = "corp.local";
            string password = "Password123";

            try
            {
                if (!CreateProcessWithLogonW(username, domain, password, LOGON_FlAGS.LogonWithProfile, null, cmd, creationFlags, IntPtr.Zero, null, ref startupInfoEx, out pInfo))
                    throw new InvalidOperationException($"Error in CreateProcessWithLogonW : {Marshal.GetLastWin32Error()}");

                Console.WriteLine("Process started!");

                var process = System.Diagnostics.Process.GetProcessById(pInfo.dwProcessId);

                byte[] b = null;
                while (!process.HasExited)
                {
                    Thread.Sleep(100);
                    b = ReadFromPipe(outPipe_rd);
                    if (b != null)
                        Console.WriteLine(Encoding.UTF8.GetString(b));
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Oooops something went wrong....");
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                //Cleaning
                CloseHandle(pInfo.hProcess);
                CloseHandle(pInfo.hThread);
                CloseHandle(outPipe_rd);
                CloseHandle(outPipe_w);
            }
        }

    }
}
