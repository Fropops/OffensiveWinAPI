using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using WinAPI.Data.AdvApi;
using WinAPI.Data.Kernel32;

namespace WinAPI.DInvoke
{
    public static class Advapi
    {
        private struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool OpenProcessToken(
                IntPtr hProcess,
                DesiredAccess dwDesiredAccess,
                out IntPtr hToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool DuplicateTokenEx(
                IntPtr hExistingToken,
                TokenAccess dwTokenAccess,
                SECURITY_ATTRIBUTES lpTokenAttributes,
                SecurityImpersonationLevel ImpersonationLevel,
                TokenType TokenType,
                out IntPtr hNewToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool ImpersonateLoggedOnUser(
                IntPtr hToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool CreateProcessWithTokenW(
                IntPtr hToken,
                LogonFlags dwLogonFlags,
                [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
                [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
                PROCESS_CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
                ref STARTUPINFOEX lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool CreateProcessWithLogonW(
               [MarshalAs(UnmanagedType.LPWStr)] string lpUsername,
               [MarshalAs(UnmanagedType.LPWStr)] string lpDomain,
               [MarshalAs(UnmanagedType.LPWStr)] string lpPassword,
               LogonFlags dwLogonFlags,
               [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
               [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
               PROCESS_CREATION_FLAGS dwCreationFlags,
               IntPtr lpEnvironment,
               [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
               ref STARTUPINFOEX lpStartupInfo,
               out PROCESS_INFORMATION lpProcessInformation);
        }

        public static bool OpenProcessToken(IntPtr hProcess, DesiredAccess dwDesiredAccess, out IntPtr hToken)
        {
            object[] parameters = { hProcess, (uint)dwDesiredAccess, null };

            var retVal = (bool)Generic.DynamicApiInvoke(@"advapi32.dll", @"OpenProcessToken", typeof(Delegates.OpenProcessToken), ref parameters);
            hToken = (IntPtr)parameters[2];
            return retVal;
        }

        public static bool ImpersonateLoggedOnUser(IntPtr hToken)
        {
            object[] parameters = { hToken };

            var retVal = (bool)Generic.DynamicApiInvoke(@"advapi32.dll", @"ImpersonateLoggedOnUser", typeof(Delegates.ImpersonateLoggedOnUser), ref parameters);
            return retVal;
        }

        public static bool DuplicateTokenEx(
              IntPtr hExistingToken,
              TokenAccess dwTokenAccess,
              ref SECURITY_ATTRIBUTES lpTokenAttributes,
              SecurityImpersonationLevel ImpersonationLevel,
              TokenType TokenType,
              out IntPtr hNewToken)
        {
            object[] parameters = { hExistingToken, (uint)dwTokenAccess, lpTokenAttributes, (int)ImpersonationLevel, (int)TokenType, null };

            var retVal = (bool)Generic.DynamicApiInvoke(@"advapi32.dll", @"DuplicateTokenEx", typeof(Delegates.DuplicateTokenEx), ref parameters);
            hNewToken = (IntPtr)parameters[5];
            return retVal;
        }

        public static bool CreateProcessWithLogonW(string lpUsername,
            string lpDomain,
            string lpPassword,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation)
        {
            object[] parameters = { lpUsername, lpDomain, lpPassword, (uint)dwLogonFlags, lpApplicationName, lpCommandLine, (uint)dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, null };

            var retVal = (bool)Generic.DynamicApiInvoke(@"advapi32.dll", @"CreateProcessWithLogonW", typeof(Delegates.CreateProcessWithLogonW), ref parameters);
            lpProcessInformation = (PROCESS_INFORMATION)parameters[10];
            return retVal;
        }

        public static bool CreateProcessWithTokenW(IntPtr hToken,
           LogonFlags dwLogonFlags,
           string lpApplicationName,
           string lpCommandLine,
           PROCESS_CREATION_FLAGS dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           ref STARTUPINFOEX lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation)
        {
            object[] parameters = { hToken, (uint)dwLogonFlags, lpApplicationName, lpCommandLine, (uint)dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, null };

            var retVal = (bool)Generic.DynamicApiInvoke(@"advapi32.dll", @"CreateProcessWithTokenW", typeof(Delegates.CreateProcessWithTokenW), ref parameters);
            lpProcessInformation = (PROCESS_INFORMATION)parameters[8];
            return retVal;
        }


    }


}
