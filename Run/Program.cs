using System;
using System.Diagnostics;
using WinAPI;
using WinAPI.Wrapper;

namespace Run
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

            string cmd = null;
            ProcessCreationResult procResult = null;

            try
            {

                if (args.Length == 0)
                {
                    Console.WriteLine($"Usage: {GetRunningExeName()} cmd");
                    return;
                    //cmd = "whoami /groups";
                }
                else
                    cmd = args[0];

               
                Console.WriteLine($"[?] WinAPIAccess = {APIWrapper.Config.PreferedAccessType}");

                IntPtr hToken = IntPtr.Zero;

                var creationParms = new ProcessCreationParameters()
                {
                    Command = cmd,
                    RedirectOutput = true,
                    CreateNoWindow = true,
                };




                Console.WriteLine($"[>] Executing {cmd}...");
                procResult = APIWrapper.CreateProcess(creationParms);

                Console.WriteLine($"[?] ProcessId = {procResult.ProcessId}");
                Console.WriteLine($"[?] ProcessHandle = {procResult.ProcessHandle}");
                Console.WriteLine($"[?] PipeHandle = {procResult.OutPipeHandle}");

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
