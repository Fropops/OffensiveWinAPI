using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TestForBlog
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //CreateProcess.Run();
            //CreateProcessWithOutput.Run();
            CreateProcessWithOutputImpersonated.Run();

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();

        }
    }
}
