using System;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json;
using SoftEther.VPNServerRpc;
using System.Text;
using SoftEther.JsonRpc;


namespace VPNServer_JSONRPC_CodeGen
{
    class Program
    {
        static void Main(string[] args)
        {
            string output_dir = CodeGenUtil.OutputDir_Clients;

            try
            {
                Directory.CreateDirectory(output_dir);
            }
            catch
            {
            }

            CodeGen g = new CodeGen();

            g.GenerateAndSaveCodes(output_dir);
        }
    }
}






