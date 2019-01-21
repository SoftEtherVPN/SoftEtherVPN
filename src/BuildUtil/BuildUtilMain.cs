// SoftEther VPN Source Code - Developer Edition Master Branch
// Build Utility


using System;
using System.Threading;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;

namespace BuildUtil
{
	public class BuildUtilMain
	{
		public static bool pause = false;

		// Main function
		public static int Main(string[] args)
		{
			string errMsg = "";

			int ret = 0;

			ret = ConsoleService.EntryPoint("BuildUtil " + Env.CommandLine, "BuildUtil", typeof(BuildUtilMain), out errMsg);

			if (ret != 0)
			{
				Con.WriteLine("{0}: fatal error C0001: {1}", Path.GetFileNameWithoutExtension(Env.ExeFileName), errMsg);

				if (pause)
				{
					Console.Write("Press any key to exit...");
					Console.ReadKey();
				}

				Environment.Exit(1);
			}

			return ret;
		}

		// Command execution
		[ConsoleCommandMethod(
			"VPN Build Utility",
			"[/IN:infile] [/OUT:outfile] [/CSV] [/PAUSEIFERROR:yes|no] [/CMD command_line...]",
			"VPN Build Utility",
			"IN:This will specify the text file 'infile' that contains the list of commands that are automatically executed after the connection is completed. If the /IN parameter is specified, the vpncmd program will terminate automatically after the execution of all commands in the file are finished. If the file contains multiple-byte characters, the encoding must be Unicode (UTF-8). This cannot be specified together with /CMD (if /CMD is specified, /IN will be ignored).",
			"OUT:You can specify the text file 'outfile' to write all strings such as onscreen prompts, message, error and execution results. Note that if the specified file already exists, the contents of the existing file will be overwritten. Output strings will be recorded using Unicode (UTF-8) encoding.",
			"CMD:If the optional command 'command_line...' is included after /CMD, that command will be executed after the connection is complete and the vpncmd program will terminate after that. This cannot be specified together with /IN (if specified together with /IN, /IN will be ignored). Specify the /CMD parameter after all other vpncmd parameters.",
			"CSV:Enable CSV Mode.",
			"PAUSEIFERROR:Specify yes if you'd like to pause before exiting the process if there are any errors."
			)]
		public static int BuildUtil(ConsoleService c, string cmdName, string str)
		{
			Con.WriteLine("");
			Con.WriteLine("Copyright (c) SoftEther VPN Project. All Rights Reserved.");
			Con.WriteLine("");

			ConsoleParam[] args =
			{
				new ConsoleParam("IN", null, null, null, null),
				new ConsoleParam("OUT", null, null, null, null),
				new ConsoleParam("CMD", null, null, null, null),
				new ConsoleParam("CSV", null, null, null, null),
				new ConsoleParam("PAUSEIFERROR", null, null, null, null),
				new ConsoleParam("DT", null, null, null, null),
			};

			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			pause = vl["PAUSEIFERROR"].BoolValue;

			string cmdline = vl["CMD"].StrValue;

			if (vl["DT"].IsEmpty == false)
			{
				BuildSoftwareList.ListCreatedDateTime = Str.StrToDateTime(vl["DT"].StrValue);
			}

			ConsoleService cs = c;
			
			while (cs.DispatchCommand(cmdline, "BuildUtil>", typeof(BuildUtilCommands), null))
			{
				if (Str.IsEmptyStr(cmdline) == false)
				{
					break;
				}
			}

			return cs.RetCode;
		}
	}
}


