// CoreUtil


using System;
using System.Threading;
using System.Data;
using System.Data.Sql;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
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
using System.Web.Mail;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Net.Mail;
using System.Net.Mime;
using System.Runtime.InteropServices;

namespace CoreUtil
{
	public static class Kernel
	{
		[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool IsWow64Process(
			[In] IntPtr hProcess,
			[Out] out bool wow64Process
		);

		public static bool InternalCheckIsWow64()
		{
			if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
				Environment.OSVersion.Version.Major >= 6)
			{
				using (Process p = Process.GetCurrentProcess())
				{
					bool retVal;
					if (!IsWow64Process(p.Handle, out retVal))
					{
						return false;
					}
					return retVal;
				}
			}
			else
			{
				return false;
			}
		} 

		public static void SleepThread(int millisec)
		{
			ThreadObj.Sleep(millisec);
		}

		public static string GetEnvStr(string name)
		{
			string ret = Environment.GetEnvironmentVariable(name);

			if (ret == null)
			{
				ret = "";
			}

			return ret;
		}

		static public void SelfKill()
		{
			System.Diagnostics.Process.GetCurrentProcess().Kill();
		}

		public static Process Run(string exeName, string args)
		{
			Process p = new Process();
			p.StartInfo.FileName = IO.InnerFilePath(exeName);
			p.StartInfo.Arguments = args;

			p.Start();

			return p;
		}
	}
}
