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
	public static class PEUtil
	{
		public const int NumRetries = 5;
		public const int RetryIntervals = 200;
		public const string MutexName = "peutil_setmanifest_mutex";

		// Set the version of the PE header to 4 (to work in Windows 98, etc.)
		public static void SetPEVersionTo4(byte[] srcData)
		{
			int offset = 0x140 + (int)((uint)srcData[0x3c] + ((uint)srcData[0x3d] * 256)) - 0xf8;

			if (!((srcData[offset] == 0x04 || srcData[offset] == 0x05) && srcData[offset + 1] == 0x00))
			{
				throw new ApplicationException("The specified file is not PE file.");
			}

			srcData[offset] = 0x04;
		}
		public static void SetPEVersionTo4(string fileName)
		{
			FileInfo fi = new FileInfo(fileName);

			byte[] data = File.ReadAllBytes(fileName);
			SetPEVersionTo4(data);

			int i;
			for (i = 0;; i++)
			{
				try
				{
					File.WriteAllBytes(fileName, data);
					break;
				}
				catch (Exception ex)
				{
					if (i >= (NumRetries - 1))
					{
						throw ex;
					}

					Kernel.SleepThread(RetryIntervals);
				}
			}

			File.SetCreationTime(fileName, fi.CreationTime);
			File.SetLastAccessTime(fileName, fi.LastAccessTime);
			File.SetLastWriteTime(fileName, fi.LastWriteTime);
		}

		public static void SetManifest(string exe, string manifestName)
		{
			Mutex x = new Mutex(false, MutexName);

			x.WaitOne();

			try
			{
				// Manifest file name
				string filename = Path.Combine(Paths.ManifestsDir, manifestName);
				if (File.Exists(filename) == false)
				{
					throw new FileNotFoundException(filename);
				}

				FileInfo fi = new FileInfo(exe);

				// Copy exe file to a temporary directory
				string exeTmp = IO.CreateTempFileNameByExt(".exe");
				IO.FileCopy(exe, exeTmp);

				// Create a batch file
				string batFileName = Path.Combine(Paths.TmpDirName, "exec_mt.cmd");
				StreamWriter bat = new StreamWriter(batFileName, false, Str.ShiftJisEncoding);
				bat.WriteLine("call \"{0}\"", Paths.VisualStudioVCBatchFileName);
				bat.WriteLine("echo on");
				bat.WriteLine("mt.exe -manifest \"{0}\" -outputresource:\"{1}\";1", filename, exeTmp);
				bat.WriteLine("EXIT /B %ERRORLEVEL%");
				bat.Close();

				Exception ex = null;

				int i;
				// Repeated 20 times in order to avoid locking the file by the anti-virus software
				for (i = 0; i < 20; i++)
				{
					try
					{
						// Execute
						Win32BuildUtil.ExecCommand(Paths.CmdFileName, string.Format("/C \"{0}\"", batFileName), true);
						ex = null;

						break;
					}
					catch (Exception ex2)
					{
						ex = ex2;
					}

					ThreadObj.Sleep(Secure.Rand31i() % 50);
				}

				if (ex != null)
				{
					throw new ApplicationException("mt.exe Manifest Processing for '" + exe + "' Failed.");
				}

				// Revert to the original file
				IO.FileCopy(exeTmp, exe);

				// Restore the date and time
				File.SetCreationTime(exe, fi.CreationTime);
				File.SetLastAccessTime(exe, fi.LastAccessTime);
				File.SetLastWriteTime(exe, fi.LastWriteTime);
			}
			finally
			{
				x.ReleaseMutex();
			}
		}
	}
}
