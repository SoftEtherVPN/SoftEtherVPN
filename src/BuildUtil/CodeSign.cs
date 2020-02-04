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
using BuildUtil.HvSignService;

namespace BuildUtil
{
	public static class CodeSign
	{
		public const int NumRetries = 1;
		public const int RetryIntervals = 200;

		public const int NumRetriesForCopy = 50;
		public const int RetryIntervalsForCopy = 10;
		
		const string in_dir = @"\\hvsigncode\SIGN\IN";
		const string out_dir = @"\\hvsigncode\SIGN\OUT";

#if !BU_SOFTETHER
		public static int UsingCertId = 1;
#else
		public static int UsingCertId = 2;
#endif

		static object lockObj = new object();
		
		// Digital-sign the data on the memory
		public static byte[] SignMemory(byte[] srcData, string comment, bool kernelModeDriver, int cert_id, int sha_mode)
		{
#if	!BU_OSS
			int i;
			string out_filename = null;
			byte[] ret = null;

			string in_tmp_filename = Path.Combine(in_dir,
				Str.DateTimeToStrShortWithMilliSecs(DateTime.Now) + "_" +
				Env.MachineName + "_" +
				Secure.Rand63i().ToString() + ".dat");

			IO.SaveFile(in_tmp_filename, srcData);

			for (i = 0; i < NumRetries; i++)
			{
				Sign sign = new Sign();
				sign.Proxy = new WebProxy();

				try
				{
					out_filename = sign.ExecSignEx(Path.GetFileName(in_tmp_filename),
						kernelModeDriver,
						comment,
						cert_id,
						sha_mode);
					break;
				}
				catch (Exception ex)
				{
					if (i != (NumRetries - 1))
					{
						Kernel.SleepThread(RetryIntervals);
					}
					else
					{
						throw ex;
					}
				}
			}

			for (i = 0; i < NumRetriesForCopy; i++)
			{
				try
				{
					ret = IO.ReadFile(Path.Combine(out_dir, out_filename));
				}
				catch (Exception ex)
				{
					if (i != (NumRetriesForCopy - 1))
					{
						Kernel.SleepThread(RetryIntervalsForCopy);
					}
					else
					{
						throw ex;
					}
				}
			}

			string tmpFileName = IO.CreateTempFileNameByExt(".exe");
			try
			{
				File.Delete(tmpFileName);
			}
			catch
			{
			}
			File.WriteAllBytes(tmpFileName, ret);

			lock (lockObj)
			{
				if (ExeSignChecker.CheckFileDigitalSignature(tmpFileName) == false)
				{
					throw new ApplicationException("CheckFileDigitalSignature failed.");
				}

				if (kernelModeDriver)
				{
					if (ExeSignChecker.IsKernelModeSignedFile(tmpFileName) == false)
					{
						throw new ApplicationException("IsKernelModeSignedFile failed.");
					}
				}
			}

			try
			{
			}
			catch
			{
				File.Delete(tmpFileName);
			}

			return ret;
#else	// BU_OSS
			return srcData;
#endif	// BU_OSS
		}

		// Digital-sign the data on the file
		public static void SignFile(string destFileName, string srcFileName, string comment, bool kernelModeDriver)
		{
			int cert_id = UsingCertId;

			SignFile(destFileName, srcFileName, comment, kernelModeDriver, cert_id, 0);
		}
		public static void SignFile(string destFileName, string srcFileName, string comment, bool kernelModeDriver, int cert_id, int sha_mode)
		{
#if	!BU_OSS
			if (cert_id == 0)
			{
				cert_id = UsingCertId;
			}

			Con.WriteLine("Signing for '{0}'...", Path.GetFileName(destFileName));
			byte[] srcData = File.ReadAllBytes(srcFileName);

			if (srcFileName.EndsWith(".msi", StringComparison.InvariantCultureIgnoreCase))
			{
				sha_mode = 1;
				// todo: Set 2 in future !!!
			}

			byte[] destData = SignMemory(srcData, comment, kernelModeDriver, cert_id, sha_mode);

			try
			{
				File.Delete(destFileName);
			}
			catch
			{
			}

			File.WriteAllBytes(destFileName, destData);

			Con.WriteLine("Done.");
#else	// BU_OSS
			Con.WriteLine("Skipping the code signing for '{0}' in the build process. You can insert your own authenticode sign process here.", srcFileName);
#endif	// BU_OSS
		}
	}
}

