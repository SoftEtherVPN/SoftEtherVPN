// SoftEther VPN Source Code - Stable Edition Repository
// Build Utility
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


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
	public static class SignClient
	{
		const string SeInternalPasswordFilePath = @"\\192.168.3.2\share\tmp\signserver\password.txt";

		const string Url = "https://codesignserver:7006/sign";

		public static byte[] Sign(byte[] srcData, string certName, string flags, string comment)
		{
			string password = File.ReadAllText(SeInternalPasswordFilePath);

			string url = Url + "?password=" + password + "&cert=" + certName + "&flags=" + flags + "&comment=" + comment;

			ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
			WebRequest req = HttpWebRequest.Create(url);

			req.Timeout = 60 * 1000;
			req.Method = "POST";

			using (Stream reqs = req.GetRequestStream())
			{
				reqs.Write(srcData, 0, srcData.Length);

				reqs.Close();

				WebResponse res = req.GetResponse();

				using (Stream ress = res.GetResponseStream())
				{
					byte[] tmp = new byte[4 * 1024 * 1024];

					MemoryStream ms = new MemoryStream();

					while (true)
					{
						int r = ress.Read(tmp, 0, tmp.Length);
						if (r <= 0) break;

						ms.Write(tmp, 0, r);
					}

					return ms.ToArray();
				}
			}
		}
	}

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
		public static byte[] SignMemory(byte[] srcData, string comment, bool kernelModeDriver, bool evCert, bool skipVerify)
		{
#if	!BU_OSS
			// 2020/01/19 switch to the new system
			return SignClient.Sign(srcData, evCert ? "SoftEtherEv" : "SoftEtherFile", (kernelModeDriver ? "Driver" : "") + "," + (skipVerify ? "SkipVerify" : ""), comment);

			/*
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

			return ret;*/
#else	// BU_OSS
			return srcData;
#endif	// BU_OSS
		}

		// Digital-sign the data on the file
		public static void SignFile2(string destFileName, string srcFileName, string comment, bool kernelModeDriver, string certName)
		{
#if	!BU_OSS

			Con.WriteLine("Signing for '{0}'...", Path.GetFileName(destFileName));
			byte[] srcData = File.ReadAllBytes(srcFileName);

			byte[] destData = SignClient.Sign(srcData, certName, kernelModeDriver ? "Driver" : "", comment);

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

		// Digital-sign the data on the file
		public static void SignFile(string destFileName, string srcFileName, string comment, bool kernelModeDriver, bool evCert, bool skipVerify)
		{
#if	!BU_OSS

			Con.WriteLine("Signing for '{0}'...", Path.GetFileName(destFileName));
			byte[] srcData = File.ReadAllBytes(srcFileName);

			byte[] destData = SignMemory(srcData, comment, kernelModeDriver, evCert, skipVerify);

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

