// SoftEther VPN Source Code
// Build Utility
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
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
		public static byte[] SignMemory(byte[] srcData, string comment, bool kernelModeDriver, int cert_id)
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
					out_filename = sign.ExecSign(Path.GetFileName(in_tmp_filename),
						kernelModeDriver,
						comment,
						cert_id);
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

			SignFile(destFileName, srcFileName, comment, kernelModeDriver, cert_id);
		}
		public static void SignFile(string destFileName, string srcFileName, string comment, bool kernelModeDriver, int cert_id)
		{
#if	!BU_OSS
			Con.WriteLine("Signing for '{0}'...", Path.GetFileName(destFileName));
			byte[] srcData = File.ReadAllBytes(srcFileName);

			byte[] destData = SignMemory(srcData, comment, kernelModeDriver, cert_id);

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


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
