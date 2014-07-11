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

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
