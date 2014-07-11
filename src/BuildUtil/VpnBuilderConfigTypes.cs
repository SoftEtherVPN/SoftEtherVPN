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
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;

namespace BuildUtil
{
	// CPU data
	public class Cpu
	{
		public string Name;						// CPU name
		public string Title;					// CPU display name
		public CPUBits Bits;					// Bit length

		public Cpu(string name, string title, CPUBits bits)
		{
			this.Name = name;
			this.Title = title;
			this.Bits = bits;
		}
	}

	// OS data
	public class OS : ICloneable
	{
		public string Name;						// OS name
		public string Title;					// OS Display Name
		public string OSSimpleList;				// OS simple list
		public Cpu[] CpuList;					// CPU support list
		public bool IsWindows = false;			// Whether Windows
		public bool IsOnlyFiles = false;			// Whether only EXE file package

		public OS(string name, string title, string simpleList, Cpu[] cpuList)
		{
			this.Name = name;
			this.Title = title;
			this.OSSimpleList = simpleList;
			this.CpuList = cpuList;
		}

		public object Clone()
		{
			return this.MemberwiseClone();
		}
	}

	// Type of software
	public enum Software
	{
		vpnserver,
		vpnbridge,
		vpnclient,
		vpnserver_vpnbridge,
	}

	// Class to build the software
	public class BuildSoftware
	{
		public Software Software;				// Software
		public int Version;						// Version number
		public int BuildNumber;					// Build Number
		public string BuildName;				// Build name
		public Cpu Cpu;							// CPU
		public OS Os;							// OS
		public DateTime BuildDate;				// Build date

		public BuildSoftware(Software software, int buildNumber, int version, string buildName, Cpu cpu, OS os)
		{
			this.Software = software;
			this.BuildNumber = buildNumber;
			this.Version = version;
			this.BuildName = buildName;
			this.Cpu = cpu;
			this.Os = os;
		}

		public void SetBuildNumberVersionName(int buildNumber, int version, string buildName, DateTime date)
		{
			this.BuildNumber = buildNumber;
			this.Version = version;
			this.BuildName = buildName;
			this.BuildDate = date;
		}

		public BuildSoftware(string filename)
		{
			filename = Path.GetFileName(filename);

			if (filename.StartsWith(Paths.Prefix, StringComparison.InvariantCultureIgnoreCase))
			{
				filename = filename.Substring(Paths.Prefix.Length);
			}

			if (filename.EndsWith(".tar.gz", StringComparison.InvariantCultureIgnoreCase))
			{
				filename = Str.ReplaceStr(filename, ".tar.gz", "");
			}
			else
			{
				filename = Path.GetFileNameWithoutExtension(filename);
			}
			char[] sps = {'-'};

			string[] tokens = filename.Split(sps, StringSplitOptions.RemoveEmptyEntries);
			if (tokens.Length != 8)
			{
				throw new ApplicationException(filename);
			}

			if (tokens[1].StartsWith("v", StringComparison.InvariantCultureIgnoreCase) == false)
			{
				throw new ApplicationException(filename);
			}

			this.Software = (Software)Enum.Parse(typeof(Software), tokens[0], true);
			this.Version = (int)(double.Parse(tokens[1].Substring(1)) * 100);
			this.BuildNumber = int.Parse(tokens[2]);
			this.BuildName = tokens[3];

			string[] ds = tokens[4].Split('.');
			this.BuildDate = new DateTime(int.Parse(ds[0]), int.Parse(ds[1]), int.Parse(ds[2]));
			this.Os = OSList.FindByName(tokens[5]);
			this.Cpu = CpuList.FindByName(tokens[6]);
		}

		// Generate a string of file name equivalent
		public virtual string FileNameBaseString
		{
			get
			{
				return string.Format("{0}-v{6}-{1}-{2}-{8:D4}.{9:D2}.{10:D2}-{4}-{3}-{7}",
					Paths.Prefix + this.Software.ToString(),
					this.BuildNumber,
					this.BuildName,
					this.Cpu.Name,
					this.Os.Name,
					0,
					BuildHelper.VersionIntToString(this.Version),
					CPUBitsUtil.CPUBitsToString(this.Cpu.Bits),
					BuildDate.Year, BuildDate.Month, BuildDate.Day).ToLower();
			}
		}

		// Generate an identifier
		public virtual string IDString
		{
			get
			{
				return string.Format("{0}-{2}-{3}-{4}",
					Paths.Prefix + this.Software.ToString(),
					0,
					this.Os.Name,
					this.Cpu.Name,
					CPUBitsUtil.CPUBitsToString(this.Cpu.Bits));
			}
		}

		// Generate a title string
		public virtual string TitleString
		{
			get
			{
				return string.Format("{0} (Ver {2}, Build {1}, {3}) for {5}", BuildHelper.GetSoftwareTitle(this.Software),
					this.BuildNumber, BuildHelper.VersionIntToString(this.Version), this.Cpu.Title, 0, this.Os.Title);
			}
		}

		// Generate extension
		public virtual string OutputFileExt
		{
			get
			{
				if (this.Os.IsWindows)
				{
					return ".exe";
				}
				else
				{
					return ".tar.gz";
				}
			}
		}

		// Generate the output file name
		public virtual string OutputFileName
		{
			get
			{
				return this.FileNameBaseString + this.OutputFileExt;
			}
		}

		// Run the build
		public virtual void Build()
		{
			throw new NotSupportedException();
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
