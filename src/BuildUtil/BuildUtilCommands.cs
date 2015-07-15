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
	public static class BuildUtilCommands
	{
		// Perform all
		[ConsoleCommandMethod(
			"Builds all sources and releases all packages.",
			"All [yes|no] [/NORMALIZESRC:yes|no] [/IGNOREERROR:yes|no] [/DEBUG:yes|no] [/SERIAL:yes|no]",
			"Builds all sources and releases all packages.",
			"[yes|no]:Specify 'yes' if you'd like to increment the build number.",
			"NORMALIZESRC:Specity 'yes' if you'd like to normalize the build infomations in the source codes and resource scripts.",
			"IGNOREERROR:Specify yes if you'd like to ignore the child process to show the error message.",
			"SERIAL:Specify yes not to use parallel mode.",
			"DEBUG:Specity yes to enable debug mode. (UNIX only)"
#if !BU_SOFTETHER
			, "SEVPN:Build SoftEther VPN Automatically After PacketiX VPN Build"
#endif
			)]
		static int All(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
#if !BU_SOFTETHER
				new ConsoleParam("[yes|no]", ConsoleService.Prompt, "Increments build number (y/n) ? ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("SEVPN", ConsoleService.Prompt, "Build SoftEther VPN automatically after PacketiX VPN Build (y/n) ? ", ConsoleService.EvalNotEmpty, null),
#else
				new ConsoleParam("[yes|no]"),
#endif
				new ConsoleParam("IGNOREERROR"),
				new	ConsoleParam("DEBUG"),
				new ConsoleParam("SERIAL"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			DateTime start = Time.NowDateTime;

			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:BuildWin32 {0} /NORMALIZESRC:{1}",
				vl["[yes|no]"].BoolValue ? "yes" : "no",
				"yes"));

			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:ReleaseWin32 all /IGNOREERROR:{0} /SERIAL:{1}",
				vl["IGNOREERROR"].BoolValue ? "yes" : "no",
				vl["SERIAL"].BoolValue ? "yes" : "no"));

#if !BU_OSS
			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:ReleaseUnix all /IGNOREERROR:{0} /DEBUG:{1} /SERIAL:{2}",
				vl["IGNOREERROR"].BoolValue ? "yes" : "no",
				vl["DEBUG"].BoolValue ? "yes" : "no",
				vl["SERIAL"].BoolValue ? "yes" : "no"));
#endif

			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:CopyRelease"));

#if !BU_SOFTETHER
			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:MakeSoftEtherDir"));

			if (vl["SEVPN"].BoolValue)
			{
				// Build SEVPN
				Win32BuildUtil.ExecCommand(Paths.CmdFileName, string.Format("/C \"{0}\"", Path.Combine(Paths.SoftEtherBuildDir, @"Main\BuildAll.cmd")));
			}

			Win32BuildUtil.ExecCommand(Env.ExeFileName, string.Format("/CMD:MakeOpenSource"));
#endif

			DateTime end = Time.NowDateTime;

			Con.WriteLine("Taken time: {0}.", (end - start));

			return 0;
		}

#if !BU_SOFTETHER
		// Create SoftEther Edition source
		[ConsoleCommandMethod(
			"Make MakeSoftEtherDir Source Dir.",
			"MakeSoftEtherDir",
			"Make MakeSoftEtherDir Source Dir."
			)]
		static int MakeSoftEtherDir(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			OpenSourceUtil.MakeSoftEtherDir();

			return 0;
		}

		// Create an open source version of source
		[ConsoleCommandMethod(
			"Make MakeOpenSource Source Dir.",
			"MakeOpenSource",
			"Make MakeOpenSource Source Dir."
			)]
		static int MakeOpenSource(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			OpenSourceUtil.MakeOpenSource();

			return 0;
		}
#endif

		// Copy the released files
		[ConsoleCommandMethod(
			"Copies all release files.",
			"CopyRelease",
			"Copies all release files."
			)]
		static int CopyRelease(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			int build, version;
			string name;
			DateTime date;
			Win32BuildUtil.ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			string baseName = string.Format("v{0}-{1}-{2}-{3:D4}.{4:D2}.{5:D2}",
									BuildHelper.VersionIntToString(version),
									build,
									name,
									date.Year, date.Month, date.Day);

#if !BU_OSS
			string destDirName = Path.Combine(Paths.ReleaseDestDir,
				string.Format(@"{0}-{1}-{2}-{3}",
					Str.DateToStrShort(BuildSoftwareList.ListCreatedDateTime),
					baseName,
					Env.MachineName, Env.UserName));
#else	// !BU_OSS
			string destDirName = Path.Combine(Paths.ReleaseDestDir,
				string.Format(@"{1}",
					Str.DateToStrShort(BuildSoftwareList.ListCreatedDateTime),
					baseName,
					Env.MachineName, Env.UserName));
#endif

#if !BU_OSS
			string publicDir = Path.Combine(destDirName, "Public");
#else	// !BU_OSS
			string publicDir = destDirName;
#endif

#if !BU_OSS
			string filesReleaseDir = Path.Combine(publicDir, baseName);
#else	// !BU_OSS
			string filesReleaseDir = publicDir;
#endif

			string autorunReleaseSrcDir = Path.Combine(publicDir, "autorun");

			IO.CopyDir(Paths.ReleaseDir, filesReleaseDir, null, false, true);

#if !BU_OSS
			IO.CopyDir(Paths.ReleaseSrckitDir, Path.Combine(destDirName, "Private"), null, false, true);
			IO.CopyDir(Path.Combine(Paths.BaseDirName, @"tmp\lib"), Path.Combine(destDirName, @"Private\lib"), null, false, true);
#endif

			//IO.MakeDir(autorunReleaseSrcDir);

			/*
			File.Copy(Path.Combine(Paths.AutorunSrcDir, "Project1.exe"),
				Path.Combine(autorunReleaseSrcDir, "autorun.exe"), true);

			File.Copy(Path.Combine(Paths.AutorunSrcDir, "autorun.inf"),
				Path.Combine(autorunReleaseSrcDir, "autorun.inf"), true);

			File.Copy(Path.Combine(Paths.AutorunSrcDir, "packetix.ico"),
				Path.Combine(autorunReleaseSrcDir, "autorun.ico"), true);*/

			// Create a batch file
			string batchFileName = Path.Combine(publicDir, "MakeCD.cmd");
#if !BU_OSS
			StreamWriter w = new StreamWriter(batchFileName);
#else	// !BU_OSS
			StringWriter w = new StringWriter();
#endif
			w.WriteLine(@"SETLOCAL");
			w.WriteLine(@"SET BATCH_FILE_NAME=%0");
			w.WriteLine(@"SET BATCH_DIR_NAME=%0\..");
			w.WriteLine(@"SET NOW_TMP=%time:~0,2%");
			w.WriteLine(@"SET NOW=%date:~0,4%%date:~5,2%%date:~8,2%_%NOW_TMP: =0%%time:~3,2%%time:~6,2%");
			w.WriteLine();
			w.WriteLine();

			string[] files = Directory.GetFiles(filesReleaseDir, "*", SearchOption.AllDirectories);

			string cddir = "CD";
				/*string.Format("CD-v{0}.{1}-{2}-{3}-{4:D4}.{5:D2}.{6:D2}",
				version / 100, version % 100, build, name,
				date.Year, date.Month, date.Day);*/

			StringWriter txt = new StringWriter();

			foreach (string filename in files)
			{
				string file = filename;

				BuildSoftware s = new BuildSoftware(file);

				// Software\Windows\PacketiX VPN Server 4.0\32bit (Intel x86)\filename.exe
				string cpustr = string.Format("{0} - {1}", CPUBitsUtil.CPUBitsToString(s.Cpu.Bits), s.Cpu.Title).Replace("/", "or");
				string cpustr2 = cpustr;

				if (s.Cpu == CpuList.intel)
				{
					cpustr2 = "";
					cpustr = "Intel";
				}

				string tmp = string.Format(@"{1}\{2}\{3}\{5}{4}",
					0,
					s.Os.Title,
					BuildHelper.GetSoftwareTitle(s.Software),
					cpustr2,
					Path.GetFileName(file),
					""
					);

				tmp = Str.ReplaceStr(tmp, "\\\\", "\\");

				tmp = Str.ReplaceStr(tmp, " ", "_");

				w.WriteLine("mkdir \"{1}\\{0}\"", Path.GetDirectoryName(tmp), cddir);
				w.WriteLine("copy /b /y \"{2}\\{0}\" \"{3}\\{1}\"", IO.GetRelativeFileName(file, filesReleaseDir), tmp, baseName, cddir);
				w.WriteLine();

				string txt_filename = tmp;
				txt_filename = Str.ReplaceStr(txt_filename, "\\", "/");

				string txt_description = BuildHelper.GetSoftwareTitle(s.Software);

				string txt_products = BuildHelper.GetSoftwareProductList(s.Software);

				string txt_os = s.Os.Title;

				string txt_cpu = s.Cpu.Title;
				if (s.Cpu.Bits != CPUBits.Both)
				{
					txt_cpu += " (" + CPUBitsUtil.CPUBitsToString(s.Cpu.Bits) + ")";
				}
				else
				{
					txt_cpu += " (x86 and x64)";
				}

				string txt_version = BuildHelper.VersionIntToString(version);

				string txt_build = build.ToString();

				string txt_verstr = name;

				string txt_date = Str.DateTimeToStrShortWithMilliSecs(date);

				string txt_lang = "English, Japanese, Simplified Chinese";

				string txt_category = "PacketiX VPN (Commercial)";

#if BU_SOFTETHER
				txt_category = "SoftEther VPN (Freeware)";
#endif

				txt.WriteLine("FILENAME\t" + txt_filename);
				txt.WriteLine("DESCRIPTION\t" + txt_description);
				txt.WriteLine("CATEGORY\t" + txt_category);
				txt.WriteLine("PRODUCT\t" + txt_products);
				txt.WriteLine("OS\t" + txt_os);
				txt.WriteLine("OSLIST\t" + s.Os.OSSimpleList);
				txt.WriteLine("CPU\t" + txt_cpu);
				txt.WriteLine("VERSION\t" + txt_version);
				txt.WriteLine("BUILD\t" + txt_build);
				txt.WriteLine("VERSTR\t" + txt_verstr);
				txt.WriteLine("DATE\t" + txt_date);
				txt.WriteLine("LANGUAGE\t" + txt_lang);
				txt.WriteLine("*");
				txt.WriteLine();
			}

#if BU_OSS
			Con.WriteLine("Installer packages are built on '{0}'. Enjoy it !!", publicDir);

			return 0;
#endif	// BU_OSS

			/*
			w.WriteLine("mkdir \"{0}\\autorun\"", cddir);
			w.WriteLine("copy /b /y autorun\\autorun.ico \"{0}\\autorun\"", cddir);
			w.WriteLine("copy /b /y autorun\\autorun.exe \"{0}\\autorun\"", cddir);
			w.WriteLine("copy /b /y autorun\\autorun.inf \"{0}\\autorun.inf\"", cddir);
			 * */

			string zipFileName = string.Format("VPN-CD-v{0}.{1:D2}-{2}-{3}-{4:D4}.{5:D2}.{6:D2}.zip",
				version / 100, version % 100, build, name,
				date.Year, date.Month, date.Day);
			w.WriteLine("del {0}", zipFileName);
			w.WriteLine("CD {0}", cddir);
			w.WriteLine("zip -r -0 ../{0} *", zipFileName);
			w.WriteLine("cd ..");
			w.WriteLine("move {0} CD\\", zipFileName);
			w.WriteLine("rename CD {0}-tree", baseName);
			w.WriteLine();

			w.Close();

			// Copy of fastcopy
			string fastcopy_dest = Path.Combine(destDirName, @"Private\fastcopy_bin");
			IO.MakeDirIfNotExists(fastcopy_dest);
			File.Copy(Path.Combine(Paths.UtilityDirName, "FastCopy.exe"), Path.Combine(fastcopy_dest, "FastCopy.exe"), true);
			File.Copy(Path.Combine(Paths.UtilityDirName, "FastEx64.dll"), Path.Combine(fastcopy_dest, "FastEx64.dll"), true);
			File.Copy(Path.Combine(Paths.UtilityDirName, "FastExt1.dll"), Path.Combine(fastcopy_dest, "FastExt1.dll"), true);

			string fastcopy_exe = @"..\Private\fastcopy_bin\FastCopy.exe";

			// Create a upload batch
			string uploadBatchFileName = Path.Combine(publicDir, "UploadNow.cmd");
#if !BU_OSS
			w = new StreamWriter(uploadBatchFileName);
#endif	// !BU_OSS

			string folder_name = "packetix";
#if BU_SOFTETHER
			folder_name = "softether";
#endif
			w.WriteLine(@"mkdir \\download\FILES\{1}\{0}-tree", baseName, folder_name);
			w.WriteLine(@"{0} /cmd=force_copy /exclude={3} /auto_close /force_start /estimate /open_window /error_stop=TRUE /bufsize=128 /disk_mode=diff /speed=full /verify {1}-tree /to=\\download\FILES\{2}\{1}-tree", fastcopy_exe, baseName, folder_name,
				"\"*files.txt*\"");

			w.WriteLine();
			/*
			w.WriteLine(@"mkdir \\downloadjp\FILES\{1}\{0}-tree", baseName, folder_name);
			w.WriteLine(@"{0} /cmd=force_copy /exclude={3} /auto_close /force_start /estimate /open_window /error_stop=TRUE /bufsize=128 /disk_mode=diff /speed=full /verify {1}-tree /to=\\downloadjp\FILES\{2}\{1}-tree", fastcopy_exe, baseName, folder_name,
				"\"*files.txt*\"");

			w.WriteLine();*/
	
			w.WriteLine(@"copy /y /b {0}-tree\files.txt \\download\FILES\{1}\{0}-tree\files.txt", baseName, folder_name);
			//w.WriteLine(@"copy /y /b {0}-tree\files.txt \\downloadjp\FILES\{1}\{0}-tree\files.txt", baseName, folder_name);


			w.WriteLine();
			w.WriteLine(@"pause");
			w.WriteLine();

			w.Close();


			txt.WriteLine("FILENAME\t" + zipFileName);
#if BU_SOFTETHER
			txt.WriteLine("DESCRIPTION\t" + "ZIP CD-ROM Image Package of SoftEther VPN (for Admins)");
			txt.WriteLine("CATEGORY\t" + "SoftEther VPN (Freeware)");
			txt.WriteLine("PRODUCT\t" + "ZIP CD-ROM Image Package of SoftEther VPN");
#else	// BU_SOFTETHER
			txt.WriteLine("DESCRIPTION\t" + "ZIP CD-ROM Image Package of PacketiX VPN (for Admins)");
			txt.WriteLine("CATEGORY\t" + "PacketiX VPN (Commercial)");
			txt.WriteLine("PRODUCT\t" + "ZIP CD-ROM Image Package of PacketiX VPN");
#endif	// BU_SOFTETHER
			txt.WriteLine("OS\t" + "Any");
			txt.WriteLine("OSLIST\t" + "Any");
			txt.WriteLine("CPU\t" + "CD-ROM");
			txt.WriteLine("VERSION\t" + BuildHelper.VersionIntToString(version));
			txt.WriteLine("BUILD\t" + build.ToString());
			txt.WriteLine("VERSTR\t" + name);
			txt.WriteLine("DATE\t" + Str.DateTimeToStrShortWithMilliSecs(date));
			txt.WriteLine("LANGUAGE\t" + "English, Japanese, Simplified Chinese");
			txt.WriteLine("*");
			txt.WriteLine();

			string src_bindir = Path.Combine(Paths.BaseDirName, "bin");
			string vpnsmgr_zip_filename_relative = @"Windows\Admin_Tools\VPN_Server_Manager_and_Command-line_Utility_Package\";
			vpnsmgr_zip_filename_relative += 
#if BU_SOFTETHER
				"softether-" + 
#endif	// BU_SOFTETHER
			string.Format("vpn_admin_tools-v{0}.{1:D2}-{2}-{3}-{4:D4}.{5:D2}.{6:D2}-win32.zip",
				version / 100, version % 100, build, name,
				date.Year, date.Month, date.Day);

			string vpnsmgr_zip_filename_full = Path.Combine(Path.Combine(publicDir, cddir), vpnsmgr_zip_filename_relative);

			ZipPacker zip = new ZipPacker();
			zip.AddFileSimple("vpnsmgr.exe", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, "vpnsmgr.exe")), true);
			zip.AddFileSimple("vpncmd.exe", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, "vpncmd.exe")), true);
			zip.AddFileSimple("hamcore.se2", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, @"BuiltHamcoreFiles\hamcore_win32\hamcore.se2")), true);
			zip.AddFileSimple("ReadMeFirst_License.txt", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, @"hamcore\eula.txt")), true);
			zip.AddFileSimple("ReadMeFirst_Important_Notices_ja.txt", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, @"hamcore\warning_ja.txt")), true);
			zip.AddFileSimple("ReadMeFirst_Important_Notices_en.txt", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, @"hamcore\warning_en.txt")), true);
			zip.AddFileSimple("ReadMeFirst_Important_Notices_cn.txt", DateTime.Now, FileAttributes.Normal,
				IO.ReadFile(Path.Combine(src_bindir, @"hamcore\warning_cn.txt")), true);
			zip.Finish();
			byte[] zip_data = zip.GeneratedData.Read();
			IO.MakeDirIfNotExists(Path.GetDirectoryName(vpnsmgr_zip_filename_full));
			IO.SaveFile(vpnsmgr_zip_filename_full, zip_data);

			// ZIP package for VPN Server Manager GUI
			txt.WriteLine("FILENAME\t" + Str.ReplaceStr(vpnsmgr_zip_filename_relative, @"\", "/"));
#if BU_SOFTETHER
			txt.WriteLine("DESCRIPTION\t" + "ZIP Package of vpnsmgr.exe and vpncmd.exe (without installers)");
			txt.WriteLine("CATEGORY\t" + "SoftEther VPN (Freeware)");
			txt.WriteLine("PRODUCT\t" + "SoftEther VPN Server Manager for Windows, SoftEther VPN Command-Line Admin Utility (vpncmd)");
#else	// BU_SOFTETHER
			txt.WriteLine("DESCRIPTION\t" + "ZIP Package of vpnsmgr.exe and vpncmd.exe (without installers)");
			txt.WriteLine("CATEGORY\t" + "PacketiX VPN (Commercial)");
			txt.WriteLine("PRODUCT\t" + "PacketiX VPN Server Manager for Windows, PacketiX VPN Command-Line Admin Utility (vpncmd)");
#endif	// BU_SOFTETHER
			txt.WriteLine("OS\t" + "Windows (.zip package without installers)");
			txt.WriteLine("OSLIST\t" + OSList.Windows.OSSimpleList);
			txt.WriteLine("CPU\t" + "Intel (x86 and x64)");
			txt.WriteLine("VERSION\t" + BuildHelper.VersionIntToString(version));
			txt.WriteLine("BUILD\t" + build.ToString());
			txt.WriteLine("VERSTR\t" + name);
			txt.WriteLine("DATE\t" + Str.DateTimeToStrShortWithMilliSecs(date));
			txt.WriteLine("LANGUAGE\t" + "English, Japanese, Simplified Chinese");
			txt.WriteLine("*");
			txt.WriteLine();

			IO.MakeDirIfNotExists(Path.Combine(publicDir, cddir));
			File.WriteAllText(Path.Combine(Path.Combine(publicDir, cddir), "files.txt"), txt.ToString(), Str.Utf8Encoding);


			// Execution of batch file
			string old_cd = Environment.CurrentDirectory;

			try
			{
				Environment.CurrentDirectory = Path.GetDirectoryName(batchFileName);
			}
			catch
			{
			}

			Win32BuildUtil.ExecCommand(Paths.CmdFileName, string.Format("/C \"{0}\"", batchFileName));

			try
			{
				Environment.CurrentDirectory = old_cd;
			}
			catch
			{
			}

			Con.WriteLine();
			Con.WriteLine("'{0}' に出力されました。", destDirName);

			return 0;
		}

		// UNIX release
		[ConsoleCommandMethod(
			"Builds UNIX installer package files.",
			"ReleaseUnix [id] [/IGNOREERROR:yes|no] [/DEBUG:yes|no] [/SERIAL:yes|no]",
			"Builds Unix installer package files.",
			"[id]:Specify target package ID which you'd like to build. If you'd like to erase and rebuild all packages, specify 'all'. Specify 'clean' to delete all release files.",
			"IGNOREERROR:Specify yes if you'd like to ignore the child process to show the error message.",
			"SERIAL:Specify yes not to use parallel mode.",
			"DEBUG:Specity yes to enable debug mode."
			)]
		static int ReleaseUnix(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[id]"),
				new ConsoleParam("IGNOREERROR"),
				new	ConsoleParam("DEBUG"),
				new ConsoleParam("SERIAL"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			int version, build;
			string name;
			DateTime date;
			Win32BuildUtil.ReadBuildInfoFromTextFile(out build, out version, out name, out date);
			BuildSoftware[] softs = BuildSoftwareList.List;
			bool serial = vl["SERIAL"].BoolValue;

			if (Str.IsEmptyStr(vl.DefaultParam.StrValue))
			{
				Con.WriteLine("IDs:");
				foreach (BuildSoftware soft in softs)
				{
					if (soft.Os.IsWindows == false)
					{
						soft.SetBuildNumberVersionName(build, version, name, date);
						Con.WriteLine("  {0}", soft.IDString);
						Con.WriteLine("    - \"{0}\"", soft.OutputFileName);
					}
				}
			}
			else
			{
				string key = vl.DefaultParam.StrValue;
				bool all = false;

				if ("all".StartsWith(key, StringComparison.InvariantCultureIgnoreCase))
				{
					all = true;
				}

				if ("clean".StartsWith(key, StringComparison.InvariantCultureIgnoreCase))
				{
					// Delete the release directory
					Paths.DeleteAllReleaseTarGz();
					Con.WriteLine("Clean completed.");
					return 0;
				}

				List<BuildSoftware> o = new List<BuildSoftware>();

				foreach (BuildSoftware soft in softs)
				{
					soft.SetBuildNumberVersionName(build, version, name, date);

					if (soft.Os.IsWindows == false)
					{
						if (all || soft.IDString.IndexOf(key, StringComparison.InvariantCultureIgnoreCase) != -1)
						{
							o.Add(soft);
						}
					}
				}

				if (o.Count == 0)
				{
					throw new ApplicationException(string.Format("Software ID '{0}' not found.", key));
				}
				else
				{
					if (all)
					{
						// Delete the release directory
						Paths.DeleteAllReleaseTarGz();
					}
					else
					{
						IO.MakeDir(Paths.ReleaseDir);
					}

					if (serial)
					{
						// Build in series
						int i;
						for (i = 0; i < o.Count; i++)
						{
							Con.WriteLine("{0} / {1}: Executing for '{2}'...",
								i + 1, o.Count, o[i].IDString);

							BuildHelper.BuildMain(o[i], vl["DEBUG"].BoolValue);
						}
					}
					else if (o.Count == 1)
					{
						// To build
						BuildHelper.BuildMain(o[0], vl["DEBUG"].BoolValue);
					}
					else
					{
						// Make a child process build
						Process[] procs = new Process[o.Count];

						int i;

						for (i = 0; i < o.Count; i++)
						{
							Con.WriteLine("{0} / {1}: Executing for '{2}'...",
								i + 1, o.Count, o[i].IDString);

							procs[i] = Kernel.Run(Env.ExeFileName,
								string.Format("/PAUSEIFERROR:{1} /DT:{2} /CMD:ReleaseUnix /DEBUG:{3} {0}",
								o[i].IDString, vl["IGNOREERROR"].BoolValue ? "no" : "yes", Str.DateTimeToStrShort(BuildSoftwareList.ListCreatedDateTime), vl["DEBUG"].BoolValue ? "yes" : "no")
								);
						}

						Con.WriteLine("Waiting child processes...");

						int numError = 0;

						for (i = 0; i < o.Count; i++)
						{
							procs[i].WaitForExit();

							bool ok = procs[i].ExitCode == 0;

							if (ok == false)
							{
								numError++;
							}

							Con.WriteLine("{0} / {1} ({2}):", i + 1, o.Count, o[i].IDString);
							Con.WriteLine("       {0}", ok ? "Success" : "* Error *");
						}

						Con.WriteLine();
						if (numError != 0)
						{
							throw new ApplicationException(string.Format("{0} Errors.", numError));
						}
						Con.WriteLine("No Errors.");
					}
				}
			}

			return 0;
		}

		// Win32 Release
		[ConsoleCommandMethod(
			"Builds Win32 installer package files.",
			"ReleaseWin32 [id] [/IGNOREERROR:yes|no] [/SERIAL:yes|no]",
			"Builds Win32 installer package files.",
			"[id]:Specify target package ID which you'd like to build. If you'd like to erase and rebuild all packages, specify 'all'. Specify 'clean' to delete all release files.",
			"SERIAL:Specify yes not to use parallel mode.",
			"IGNOREERROR:Specify yes if you'd like to ignore the child process to show the error message."
			)]
		static int ReleaseWin32(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[id]"),
				new ConsoleParam("IGNOREERROR"),
				new ConsoleParam("SERIAL"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			bool serial = vl["SERIAL"].BoolValue;
			int version, build;
			string name;
			DateTime date;
			Win32BuildUtil.ReadBuildInfoFromTextFile(out build, out version, out name, out date);
			BuildSoftware[] softs = BuildSoftwareList.List;

			if (Str.IsEmptyStr(vl.DefaultParam.StrValue))
			{
				Con.WriteLine("IDs:");
				foreach (BuildSoftware soft in softs)
				{
					if (soft.Os.IsWindows)
					{
						soft.SetBuildNumberVersionName(build, version, name, date);
						Con.WriteLine("  {0}", soft.IDString);
						Con.WriteLine("    - \"{0}\"", soft.OutputFileName);
					}
				}
			}
			else
			{
				string key = vl.DefaultParam.StrValue;
				bool all = false;

				if ("all".StartsWith(key, StringComparison.InvariantCultureIgnoreCase))
				{
					all = true;
				}

				if ("clean".StartsWith(key, StringComparison.InvariantCultureIgnoreCase))
				{
					// Delete the release directory
					Paths.DeleteAllReleaseExe();
					Con.WriteLine("Clean completed.");
					return 0;
				}

				List<BuildSoftware> o = new List<BuildSoftware>();

				foreach (BuildSoftware soft in softs)
				{
					soft.SetBuildNumberVersionName(build, version, name, date);

					if (soft.Os.IsWindows)
					{
						if (all || soft.IDString.IndexOf(key, StringComparison.InvariantCultureIgnoreCase) != -1)
						{
							o.Add(soft);
						}
					}
				}

				if (o.Count == 0)
				{
					throw new ApplicationException(string.Format("Software ID '{0}' not found.", key));
				}
				else
				{
					if (all)
					{
						// Delete the release directory
						Paths.DeleteAllReleaseExe();
					}
					else
					{
						IO.MakeDir(Paths.ReleaseDir);
					}

					if (serial)
					{
						// Build in series
						int i;
						for (i = 0; i < o.Count; i++)
						{
							Con.WriteLine("{0} / {1}: Executing for '{2}'...",
								i + 1, o.Count, o[i].IDString);

							BuildHelper.BuildMain(o[i], false);
						}
					}
					else if (o.Count == 1)
					{
						// To build
						BuildHelper.BuildMain(o[0], false);
					}
					else
					{
						// Make a child process build
						Process[] procs = new Process[o.Count];

						int i;

						for (i = 0; i < o.Count; i++)
						{
							Con.WriteLine("{0} / {1}: Executing for '{2}'...",
								i + 1, o.Count, o[i].IDString);

							procs[i] = Kernel.Run(Env.ExeFileName,
								string.Format("/PAUSEIFERROR:{1} /CMD:ReleaseWin32 {0}",
								o[i].IDString, vl["IGNOREERROR"].BoolValue ? "no" : "yes"));
						}

						Con.WriteLine("Waiting child processes...");

						int numError = 0;

						for (i = 0; i < o.Count; i++)
						{
							procs[i].WaitForExit();

							bool ok = procs[i].ExitCode == 0;

							if (ok == false)
							{
								numError++;
							}

							Con.WriteLine("{0} / {1} ({2}):", i + 1, o.Count, o[i].IDString);
							Con.WriteLine("       {0}", ok ? "Success" : "* Error *");
						}

						Con.WriteLine();
						if (numError != 0)
						{
							throw new ApplicationException(string.Format("{0} Errors.", numError));
						}
						Con.WriteLine("No Errors.");
					}
				}
			}

			return 0;
		}

		// Copy the Unix source
		[ConsoleCommandMethod(
			"Copies source codes for Unix.",
			"CopyUnixSrc [destdir]",
			"Copies source codes for Unix.",
			"[destdir]:Specify the destination directory."
			)]
		static int CopyUnixSrc(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[destdir]", ConsoleService.Prompt, "Destination directory : ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			((BuildSoftwareUnix)BuildSoftwareList.vpnbridge_linux_x86_ja).CopyUnixSrc(vl.DefaultParam.StrValue);

			return 0;
		}

		// Driver package build
		// Win32 build
		[ConsoleCommandMethod(
			"Builds the driver package.",
			"BuildDriverPackage",
			"Builds the driver package.")]
		static int BuildDriverPackage(ConsoleService c, string cmdName, string str)
		{
			Win32BuildUtil.MakeDriverPackage();

			return 0;
		}

		// Win32 build
		[ConsoleCommandMethod(
			"Builds all executable files for win32 and HamCore for all OS.",
			"BuildWin32 [yes|no] [/NORMALIZESRC:yes|no]",
			"Builds all executable files for win32 and HamCore for all OS.",
			"[yes|no]:Specify 'yes' if you'd like to increment the build number.",
			"NORMALIZESRC:Specity 'yes' if you'd like to normalize the build infomations in the source codes and resource scripts."
			)]
		static int BuildWin32(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[yes|no]", ConsoleService.Prompt, "Increments build number (y/n) ? ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("NORMALIZESRC", ConsoleService.Prompt, "Normalizes source codes (y/n) ? ", ConsoleService.EvalNotEmpty, null)
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			if (vl.DefaultParam.BoolValue)
			{
				Win32BuildUtil.IncrementBuildNumber();
			}
			if (vl.DefaultParam.BoolValue || vl["NORMALIZESRC"].BoolValue)
			{
				Win32BuildUtil.NormalizeBuildInfo();
			}

			Paths.DeleteAllReleaseTarGz();
			Paths.DeleteAllReleaseExe();
			Paths.DeleteAllReleaseManuals();
			Paths.DeleteAllReleaseAdminKits();

			Win32BuildUtil.BuildMain();
			Win32BuildUtil.SignAllBinaryFiles();
			HamCoreBuildUtil.BuildHamcore();
			Win32BuildUtil.CopyDebugSnapshot();

			return 0;
		}

		// Process of post-build
		[ConsoleCommandMethod(
			"Process necessary tasks after building.",
			"PostBuild",
			"Process necessary tasks after building."
			)]
		static int PostBuild(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			Win32BuildUtil.SignAllBinaryFiles();
			HamCoreBuildUtil.BuildHamcore();

			return 0;
		}

		// Increment the build number
		[ConsoleCommandMethod(
			"Increments the build number.",
			"IncrementBuildNumber",
			"Increments the build number written in 'CurrentBuild.txt' text file."
			)]
		static int IncrementBuildNumber(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			Win32BuildUtil.IncrementBuildNumber();

			return 0;
		}


		// Test processing
		[ConsoleCommandMethod(
			"Run Test Procedure.",
			"Test",
			"Run Test Procedure."
			)]
		static int Test(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			TestClass.Test();

			return 0;
		}

		// Build a HamCore
		[ConsoleCommandMethod(
			"Builds a HamCore file.",
			"BuildHamCore",
			"Builds a HamCore file."
			)]
		static int BuildHamCore(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			HamCoreBuildUtil.BuildHamcore();

			return 0;
		}

		// Sign a binary file
		[ConsoleCommandMethod(
			"Sign all binary files.",
			"SignAll",
			"Sign all binary files."
			)]
		static int SignAll(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			Win32BuildUtil.SignAllBinaryFiles();

			return 0;
		}

		// Create and sign a Inf file of SeLow for Windows 8
		[ConsoleCommandMethod(
			"Generate INF files for SeLow.",
			"SignSeLowInfFiles",
			"Generate INF files for SeLow."
			)]
		static int SignSeLowInfFiles(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[cpu]", ConsoleService.Prompt, "x86 / x64: ", ConsoleService.EvalNotEmpty, null)
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

#if	!BU_OSS

			Win32BuildUtil.SignSeLowInfFiles(vl.DefaultParam.StrValue);

#endif

			return 0;
		}

		// Create Inf file for Windows 8
		[ConsoleCommandMethod(
			"Generate INF files for Windows 8.",
			"GenerateWin8InfFiles",
			"Generate INF files for Windows 8."
			)]
		static int GenerateWin8InfFiles(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[cpu]", ConsoleService.Prompt, "x86 / x64: ", ConsoleService.EvalNotEmpty, null)
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

#if	!BU_OSS

			Win32BuildUtil.GenerateINFFilesForWindows8(vl.DefaultParam.StrValue);

#endif

			return 0;
		}

		// Set the version of the PE to 4
		[ConsoleCommandMethod(
			"Set the version of the PE file to 4.",
			"SetPE4 [filename]",
			"Set the version of the PE file to 4.",
			"[filename]:Specify the target filename."
			)]
		static int SetPE4(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[filename]", ConsoleService.Prompt, "Filename: ", ConsoleService.EvalNotEmpty, null)
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			PEUtil.SetPEVersionTo4(vl.DefaultParam.StrValue);

			return 0;
		}

		// Set the Manifest
		[ConsoleCommandMethod(
			"Set the manifest to the executable file.",
			"SetManifest [filename] [/MANIFEST:manifest_file_name]",
			"Set the manifest to the executable file.",
			"[filename]:Specify the target executable filename.",
			"MANIFEST:Specify the manifest XML file."
			)]
		static int SetManifest(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[filename]", ConsoleService.Prompt, "Target Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("MANIFEST", ConsoleService.Prompt, "Manifest Filename: ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			PEUtil.SetManifest(vl.DefaultParam.StrValue, vl["MANIFEST"].StrValue);

			return 0;
		}

		// Generate a version information resource
		[ConsoleCommandMethod(
			"Generate a Version Information Resource File.",
			"GenerateVersionResource [targetFileName] [/OUT:destFileName]",
			"Generate a Version Information Resource File.",
			"[targetFileName]:Specify the target exe/dll file name.",
			"OUT:Specify the output .res file.",
			"RC:Specify a template RC file name.")]
		static int GenerateVersionResource(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[targetFileName]", ConsoleService.Prompt, "Target Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("OUT", ConsoleService.Prompt, "Dst Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("PRODUCT"),
				new ConsoleParam("RC"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string targetFilename = vl.DefaultParam.StrValue;
			string outFilename = vl["OUT"].StrValue;
			string product_name = vl["PRODUCT"].StrValue;

			Win32BuildUtil.GenerateVersionInfoResource(targetFilename, outFilename, vl["RC"].StrValue, product_name);

			return 0;
		}

		// Measure the number of lines of code
		[ConsoleCommandMethod(
			"Count the number of lines of the sources.",
			"Count [DIR]",
			"Count the number of lines of the sources.",
			"[DIR]:dir name.")]
		static int Count(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[DIR]", null, null, null, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string dir = vl.DefaultParam.StrValue;
			if (Str.IsEmptyStr(dir))
			{
				dir = Paths.BaseDirName;
			}

			string[] files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);

			int numLines = 0;
			int numBytes = 0;
			int numComments = 0;
			int totalLetters = 0;

			Dictionary<string, int> commentsDict = new Dictionary<string, int>();

			foreach (string file in files)
			{
				string ext = Path.GetExtension(file);

				if (Str.StrCmpi(ext, ".c") || Str.StrCmpi(ext, ".cpp") || Str.StrCmpi(ext, ".h") ||
                    Str.StrCmpi(ext, ".rc") || Str.StrCmpi(ext, ".stb") || Str.StrCmpi(ext, ".cs")
                     || Str.StrCmpi(ext, ".fx") || Str.StrCmpi(ext, ".hlsl"))
				{
					if (Str.InStr(file, "\\.svn\\") == false && Str.InStr(file, "\\seedll\\") == false && Str.InStr(file, "\\see\\") == false && Str.InStr(file, "\\openssl\\") == false)
					{
						string[] lines = File.ReadAllLines(file);

						numLines += lines.Length;
						numBytes += (int)new FileInfo(file).Length;

						foreach (string line in lines)
						{
							if (Str.InStr(line, "//") && Str.InStr(line, "// Validate arguments") == false)
							{
								if (commentsDict.ContainsKey(line) == false)
								{
									commentsDict.Add(line, 1);
								}
								numComments++;

								totalLetters += line.Trim().Length - 3;
							}
						}
					}
				}
			}

			Con.WriteLine("{0} Lines,  {1} Bytes.  {2} Comments ({3} distinct, aver: {4})", Str.ToStr3(numLines), Str.ToStr3(numBytes),
				Str.ToStr3(numComments), commentsDict.Count, totalLetters / numComments);

			return 0;
		}

		// Add to Cab by compressing OCX
		[ConsoleCommandMethod(
			"Compress a OCX and Generate a Cab file.",
			"GenerateVpnWebOcxCab [src] [/DEST:dest]",
			"Compress a OCX and Generate a Cab file.",
			"[src]:Specify the ocx file.",
			"DEST:Specify the destination cab file.")]
		static int GenerateVpnWebOcxCab(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[src]", ConsoleService.Prompt, "Src Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("DEST", ConsoleService.Prompt, "Dst Filename: ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

#if	!BU_OSS
			string destFileName = vl["DEST"].StrValue;
			string srcFileName = vl.DefaultParam.StrValue;

			Win32BuildUtil.GenerateVpnWebOcxCab(destFileName, srcFileName);
#endif

			return 0;
		}
		

		// Copy the file
		[ConsoleCommandMethod(
			"Copy a File.",
			"FileCopy [src] [/DEST:dest]",
			"Copy a File.",
			"[src]:Specify the source file.",
			"DEST:Specify the destination file.")]
		static int FileCopy(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[src]", ConsoleService.Prompt, "Src Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("DEST", ConsoleService.Prompt, "Dst Filename: ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string destFileName = vl["DEST"].StrValue;
			string srcFileName = vl.DefaultParam.StrValue;

			IO.FileCopy(srcFileName, destFileName, true, false);

			return 0;
		}

		// Sign the file
		[ConsoleCommandMethod(
			"Sign files using Authenticode certificates.",
			"SignCode [filename] [/DEST:destfilename] [/COMMENT:comment] [/KERNEL:yes|no]",
			"Sign files using Authenticode certificates.",
			"[filename]:Specify the target filename.",
			"DEST:Specify the destination filename. If this parameter is not specified, the target file will be overwritten.",
			"COMMENT:Provide a description of the signed content.",
			"KERNEL:Specify \"yes\" if Windows Vista / 7 Kernel Mode Driver Signing is needed."
			)]
		static int SignCode(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[filename]", ConsoleService.Prompt, "Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("DEST"),
				new ConsoleParam("COMMENT", ConsoleService.Prompt, "Comment: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("KERNEL"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string destFileName = vl["DEST"].StrValue;
			string srcFileName = vl.DefaultParam.StrValue;
			if (Str.IsEmptyStr(destFileName))
			{
				destFileName = srcFileName;
			}
			string comment = vl["COMMENT"].StrValue;
			bool kernel = vl["KERNEL"].BoolValue;

			CodeSign.SignFile(destFileName, srcFileName, comment, kernel);

			return 0;
		}
	}
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
