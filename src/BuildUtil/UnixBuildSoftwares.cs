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
	// Build the UNIX software
	public class BuildSoftwareUnix : BuildSoftware
	{
		public readonly string[] SrcDirNameList =
		{
			@"bin\BuiltHamcoreFiles",
			@"bin\hamcore",
			"Cedar",
			"Ham",
			"Mayaqua",
			"Neo",
			"VGate",
			"vpnbridge",
			"vpnclient",
			"vpncmd",
			"vpnserver",
		};

		public readonly string CrossLibName;
		public readonly string CrossLibBaseDir = Path.Combine(Paths.BaseDirName, @"BuildFiles\CrossLib");
		public readonly bool UseGccBitsOption;
		public readonly string CrossCompilerName;
		public readonly bool NoPThreadOption;
		public readonly string CrossCompilerOption;
		public readonly string SrcKitDefaultDir;

		public BuildSoftwareUnix(Software software, int buildNumber, int version, string buildName, Cpu cpu, OS os, 
			string crossLibName, bool useGccBitsOption, string crossCompilerName, bool noPthreadOption, string crossCompilerOption)
			: base(software, buildNumber, version, buildName, cpu, os)
		{
			this.CrossLibName = crossLibName;
			this.UseGccBitsOption = useGccBitsOption;
			this.CrossCompilerName = crossCompilerName;
			this.NoPThreadOption = noPthreadOption;
			this.CrossCompilerOption = crossCompilerOption;

#if !BU_SOFTETHER
			this.SrcKitDefaultDir = Env.SystemDir.Substring(0, 2) + @"\tmp\vpn4_srckit";
#else
			this.SrcKitDefaultDir = Env.SystemDir.Substring(0, 2) + @"\tmp\se_vpn_srckit";
#endif
		}

		// Run the build
		public void Build(bool debugMode)
		{
			string mutexName = "buildsrckit_" + this.CrossLibName;

			Mutex mutex = new Mutex(false, mutexName);

			mutex.WaitOne();

			try
			{
				if (this.BuildSrcKit(SrcKitDefaultDir, debugMode))
				{
					this.BuildWithCrossCompiler(SrcKitDefaultDir);
				}
			}
			finally
			{
				mutex.ReleaseMutex();
			}

			this.Release(SrcKitDefaultDir);
		}

		public override void Build()
		{
			throw new NotImplementedException();
		}

		// Delegate to copy the source code
		public bool CopySrcFilesDelegate(FileInfo info)
		{
			string[] ignoreExts =
			{
				".exe", ".sys", ".dll", ".inf", ".vcproj", ".user",
				".ico", ".rc", 
			};
			string name = info.FullName;

			if (Str.InStr(name, @"\.svn\") ||
				Str.InStr(name, @"\WinPcap\") ||
				Str.InStr(name, @"_Debug\") ||
				Str.InStr(name, @"_Release\") ||
				Str.InStr(name, @"\BuiltHamcoreFiles\win32_"))
			{
				return false;
			}

			foreach (string ext in ignoreExts)
			{
				if (name.EndsWith(ext, StringComparison.InvariantCultureIgnoreCase))
				{
					return false;
				}
			}

			return true;
		}

		// Create a release
		public virtual void Release(string baseOutputDir)
		{
			string srcDir = Path.Combine(baseOutputDir, this.CrossLibName + @"\src");
			string releaseFileName = Path.Combine(Paths.ReleaseDir, this.OutputFileName);
			Con.WriteLine("Generating '{0}'...", releaseFileName);

			List<string> files = new List<string>();
			string gccOptionForLink;
			string gccOptionForCompile;

			generateGccOptions(srcDir, false, false, out gccOptionForLink, out gccOptionForCompile);

			string targetName = this.Software.ToString();

			// Makefile
			StringWriter mk = GenerateMakeFileForRelease(srcDir);
			byte[] mkData = Str.NormalizeCrlf(Str.Utf8Encoding.GetBytes(mk.ToString()), new byte[] { 10 });

			TarPacker tar = new TarPacker();

			tar.AddFileSimple(targetName + @"\Makefile", mkData, 0, mkData.Length, DateTime.Now);

			// Install Script
			string isText = File.ReadAllText(Paths.UnixInstallScript);
			isText = Str.ReplaceStr(isText, "<TITLE>", TitleString, false);
			byte[] scriptData = Str.NormalizeCrlf(Str.Utf8Encoding.GetBytes(isText), new byte[] { 10 });
			tar.AddFileSimple(targetName + @"\.install.sh", scriptData, 0, scriptData.Length, DateTime.Now);

			// EULA
			Encoding enc = Str.Utf8Encoding;

			if (true)
			{
				string srcData = File.ReadAllText(Path.Combine(Paths.BinDirName, @"hamcore\eula.txt"),
					enc);

				byte[] destData = enc.GetBytes(srcData);

				tar.AddFileSimple(targetName + @"\" + "ReadMeFirst_License.txt", destData, 0, destData.Length, DateTime.Now);
			}

			if (true)
			{
				string srcData = File.ReadAllText(Path.Combine(Paths.BinDirName, @"hamcore\authors.txt"),
					enc);

				byte[] destData = enc.GetBytes(srcData);

				tar.AddFileSimple(targetName + @"\" + "Authors.txt", destData, 0, destData.Length, DateTime.Now);
			}

			if (true)
			{
				string srcData = File.ReadAllText(Path.Combine(Paths.BinDirName, @"hamcore\warning_ja.txt"),
					enc);

				byte[] destData = enc.GetBytes(srcData);

				tar.AddFileSimple(targetName + @"\" + "ReadMeFirst_Important_Notices_ja.txt", destData, 0, destData.Length, DateTime.Now);
			}

			if (true)
			{
				string srcData = File.ReadAllText(Path.Combine(Paths.BinDirName, @"hamcore\warning_en.txt"),
					enc);

				byte[] destData = enc.GetBytes(srcData);

				tar.AddFileSimple(targetName + @"\" + "ReadMeFirst_Important_Notices_en.txt", destData, 0, destData.Length, DateTime.Now);
			}

			if (true)
			{
				string srcData = File.ReadAllText(Path.Combine(Paths.BinDirName, @"hamcore\warning_cn.txt"),
					enc);

				byte[] destData = enc.GetBytes(srcData);

				tar.AddFileSimple(targetName + @"\" + "ReadMeFirst_Important_Notices_cn.txt", destData, 0, destData.Length, DateTime.Now);
			}
	

			// Codes
			string[] dirs =
			{
				Path.Combine(srcDir, "code"),
				Path.Combine(srcDir, "lib"),
			};

			foreach (string dir in dirs)
			{
				string[] fileList = Directory.GetFiles(dir, "*.a", SearchOption.TopDirectoryOnly);

				if (Path.GetFileName(dir).Equals("code", StringComparison.InvariantCultureIgnoreCase))
				{
					fileList = new string[]
					{
						Path.Combine(dir, string.Format("{0}.a", this.Software.ToString())),
						Path.Combine(dir, "vpncmd.a"),
					};
				}

				foreach (string fileName in fileList)
				{
					if (Str.StrCmpi(Path.GetFileName(fileName), "libpcap.a") == false)
					{
						// Libpcap.a is not included in the release
						byte[] fileData = File.ReadAllBytes(fileName);

						tar.AddFileSimple(targetName + @"\" + IO.GetRelativeFileName(fileName, srcDir),
							fileData, 0, fileData.Length, DateTime.Now);
					}
				}
			}

			// License file
			byte[] lsFileData = File.ReadAllBytes(Path.Combine(CrossLibBaseDir, @"License.txt"));
			tar.AddFileSimple(targetName + @"\lib\License.txt", lsFileData, 0, lsFileData.Length, DateTime.Now);

			// HamCore
			byte[] hcData = File.ReadAllBytes(Path.Combine(Paths.BaseDirName, string.Format(@"bin\BuiltHamcoreFiles\hamcore_unix\hamcore.se2")));
			tar.AddFileSimple(targetName + @"\hamcore.se2", hcData, 0, hcData.Length, DateTime.Now);

			// Generate a tar
			tar.Finish();
			byte[] tarData = tar.CompressToGZip();

			File.WriteAllBytes(releaseFileName, tarData);

			Con.WriteLine("Finished.");
		}

		// Build by cross-compiler
		public virtual void BuildWithCrossCompiler(string baseOutputDir)
		{
			// Create a batch file
			string outDir = Path.Combine(baseOutputDir, this.CrossLibName);
			string outSrcDir = Path.Combine(outDir, "src");

			try
			{
				string xcDir = Path.Combine(Path.Combine(Paths.CrossCompilerBaseDir, this.CrossCompilerName), "bin");

				if (Directory.Exists(xcDir) == false)
				{
					throw new ApplicationException(string.Format("dir '{0}' not found.", xcDir));
				}

				string batFileName = Path.Combine(outSrcDir, "cross_build.cmd");
				StreamWriter w = new StreamWriter(batFileName, false, Str.ShiftJisEncoding);
				w.WriteLine("SET PATH={0};%PATH%", xcDir);
				w.WriteLine();
				w.WriteLine(outSrcDir.Substring(0, 2));
				w.WriteLine("CD {0}", outSrcDir);
				w.WriteLine();
				w.WriteLine("make clean");
				w.WriteLine("make");
				w.WriteLine();
				w.WriteLine("EXIT /B %ERRORLEVEL%");
				w.Close();

				Semaphore sem = new Semaphore(BuildConfig.NumMultipleCompileTasks, BuildConfig.NumMultipleCompileTasks, "vpn_build_cross");
				Con.WriteLine("Waiting for Semaphore...");
				sem.WaitOne();
				Con.WriteLine("Done.");
				try
				{
					Win32BuildUtil.ExecCommand(Paths.CmdFileName, string.Format("/C \"{0}\"", batFileName));
				}
				finally
				{
					sem.Release();
				}
			}
			catch
			{
				string[] files = Directory.GetFiles(Path.Combine(outSrcDir, "code"), "*.a", SearchOption.AllDirectories);
				foreach (string file in files)
				{
					try
					{
						File.Delete(file);
					}
					catch
					{
					}
				}
			}
		}

		// SrcKit file name
		public string SrcKitFileName
		{
			get
			{
				int build, version;
				string name;
				DateTime date;
				Win32BuildUtil.ReadBuildInfoFromTextFile(out build, out version, out name, out date);
				return string.Format("{0}-{3}-{1}.tar.gz", "srckit", this.CrossLibName,
					Str.DateTimeToStrShort(BuildSoftwareList.ListCreatedDateTime),
					build);
			}
		}

		// Copy the source code
		public virtual void CopyUnixSrc(string baseOutputDir)
		{
			// Generate an Output directory name
			string outDir = baseOutputDir;
			string outSrcDir = baseOutputDir;
			Con.WriteLine("BuildSrcKit for '{0}'...", this.IDString);
			Con.WriteLine("BuildSrcKit Output Dir = '{0}'.", outDir);

			string tsFile = Path.Combine(outDir, "TimeStamp.txt");
			string timeStamp = Str.DateTimeToStrShort(BuildSoftwareList.ListCreatedDateTime);
			Con.WriteLine("timestamp={0}", timeStamp);

			if (Directory.Exists(outDir))
			{
			}
			else
			{
				Directory.CreateDirectory(outDir);
			}

			// Copy the source code
			foreach (string srcDirName in SrcDirNameList)
			{
				string srcFullPath = Path.Combine(Paths.BaseDirName, srcDirName);
				string destFullPath = Path.Combine(outSrcDir, srcDirName);

				IO.CopyDir(srcFullPath, destFullPath, new IO.CopyDirPreCopyDelegate(CopySrcFilesDelegate), false, true, true, true, true);
			}
			IO.FileCopy(Path.Combine(Paths.BaseDirName, "CurrentBuild.txt"), Path.Combine(outSrcDir, "CurrentBuild.txt"), true, false);
		}

		// Build SrcKit
		public virtual bool BuildSrcKit(string baseOutputDir, bool debugMode)
		{
			// Generate an Output directory name
			string outDir = Path.Combine(baseOutputDir, this.CrossLibName);
			string outSrcDir = Path.Combine(outDir, "src");
			Con.WriteLine("BuildSrcKit for '{0}'...", this.IDString);
			Con.WriteLine("CrossLib Name: '{0}'.", this.CrossLibName);
			Con.WriteLine("BuildSrcKit Output Dir = '{0}'.", outDir);

			string tsFile = Path.Combine(outDir, "TimeStamp.txt");
			string timeStamp = Str.DateTimeToStrShort(BuildSoftwareList.ListCreatedDateTime);
			Con.WriteLine("timestamp={0}", timeStamp);

			if (Directory.Exists(outDir))
			{
				bool ok = false;
				// See TimeStamp.txt file if the directory already exists
				try
				{
					string[] ts = File.ReadAllLines(tsFile);
					if (ts[0] == timeStamp)
					{
						ok = true;
					}
				}
				catch
				{
				}

				if (ok)
				{
					Con.WriteLine("Skipped for '{0}'.", this.IDString);
					return false;
				}
			}
			else
			{
				Directory.CreateDirectory(outDir);
			}

			// Copy the source code
			foreach (string srcDirName in SrcDirNameList)
			{
				string srcFullPath = Path.Combine(Paths.BaseDirName, srcDirName);
				string destFullPath = Path.Combine(outSrcDir, srcDirName);
				bool delete_bom = true;

				if (Str.InStr(srcDirName, "\\hamcore"))
				{
					delete_bom = false;
				}

				IO.CopyDir(srcFullPath, destFullPath, new IO.CopyDirPreCopyDelegate(CopySrcFilesDelegate), false, true, true, delete_bom);
			}
			IO.FileCopy(Path.Combine(Paths.BaseDirName, "CurrentBuild.txt"), Path.Combine(outSrcDir, "CurrentBuild.txt"), true, false);
			IO.FileCopy(Path.Combine(Paths.BaseDirName, "GlobalConst.h"), Path.Combine(outSrcDir, "GlobalConst.h"), true, false);
			IO.FileCopy(Path.Combine(Paths.BaseDirName, @"DebugFiles\Replace.h"), Path.Combine(outSrcDir, "Replace.h"), true, false);
			IO.FileCopy(Path.Combine(Paths.BaseDirName, @"bin\BuiltHamcoreFiles\hamcore_unix\hamcore.se2"),
				Path.Combine(outSrcDir, @"bin\hamcore.se2"), true, false);

			// Copy Crosslibs
			IO.CopyDir(Path.Combine(this.CrossLibBaseDir, this.CrossLibName), Path.Combine(outSrcDir, @"lib"),
				delegate(FileInfo fi)
				{
					if (fi.DirectoryName.IndexOf(@".svn", StringComparison.InvariantCultureIgnoreCase) != -1)
					{
						return false;
					}
					return true;
				}, false, true, true, false);

			// Generate Makefile for compilation
			byte[] makeFileDataForCross = Str.NormalizeCrlf(Str.Utf8Encoding.GetBytes(GenerateMakeFileForCompile(outSrcDir, debugMode, true).ToString()), new byte[] { 10, });
			byte[] makeFileDataForSelf = Str.NormalizeCrlf(Str.Utf8Encoding.GetBytes(GenerateMakeFileForCompile(outSrcDir, debugMode, false).ToString()), new byte[] { 10, });

			string makeFileName = Path.Combine(outSrcDir, "Makefile");
			File.WriteAllBytes(makeFileName, makeFileDataForCross);

			// TimeStamp.txt
			File.WriteAllText(tsFile, timeStamp);

			// Create a tar.gz
			string tarGzFileName = Path.Combine(outSrcDir, this.SrcKitFileName);
			Con.WriteLine("Creating '{0}'...", tarGzFileName);
			List<string> files = new List<string>();

			foreach (string srcDirName in Util.CombineArray<string>(SrcDirNameList, new string[] { "lib" }))
			{
				string dirFullPath = Path.Combine(outSrcDir, srcDirName);
				string[] fileList = Directory.GetFiles(dirFullPath, "*",
					srcDirName.Equals("lib", StringComparison.InvariantCultureIgnoreCase) ? SearchOption.TopDirectoryOnly : SearchOption.AllDirectories);
				foreach (string fileName in fileList)
				{
					files.Add(fileName);
				}
			}
			files.Add(Path.Combine(outSrcDir, @"CurrentBuild.txt"));
			files.Add(Path.Combine(outSrcDir, @"bin\hamcore.se2"));
			files.Add(Path.Combine(outSrcDir, @"Replace.h"));
			files.Add(Path.Combine(outSrcDir, @"GlobalConst.h"));

			files.Sort();
			TarPacker tar = new TarPacker();
			foreach (string file in files)
			{
				byte[] fileData = File.ReadAllBytes(file);
				tar.AddFileSimple(@"src\" + IO.GetRelativeFileName(file, outSrcDir),
					fileData,
                    0, fileData.Length, File.GetLastWriteTime(file), "0000750", "0000640");
			}
            tar.AddFileSimple(@"src\Makefile", makeFileDataForSelf, 0, makeFileDataForSelf.Length, DateTime.Now, "0000750", "0000640");
			tar.Finish();
			byte[] tarGzData = tar.CompressToGZip();
			File.WriteAllBytes(tarGzFileName, tarGzData);

			IO.MakeDir(Paths.ReleaseSrckitDir);
			File.WriteAllBytes(Path.Combine(Paths.ReleaseSrckitDir, this.SrcKitFileName), tarGzData);

			Con.WriteLine("Completed.");

			return true;
		}

		// Compilation settings
		public string Compiler = "gcc";
		public List<string> GccMacros = new List<string>();

		// Create a Makefile for release
		public virtual StringWriter GenerateMakeFileForRelease(string srcDir)
		{
			string gccOptionForLink;
			string gccOptionForCompile;

			generateGccOptions(srcDir, false, false, out gccOptionForLink, out gccOptionForCompile);

			string codeDir = Path.Combine(srcDir, "code");
			string libDir = Path.Combine(srcDir, "lib");

			string[] codeFiles = Directory.GetFiles(codeDir, "*.a");
			string[] libFiles = Directory.GetFiles(libDir, "*.a");

			StringWriter sr = new StringWriter();
			sr.WriteLine("# {0}", this.TitleString);
			sr.WriteLine("# Makefile");
			sr.WriteLine("# ");

#if !BU_SOFTETHER
			sr.WriteLine("# Copyright (c) SoftEther Corporation. All Rights Reserved.");
#else
			sr.WriteLine("# Copyright (c) SoftEther VPN Project at University of Tsukuba, Japan. All Rights Reserved.");
#endif
			sr.WriteLine("# Platform: {0}", this.CrossLibName);
			sr.WriteLine();
			sr.WriteLine("CC={0}", this.Compiler);
			sr.WriteLine("OPTIONS={0}", gccOptionForLink);
			sr.WriteLine();
			sr.WriteLine("default:");
			sr.WriteLine("\t@./.install.sh");
			sr.WriteLine();
			sr.WriteLine("# NOTE:");
			sr.WriteLine("# You have to read and agree the license agreement at the same directory");
			sr.WriteLine("#  before using this software.");
			sr.WriteLine();
			sr.WriteLine("i_read_and_agree_the_license_agreement:");

			sr.WriteLine("\t@echo \"Preparing {0}...\"", BuildHelper.GetSoftwareTitle(this.Software));

			foreach (string filename in libFiles)
			{
				sr.WriteLine("\t-ranlib lib/{0}", Path.GetFileName(filename));
			}

			sr.WriteLine("\t-ranlib code/{0}.a", this.Software.ToString());
			sr.WriteLine("\t$(CC) code/{0}.a $(OPTIONS) -o {0}", this.Software.ToString());

			sr.WriteLine("\t-ranlib code/{0}.a", "vpncmd");
			sr.WriteLine("\t$(CC) code/{0}.a $(OPTIONS) -o {0}", "vpncmd");

			if (this.Software == Software.vpnserver_vpnbridge || this.Software == Software.vpnbridge || this.Software == Software.vpnserver)
			{
				sr.WriteLine("\t./vpncmd /tool /cmd:Check");
			}

			Language[] langs = BuildHelper.GetLanguageList();

			sr.WriteLine("\t@echo");
			sr.WriteLine("\t@echo \"--------------------------------------------------------------------\"");
			sr.WriteLine("\t@echo \"The preparation of {0} is completed !\"", BuildHelper.GetSoftwareTitle(this.Software));
			sr.WriteLine("\t@echo");
			sr.WriteLine("\t@echo");
			sr.WriteLine("\t@echo \"*** How to switch the display language of the {0} Service ***\"", BuildHelper.GetSoftwareTitle(this.Software));
			sr.WriteLine("\t@echo \"{0} supports the following languages:\"", BuildHelper.GetSoftwareTitle(this.Software));

			foreach (Language lang in langs)
			{
				sr.WriteLine("\t@echo \"  - {0}\"", lang.Title);
			}

			sr.WriteLine("\t@echo");
			sr.WriteLine("\t@echo \"You can choose your prefered language of {0} at any time.\"", BuildHelper.GetSoftwareTitle(this.Software));
			sr.WriteLine("\t@echo \"To switch the current language, open and edit the 'lang.config' file.\"");

			sr.WriteLine("\t@echo");
			sr.WriteLine("\t@echo");

			sr.WriteLine("\t@echo \"*** How to start the {0} Service ***\"", BuildHelper.GetSoftwareTitle(this.Software));
			sr.WriteLine("\t@echo");

			sr.WriteLine("\t@echo \"Please execute './{0} start' to run the {1} Background Service.\"", this.Software.ToString(), BuildHelper.GetSoftwareTitle(this.Software));
#if !BU_SOFTETHER
			sr.WriteLine("\t@echo \"And please execute './vpncmd' to run the PacketiX VPN Command-Line Utility to configure {0}.\"", BuildHelper.GetSoftwareTitle(this.Software));
#else
			sr.WriteLine("\t@echo \"And please execute './vpncmd' to run the SoftEther VPN Command-Line Utility to configure {0}.\"", BuildHelper.GetSoftwareTitle(this.Software));
#endif
			sr.WriteLine("\t@echo \"Of course, you can use the VPN Server Manager GUI Application for Windows on the other Windows PC in order to configure the {0} remotely.\"", BuildHelper.GetSoftwareTitle(this.Software));

			sr.WriteLine("\t@echo \"--------------------------------------------------------------------\"");
			sr.WriteLine("\t@echo");

			sr.WriteLine();

			sr.WriteLine("clean:");
			sr.WriteLine("\trm -f {0}", this.Software.ToString());
			sr.WriteLine("\trm -f {0}", "vpncmd");
			sr.WriteLine();

			return sr;
		}

		// Generate Makefile for compilation
		public virtual StringWriter GenerateMakeFileForCompile(string outDir, bool debugMode, bool crossCompile)
		{
			string[] programNames =
			{
				"Ham",
				"vpnserver",
				"vpnbridge",
				"vpnclient",
				"vpncmd",
			};

			string gccOptionForLinkDebug, gccOptionForLinkRelease;
			string gccOptionForCompileDebug, gccOptionForCompileRelease;

			generateGccOptions(outDir, false, crossCompile, out gccOptionForLinkRelease, out gccOptionForCompileRelease);
			generateGccOptions(outDir, true, crossCompile, out gccOptionForLinkDebug, out gccOptionForCompileDebug);

			StringWriter sr = new StringWriter();
#if !BU_SOFTETHER
			sr.WriteLine("# PacketiX VPN Source Code");
			sr.WriteLine("# Copyright (c) SoftEther Corporation. All Rights Reserved.");
#else
			sr.WriteLine("# SoftEther VPN Source Code");
			sr.WriteLine("# Copyright (c) SoftEther VPN Project at University of Tsukuba, Japan. All Rights Reserved.");
#endif
			sr.WriteLine("# Platform: {0}", this.CrossLibName);
			sr.WriteLine();

			// Variable declaration
			sr.WriteLine("# Variables");
			sr.WriteLine("CC={0}", this.Compiler);
			sr.WriteLine();
			sr.WriteLine("OPTIONS_COMPILE_DEBUG={0}", gccOptionForCompileDebug);
			sr.WriteLine();
			sr.WriteLine("OPTIONS_LINK_DEBUG={0}", gccOptionForLinkDebug);
			sr.WriteLine();
			sr.WriteLine("OPTIONS_COMPILE_RELEASE={0}", gccOptionForCompileRelease);
			sr.WriteLine();
			sr.WriteLine("OPTIONS_LINK_RELEASE={0}", gccOptionForLinkRelease);
			sr.WriteLine();
			sr.WriteLine("ifeq ($(DEBUG),YES)");
			sr.WriteLine("\tOPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)");
			sr.WriteLine("\tOPTIONS_LINK=$(OPTIONS_LINK_DEBUG)");
			sr.WriteLine("else");
			sr.WriteLine("\tOPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)");
			sr.WriteLine("\tOPTIONS_LINK=$(OPTIONS_LINK_RELEASE)");
			sr.WriteLine("endif");
			sr.WriteLine();

			string[] mayaquaHeaders = generateFileList(Path.Combine(outDir, "Mayaqua"), outDir, "*.h");
			string[] cedarHeaders = generateFileList(Path.Combine(outDir, "Cedar"), outDir, "*.h");
			string[] mayaquaSrcs = generateFileList(Path.Combine(outDir, "Mayaqua"), outDir, "*.c");
			string[] cedarSrcs = generateFileList(Path.Combine(outDir, "Cedar"), outDir, "*.c");
			List<string> mayaquaObjs = new List<string>();
			List<string> cedarObjs = new List<string>();
			List<string> progSrcs = new List<string>();
			List<string> progObjs = new List<string>();
			List<string> progAs = new List<string>();
			List<string> progBins = new List<string>();

			foreach (string progName in programNames)
			{
				string progName2 = progName;

				if (progName2.Equals("vpnclient", StringComparison.InvariantCultureIgnoreCase) == false)
				{
					progSrcs.Add(string.Format("{0}/{0}.c", progName2));
				}
				else
				{
					progSrcs.Add(string.Format("{0}/vpncsvc.c", progName2));
				}
				progObjs.Add(string.Format("object/{0}.o", progName2));
				progAs.Add(string.Format("code/{0}.a", progName));
				progBins.Add(string.Format("bin/{0}", progName.ToLower()));
			}

			int i;
			for (i = 0; i < mayaquaSrcs.Length; i++)
			{
				mayaquaObjs.Add(string.Format("object/Mayaqua/{0}.o", Path.GetFileNameWithoutExtension(mayaquaSrcs[i])));
			}
			for (i = 0; i < cedarSrcs.Length; i++)
			{
				cedarObjs.Add(string.Format("object/Cedar/{0}.o", Path.GetFileNameWithoutExtension(cedarSrcs[i])));
			}
			sr.WriteLine("# Files");
			sr.WriteLine("HEADERS_MAYAQUA={0}", Str.CombineStringArray(mayaquaHeaders, " "));
			sr.WriteLine("HEADERS_CEDAR={0}", Str.CombineStringArray(cedarHeaders, " "));
			sr.WriteLine("OBJECTS_MAYAQUA={0}", Str.CombineStringArray(mayaquaObjs.ToArray(), " "));
			sr.WriteLine("OBJECTS_CEDAR={0}", Str.CombineStringArray(cedarObjs.ToArray(), " "));
			sr.WriteLine();

			// Behavior
			sr.WriteLine("# Build Action");
			sr.WriteLine("default:\tbuild");
			sr.WriteLine();
			sr.WriteLine("build:\t$(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) {0}", Str.CombineStringArray(progBins.ToArray(), " "));
			sr.WriteLine();

			sr.WriteLine("# Mayaqua Kernel Code");
			for (i = 0; i < mayaquaSrcs.Length; i++)
			{
				sr.WriteLine("{0}: {1} $(HEADERS_MAYAQUA)", mayaquaObjs[i], mayaquaSrcs[i]);
				if (i == 0)
				{
					sr.WriteLine("\t@mkdir -p object/");
					sr.WriteLine("\t@mkdir -p object/Mayaqua/");
					sr.WriteLine("\t@mkdir -p object/Cedar/");
					sr.WriteLine("\t@mkdir -p code/");
				}
				sr.WriteLine("\t$(CC) $(OPTIONS_COMPILE) -c {0} -o {1}", mayaquaSrcs[i], mayaquaObjs[i]);
				sr.WriteLine();
			}

			sr.WriteLine("# Cedar Communication Module Code");
			for (i = 0; i < cedarSrcs.Length; i++)
			{
				string line = string.Format("{0}: {1} $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)", cedarObjs[i], cedarSrcs[i]);
				if (cedarSrcs[i].EndsWith("Bridge.c", StringComparison.InvariantCultureIgnoreCase))
				{
					line += " Cedar/BridgeUnix.c";
				}
				sr.WriteLine(line);
				sr.WriteLine("\t$(CC) $(OPTIONS_COMPILE) -c {0} -o {1}", cedarSrcs[i], cedarObjs[i]);
				sr.WriteLine();
			}

			for (i = 0; i < programNames.Length; i++)
			{
				sr.WriteLine("# {0}", programNames[i]);
				sr.WriteLine("{0}: {1} $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)",
					progBins[i], progAs[i]);
				sr.WriteLine("\t$(CC) {0} $(OPTIONS_LINK) -o {1}", progAs[i], progBins[i]);
				sr.WriteLine();
				sr.WriteLine("{0}: {1} $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)",
					progAs[i], progObjs[i]);
				sr.WriteLine("\trm -f {0}", progAs[i]);
				sr.WriteLine("\tar r {0} $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) {1}", progAs[i], progObjs[i]);
				sr.WriteLine("\tranlib {0}", progAs[i]);
				sr.WriteLine();
				sr.WriteLine("{0}: {1} $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)",
					progObjs[i], progSrcs[i]);
				sr.WriteLine("\t$(CC) $(OPTIONS_COMPILE) -c {0} -o {1}", progSrcs[i], progObjs[i]);
				sr.WriteLine();
			}

			sr.WriteLine("# Clean");
			sr.WriteLine("clean:");
			sr.WriteLine("\t-rm -f $(OBJECTS_MAYAQUA)");
			sr.WriteLine("\t-rm -f $(OBJECTS_CEDAR)");
			for (i = 0; i < programNames.Length; i++)
			{
				sr.WriteLine("\t-rm -f {0}", progObjs[i]);
				sr.WriteLine("\t-rm -f {0}", progAs[i]);
				sr.WriteLine("\t-rm -f {0}", progBins[i]);
			}
			sr.WriteLine();

			sr.WriteLine("# Help Strings");
			sr.WriteLine("help:");
			sr.WriteLine("\t@echo \"make [DEBUG=YES]\"");
			sr.WriteLine();

			return sr;
		}

		// Create a file list
		string[] generateFileList(string dir, string baseDir, string searchPattern)
		{
			string[] files = Directory.GetFiles(dir, searchPattern, SearchOption.AllDirectories);
			List<string> ret = new List<string>();

			foreach (string file in files)
			{
				string name = IO.GetRelativeFileName(file, baseDir).Replace(@"\", "/");
				ret.Add(name);
			}

			ret.Sort();

			return ret.ToArray();
		}

		// Generate the GCC option string
		void generateGccOptions(string outDir, bool debugMode, bool crossCompile, out string gccOptionForLink, out string gccOptionForCompile)
		{
			List<string> macros = new List<string>(this.GccMacros.ToArray());
			List<string> includes = new List<string>();
			List<string> options = new List<string>();
			List<string> libs = new List<string>();

			// Determine the macro
			if (debugMode)
			{
				macros.Add("_DEBUG");
				macros.Add("DEBUG");
			}
			else
			{
				macros.Add("NDEBUG");
				macros.Add("VPN_SPEED");
				macros.Add("MAYAQUA_REPLACE");
			}

			macros.Add("UNIX");
			macros.Add("_REENTRANT");
			macros.Add("REENTRANT");
			macros.Add("_THREAD_SAFE");
			macros.Add("_THREADSAFE");
			macros.Add("THREAD_SAFE");
			macros.Add("THREADSAFE");
			macros.Add("_FILE_OFFSET_BITS=64");

			// Decide the include directory
			includes.Add("./");
			includes.Add("./Cedar/");
			includes.Add("./Mayaqua/");

			// Determine options
			if (debugMode)
			{
				options.Add("-g");
			}
			else
			{
				options.Add("-O2");
			}
			options.Add("-fsigned-char");
			if (this.NoPThreadOption == false)
			{
				options.Add("-pthread");
			}
			if (this.UseGccBitsOption)
			{
				if (this.Cpu.Bits == CPUBits.Bits32)
				{
					options.Add("-m32");
				}
				else
				{
					options.Add("-m64");
				}
			}

			// Determine library files
			string[] libNames =
			{
				"libssl",
				"libcrypto",
				"libiconv",
				"libcharset",
				"libedit",
				"libncurses",
				"libz",
			};
			foreach (string libName in libNames)
			{
				libs.Add(string.Format("lib/{0}.a", libName));
			}

			if (crossCompile)
			{
				if (this.Os == OSList.MacOS)
				{
					// Include libpcap.a only when cross-compiling for Mac OS X
					libs.Add(string.Format("lib/{0}.a", "libpcap"));
				}
			}

			if (this.Os == OSList.Linux)
			{
				if (this.Cpu == CpuList.x86 || this.Cpu == CpuList.x64)
				{
					// Include libintelaes.a only for x86 / x64 in Linux
					libs.Add(string.Format("lib/{0}.a", "libintelaes"));
				}
			}

			gccOptionForCompile = MakeGccOptions(macros.ToArray(), includes.ToArray(), options.ToArray(), null);

			if (crossCompile)
			{
				if (Str.IsEmptyStr(this.CrossCompilerOption) == false)
				{
					options.Add(this.CrossCompilerOption);
				}
			}

			options.Add("-lm");

			if (this.Os == OSList.Solaris)
			{
				options.Add("-lrt");
				options.Add("-lnsl");
				options.Add("-lsocket");
				options.Add("-ldl");
			}
			else if (this.Os == OSList.Linux)
			{
				options.Add("-ldl");
				options.Add("-lrt");
			}
			else if (this.Os == OSList.MacOS)
			{
				if (crossCompile == false)
				{
					// Include -lpcap for the user environment on Mac OS X
					options.Add("-lpcap");
				}
			}

			if (this.Cpu == CpuList.armeabi)
			{
				// Prevent to show a warning on linking in EABI binaries
				// to EABIHF architecture in ARM
				options.Add("-Wl,--no-warn-mismatch");
			}

			options.Add("-lpthread");

			gccOptionForLink = MakeGccOptions(new string[0], new string[0], options.ToArray(), libs.ToArray());
		}

		public static string MakeGccOptions(string[] macros, string[] includeDirs, string[] options, string[] libs)
		{
			List<string> o = new List<string>();
			foreach (string macro in macros)
			{
				o.Add(string.Format("-D{0}", macro));
			}
			foreach (string dir in includeDirs)
			{
				o.Add(string.Format("-I{0}", dir));
			}
			foreach (string opt in options)
			{
				o.Add(opt);
			}
			if (libs != null)
			{
				o.Add("-L./");
				foreach (string lib in libs)
				{
					o.Add(lib);
				}
			}

			return Str.CombineStringArray(o.ToArray(), " ");
		}
	}
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
