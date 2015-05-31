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
	// Build utility for Win32
	public static class Win32BuildUtil
	{
		// Generate vpnweb.ocx
		public static void GenerateVpnWebOcxCab(string dstFileName, string ocxFileName)
		{
			int build, version;
			string name;
			DateTime date;
			ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			string cabVer = string.Format("{0},{1},0,{2}", version / 100, version % 100, build);
			string cabFileName = IO.CreateTempFileNameByExt(".cab");
			Mutex m = new Mutex(false, "cabtmp_mutex");

			m.WaitOne();

			try
			{
				// Building the cab
				string cabTmpDir = Path.Combine(Paths.TmpDirName, "cabtmp");

				IO.MakeDir(cabTmpDir);
				IO.DeleteFilesAndSubDirsInDir(cabTmpDir);

				File.Copy(Path.Combine(Paths.BinDirName, ocxFileName), Path.Combine(cabTmpDir, "vpnweb.ocx"));

				string infText = File.ReadAllText(Path.Combine(Path.Combine(Paths.BaseDirName, @"BuildFiles\OcxCabInf"), "vpnweb.inf"));
				infText = Str.ReplaceStr(infText, "$CAB_VERSION$", cabVer);
				File.WriteAllText(Path.Combine(cabTmpDir, "vpnweb.inf"), infText);

				Win32BuildUtil.ExecCommand(Path.Combine(Paths.BaseDirName, @"BuildFiles\Utility\cabarc.exe"),
					string.Format(@"-s 6144 n {0}\vpnweb.cab {0}\vpnweb.ocx {0}\vpnweb.inf", cabTmpDir));

				File.Copy(Path.Combine(cabTmpDir, "vpnweb.cab"), cabFileName, true);
			}
			finally
			{
				m.ReleaseMutex();
			}

			CodeSign.SignFile(cabFileName, cabFileName, "VPN Software", false);

			File.Copy(cabFileName, dstFileName, true);
		}

		// Generate a version information resource
		public static void GenerateVersionInfoResource(string targetExeName, string outName, string rc_name, string product_name)
		{
			int build, version;
			string name;
			DateTime date;
			ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			if (Str.IsEmptyStr(rc_name))
			{
				rc_name = "ver.rc";
			}

			string templateFileName = Path.Combine(Paths.BaseDirName, @"BuildFiles\VerScript\" + rc_name);
			string body = Str.ReadTextFile(templateFileName);

			string exeFileName = Path.GetFileName(targetExeName);
			string internalName = Path.GetFileNameWithoutExtension(exeFileName);

			if (Str.IsEmptyStr(product_name) == false)
			{
				body = Str.ReplaceStr(body, "$PRODUCTNAME$", product_name);
			}
			else
			{
#if !BU_SOFTETHER
				body = Str.ReplaceStr(body, "$PRODUCTNAME$", "PacketiX VPN");
#else		
				body = Str.ReplaceStr(body, "$PRODUCTNAME$", "SoftEther VPN");
#endif
			}
			body = Str.ReplaceStr(body, "$INTERNALNAME$", internalName);
			body = Str.ReplaceStr(body, "$YEAR$", date.Year.ToString());
			body = Str.ReplaceStr(body, "$FILENAME$", exeFileName);
			body = Str.ReplaceStr(body, "$VER_MAJOR$", (version / 100).ToString());
			body = Str.ReplaceStr(body, "$VER_MINOR$", (version % 100).ToString());
			body = Str.ReplaceStr(body, "$VER_BUILD$", build.ToString());

			IO f = IO.CreateTempFileByExt(".rc");
			string filename = f.Name;

			f.Write(Str.AsciiEncoding.GetBytes(body));

			f.Close();

			ExecCommand(Paths.RcFilename, "\"" + filename + "\"");

			string rcDir = Path.GetDirectoryName(filename);
			string rcFilename = Path.GetFileName(filename);
			string rcFilename2 = Path.GetFileNameWithoutExtension(rcFilename);

			string resFilename = Path.Combine(rcDir, rcFilename2) + ".res";

			IO.MakeDirIfNotExists(Path.GetDirectoryName(outName));

			IO.FileCopy(resFilename, outName, true, false);
		}

		// Flush to disk
		public static void Flush()
		{
			string txt = IO.CreateTempFileNameByExt(".txt");
			byte[] ret = Secure.Rand(64);

			FileStream f = File.Create(txt);

			f.Write(ret, 0, ret.Length);

			f.Flush();

			f.Close();

			File.Delete(txt);
		}

		// Increment the build number
		public static void IncrementBuildNumber()
		{
			int build, version;
			string name;
			DateTime date;

			ReadBuildInfoFromTextFile(out build, out version, out name, out date);
			build++;

			WriteBuildInfoToTextFile(build, version, name, date);

			SetNowDate();

			Con.WriteLine("New build number: {0}", build);
		}

		// Set the date and time
		public static void SetNowDate()
		{
			int build, version;
			string name;
			DateTime date;

			ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			date = DateTime.Now;

			WriteBuildInfoToTextFile(build, version, name, date);
		}

		// Write the build number and the version number in the text file
		public static void WriteBuildInfoToTextFile(int build, int version, string name, DateTime date)
		{
			string filename = Path.Combine(Paths.BaseDirName, "CurrentBuild.txt");

			WriteBuildInfoToTextFile(build, version, name, date, filename);
		}
		public static void WriteBuildInfoToTextFile(int build, int version, string name, DateTime date, string filename)
		{
			using (StreamWriter w = new StreamWriter(filename))
			{
				w.WriteLine("BUILD_NUMBER {0}", build);
				w.WriteLine("VERSION {0}", version);
				w.WriteLine("BUILD_NAME {0}", name);
				w.WriteLine("BUILD_DATE {0}", Str.DateTimeToStrShort(date));

				w.Flush();
				w.Close();
			}
		}

		// Read the build number and the version number from a text file
		public static void ReadBuildInfoFromTextFile(out int build, out int version, out string name, out DateTime date)
		{
			string filename = Path.Combine(Paths.BaseDirName, "CurrentBuild.txt");

			ReadBuildInfoFromTextFile(out build, out version, out name, out date, filename);
		}
		public static void ReadBuildInfoFromTextFile(out int build, out int version, out string name, out DateTime date, string filename)
		{
			char[] seps = { '\t', ' ', };
			name = "";
			date = new DateTime(0);

			using (StreamReader r = new StreamReader(filename))
			{
				build = version = 0;

				while (true)
				{
					string line = r.ReadLine();
					if (line == null)
					{
						break;
					}

					string[] tokens = line.Split(seps, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Length == 2)
					{
						if (tokens[0].Equals("BUILD_NUMBER", StringComparison.InvariantCultureIgnoreCase))
						{
							build = int.Parse(tokens[1]);
						}

						if (tokens[0].Equals("VERSION", StringComparison.InvariantCultureIgnoreCase))
						{
							version = int.Parse(tokens[1]);
						}

						if (tokens[0].Equals("BUILD_NAME", StringComparison.InvariantCultureIgnoreCase))
						{
							name = tokens[1];

							name = Str.ReplaceStr(name, "-", "_");
						}

						if (tokens[0].Equals("BUILD_DATE", StringComparison.InvariantCultureIgnoreCase))
						{
							date = Str.StrToDateTime(tokens[1]);
						}
					}
				}

				r.Close();

				if (build == 0 || version == 0 || Str.IsEmptyStr(name) || date.Ticks == 0)
				{
					throw new ApplicationException(string.Format("Wrong file data: '{0}'", filename));
				}
			}
		}

		// Normalize the build information
		public static void NormalizeBuildInfo()
		{
			SetNowDate();

			int build, version;
			string name;
			DateTime date;
			ReadBuildInfoFromTextFile(out build, out version, out name, out date);
			string username = Env.UserName;
			string pcname = Env.MachineName;

			NormalizeSourceCode(build, version, username, pcname, date);
		}

		// Apply build number, version number, user name, and PC name to the source code
		public static void NormalizeSourceCode(int buildNumber, int version, string userName, string pcName, DateTime date)
		{
			DateTime now = date;
			char[] seps = { '\t', ' ', };

			int i = pcName.IndexOf(".");
			if (i != -1)
			{
				pcName = pcName.Substring(0, i);
			}

			userName = userName.ToLower();
			pcName = pcName.ToLower();

			string[] files = Util.CombineArray<string>(
				Directory.GetFiles(Paths.BaseDirName, "*.h", SearchOption.AllDirectories));

			foreach (string file in files)
			{
				string dir = Path.GetDirectoryName(file);
				if (Str.InStr(dir, @"\.svn\") == false &&
					Str.InStr(IO.GetRelativeFileName(file, Paths.BaseDirName), @"tmp\") == false)
				{
					byte[] srcData = File.ReadAllBytes(file);

					int bomSize;
					Encoding enc = Str.GetEncoding(srcData, out bomSize);
					if (enc == null)
					{
						enc = Str.Utf8Encoding;
					}
					StringReader r = new StringReader(enc.GetString(Util.ExtractByteArray(srcData, bomSize, srcData.Length - bomSize)));
					StringWriter w = new StringWriter();
					bool somethingChanged = false;

					while (true)
					{
						string line = r.ReadLine();
						if (line == null)
						{
							break;
						}
						string newLine = null;

						string[] tokens = line.Split(seps, StringSplitOptions.RemoveEmptyEntries);

						if (tokens.Length >= 1)
						{
							if (file.EndsWith(".h", StringComparison.InvariantCultureIgnoreCase))
							{
								if (tokens.Length == 3)
								{
									// Build number portion of the source code
									if (tokens[0].Equals("//") && tokens[1].Equals("Build") && Str.IsNumber(tokens[2]))
									{
										newLine = line.Replace(tokens[2], buildNumber.ToString());
									}
								}
							}

							if (file.EndsWith(".h", StringComparison.InvariantCultureIgnoreCase))
							{
								if (tokens.Length == 3)
								{
									// String part of the version information of Cedar.h
									if (tokens[0].Equals("#define") && tokens[1].Equals("CEDAR_BUILD"))
									{
										newLine = line.Replace(tokens[2], buildNumber.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("CEDAR_VER"))
									{
										newLine = line.Replace(tokens[2], version.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILDER_NAME"))
									{
										newLine = line.Replace(tokens[2], "\"" + userName + "\"");
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_PLACE"))
									{
										newLine = line.Replace(tokens[2], "\"" + pcName + "\"");
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_Y"))
									{
										newLine = line.Replace(tokens[2], date.Year.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_M"))
									{
										newLine = line.Replace(tokens[2], date.Month.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_D"))
									{
										newLine = line.Replace(tokens[2], date.Day.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_HO"))
									{
										newLine = line.Replace(tokens[2], date.Hour.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_MI"))
									{
										newLine = line.Replace(tokens[2], date.Minute.ToString());
									}

									if (tokens[0].Equals("#define") && tokens[1].Equals("BUILD_DATE_SE"))
									{
										newLine = line.Replace(tokens[2], date.Second.ToString());
									}
								}

								if (tokens.Length >= 3)
								{
									if (tokens[0].Equals("#define") && tokens[1].Equals("SUPPORTED_WINDOWS_LIST"))
									{
										newLine = "#define\tSUPPORTED_WINDOWS_LIST\t\t\"" + OSList.Windows.OSSimpleList + "\"";
									}
								}
							}
						}

						if (newLine == null || newLine == line)
						{
							w.WriteLine(line);
						}
						else
						{
							w.WriteLine(newLine);

							somethingChanged = true;
						}
					}

					if (somethingChanged)
					{
						byte[] retData = Str.ConvertEncoding(Str.Utf8Encoding.GetBytes(w.ToString()), enc, bomSize != 0);

						File.WriteAllBytes(file, retData);

						Con.WriteLine("Modified: '{0}'.", file);
					}
				}
			}
		}

		// Get the DebugSnapshot directory name
		public static string GetDebugSnapstotDirName()
		{
			return Path.Combine(Paths.DebugSnapshotBaseDir, Str.DateTimeToStrShort(BuildSoftwareList.ListCreatedDateTime));
		}

		// Copy DebugSnapshot
		public static void CopyDebugSnapshot()
		{
			string snapDir = GetDebugSnapstotDirName();

			CopyDebugSnapshot(snapDir);
		}
		public static void CopyDebugSnapshot(string snapDir, params string[] exclude_exts)
		{
			IO.CopyDir(Paths.BaseDirName, Path.Combine(snapDir, "Main"),
				delegate(FileInfo fi)
				{
					string srcPath = fi.FullName;
					string[] exts_default =
					{
						".ncb", ".aps", ".suo", ".old", ".scc", ".vssscc", ".vspscc", ".cache", ".psess", ".tmp", ".dmp",
					};

					List<string> exts = new List<string>();

					foreach (string ext in exts_default)
					{
						exts.Add(ext);
					}

					foreach (string ext in exclude_exts)
					{
						exts.Add(ext);
					}

					if (Str.InStr(srcPath, @"\.svn\", false))
					{
						return false;
					}

					if (Str.InStr(srcPath.Substring(3), @"\tmp\", false))
					{
						return false;
					}

					if (Str.InStr(srcPath, @"_log\", false))
					{
						return false;
					}

					if (Str.InStr(srcPath, @"\backup.vpn_", false))
					{
						return false;
					}

					foreach (string ext in exts)
					{
						if (srcPath.EndsWith(ext, StringComparison.InvariantCultureIgnoreCase))
						{
							return false;
						}
					}

					if (Str.InStr(srcPath, @"\hamcore\", false))
					{
						return true;
					}

					if (Str.InStr(srcPath, @"\hamcore_", false))
					{
						return true;
					}

					return true;
				},
				false, true, false, false);
		}

		// Execute building in Visual Studio
		public static void BuildMain()
		{
			Mutex x = new Mutex(false, "VpnBuilderWin32_BuildMain");

			x.WaitOne();

			try
			{
				// Generate the contents of the batch file
				string batFileName = Path.Combine(Paths.TmpDirName, "vc_build.cmd");
				StreamWriter bat = new StreamWriter(batFileName, false, Str.ShiftJisEncoding);
				bat.WriteLine("call \"{0}\"", Paths.VisualStudioVCBatchFileName);
				bat.WriteLine("echo on");
				bat.WriteLine("\"{0}\" /toolsversion:3.5 /verbosity:detailed /target:Clean /property:Configuration=Release /property:Platform=Win32 \"{1}\"",
					Paths.MSBuildFileName, Paths.VPN4SolutionFileName);
				bat.WriteLine("IF ERRORLEVEL 1 GOTO LABEL_ERROR");

				bat.WriteLine("\"{0}\" /toolsversion:3.5 /verbosity:detailed /target:Clean /property:Configuration=Release /property:Platform=x64 \"{1}\"",
					Paths.MSBuildFileName, Paths.VPN4SolutionFileName);
				bat.WriteLine("IF ERRORLEVEL 1 GOTO LABEL_ERROR");

				bat.WriteLine("\"{0}\" /toolsversion:3.5 /verbosity:detailed /target:Rebuild /property:Configuration=Release /property:Platform=Win32 \"{1}\"",
					Paths.MSBuildFileName, Paths.VPN4SolutionFileName);
				bat.WriteLine("IF ERRORLEVEL 1 GOTO LABEL_ERROR");

				bat.WriteLine("\"{0}\" /toolsversion:3.5 /verbosity:detailed /target:Rebuild /property:Configuration=Release /property:Platform=x64 \"{1}\"",
					Paths.MSBuildFileName, Paths.VPN4SolutionFileName);
				bat.WriteLine("IF ERRORLEVEL 1 GOTO LABEL_ERROR");

				bat.WriteLine(":LABEL_ERROR");

				bat.WriteLine("EXIT %ERRORLEVEL%");

				bat.Close();

				ExecCommand(Paths.CmdFileName, string.Format("/C \"{0}\"", batFileName));

				BuildReplaceHeader();
			}
			finally
			{
				x.ReleaseMutex();
			}
		}

		// Generate the Replace.h
		public static void BuildReplaceHeader()
		{
			List<string> o = new List<string>();
			int maxLen = 0;

			// Read the map file
			string[] lines = File.ReadAllLines(Path.Combine(Paths.BaseDirName, @"DebugFiles\map\Win32_Release\vpnserver.map"));
			char[] sps = { ' ', '\t', };

			foreach (string line in lines)
			{
				string[] tokens = line.Trim().Split(sps, StringSplitOptions.RemoveEmptyEntries);

				if (tokens.Length == 5)
				{
					if (tokens[0].StartsWith("0001:", StringComparison.InvariantCultureIgnoreCase))
					{
						if (tokens[0].Length == 13)
						{
							if (tokens[2].Length == 8)
							{
								if (tokens[3].Equals("f", StringComparison.InvariantCultureIgnoreCase))
								{
									if (tokens[4].StartsWith("Mayaqua:", StringComparison.InvariantCultureIgnoreCase) ||
										tokens[4].StartsWith("Cedar:", StringComparison.InvariantCultureIgnoreCase))
									{
										string name = tokens[1];

										if (name.Length >= 2)
										{
											if (Str.InStr(name, "mktime") == false &&
												Str.InStr(name, "gmtime") == false &&
												Str.InStr(name, "stdin") == false &&
												Str.InStr(name, "stdout") == false &&
												Str.InStr(name, "@") == false &&
												Str.InStr(name, "localtime") == false)
											{
												string tmp = tokens[4].Split(':')[1];

												if (tmp[0] >= 'A' && tmp[0] <= 'Z' &&
													Str.InStr(tmp, "_") == false)
												{
													o.Add(name.Substring(1));

													maxLen = Math.Max(maxLen, name.Length);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			o.Sort();

			// Generate the Replace.h
			string filename = Path.Combine(Paths.BaseDirName, @"DebugFiles\Replace.h");
			StreamWriter w = new StreamWriter(filename);

			w.WriteLine("// PacketiX VPN Function Name Replacement Header File");
			w.WriteLine("//");
			w.WriteLine("// Copyright (c) SoftEther Corporation.");
			w.WriteLine("// All Rights Reserved.");
			w.WriteLine("//");
			w.WriteLine("// SoftEther Confidential");
			w.WriteLine("//");
			w.WriteLine();

			foreach (string name in o)
			{
				if (Str.StrCmpi(name, "VLanGetPacketAdapter") == false)
				{
					string tmp = Str.ByteToHex(Secure.HashMD5(Str.Utf8Encoding.GetBytes("xx" + name)), "");
					string tmp2 = "VPN_" + tmp.Substring(0, 12).ToUpper();

					w.WriteLine("#define  {0,-" + maxLen.ToString() + "}  {1}",
						name, tmp2);
				}
			}

			w.WriteLine();

			w.Flush();
			w.Close();
		}

		// Command execution
		public static void ExecCommand(string exe, string arg)
		{
			ExecCommand(exe, arg, false);
		}
		public static void ExecCommand(string exe, string arg, bool shell_execute)
		{
			Process p = new Process();
			p.StartInfo.FileName = exe;
			p.StartInfo.Arguments = arg;
			p.StartInfo.UseShellExecute = shell_execute;

			if (shell_execute)
			{
				p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			}

			Con.WriteLine("Executing '{0} {1}'...", exe, arg);

			p.Start();

			p.WaitForExit();

			int ret = p.ExitCode;
			if (ret != 0)
			{
				throw new ApplicationException(string.Format("Child process '{0}' returned error code {1}.", exe, ret));
			}

			Kernel.SleepThread(50);
		}

		// Get whether the specified fileis a target of signature
		public static bool IsFileSignable(string fileName)
		{
			if (fileName.IndexOf(@".svn", StringComparison.InvariantCultureIgnoreCase) != -1 ||
				fileName.StartsWith(".svn", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("vpn16.exe", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("BuildUtil.exe", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("BuildUtilTmp.exe", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("CoreUtil.dll", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("npptools.dll", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("winpcap_installer.exe", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("winpcap_installer_win9x.exe", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("VpnGatePlugin_x64.dll", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (fileName.EndsWith("VpnGatePlugin_x86.dll", StringComparison.InvariantCultureIgnoreCase))
			{
				return false;
			}
			if (Str.InStr(fileName, "DriverPackages", false))
			{
				return false;
			}
			if (Str.InStr(fileName, "_nosign", false))
			{
				return false;
			}

			if (fileName.EndsWith(".exe", StringComparison.InvariantCultureIgnoreCase) ||
				fileName.EndsWith(".dll", StringComparison.InvariantCultureIgnoreCase) ||
				fileName.EndsWith(".ocx", StringComparison.InvariantCultureIgnoreCase) ||
				fileName.EndsWith(".sys", StringComparison.InvariantCultureIgnoreCase))
			{
				return true;
			}

			return false;
		}

		// Create and sign the Inf file and the catalog file for SeLow
		public static void SignSeLowInfFiles(string cpu)
		{
			int build, version;
			string name;
			DateTime date;

			ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			string hamcore = Path.Combine(Paths.BinDirName, "hamcore");
			string sys_src = Path.Combine(hamcore, "SeLow_" + cpu + ".sys");
			string inf_src = Path.Combine(hamcore, "SeLow_" + cpu + ".inf");

			Con.WriteLine("Generating INF Files for SeLow...");

			string dst_dir = Path.Combine(hamcore, @"inf\selow_" + cpu);

			if (ExeSignChecker.CheckFileDigitalSignature(sys_src) == false ||
				ExeSignChecker.IsKernelModeSignedFile(sys_src) == false)
			{
				throw new ApplicationException(sys_src + " is not signed.");
			}

			generateINFFilesForPlatform(inf_src, sys_src, null, dst_dir, version, build, date, true);

			Con.WriteLine("Generating INF Files for SeLow Ok.");
		}

		// Create Inf file for Windows 8
		public static void GenerateINFFilesForWindows8(string cpu)
		{
			int build, version;
			string name;
			DateTime date;
			ReadBuildInfoFromTextFile(out build, out version, out name, out date);

			string hamcore = Path.Combine(Paths.BinDirName, "hamcore");
			string inf_src_x86 = Path.Combine(hamcore, "vpn_driver.inf");
			string inf_src_x64 = Path.Combine(hamcore, "vpn_driver_x64.inf");
			string sys_src_x86 = Path.Combine(hamcore, "vpn_driver.sys");
			string sys_src_x64 = Path.Combine(hamcore, "vpn_driver_x64.sys");
			string sys6_src_x86 = Path.Combine(hamcore, "vpn_driver6.sys");
			string sys6_src_x64 = Path.Combine(hamcore, "vpn_driver6_x64.sys");

			Con.WriteLine("Generating INF Files for Windows 8...");

			string dst_x86 = Path.Combine(hamcore, @"inf\x86");
			string dst_x64 = Path.Combine(hamcore, @"inf\x64");

			if (Str.StrCmpi(cpu, "x64"))
			{
				if (ExeSignChecker.CheckFileDigitalSignature(sys_src_x64) == false || ExeSignChecker.IsKernelModeSignedFile(sys_src_x64) == false)
				{
					throw new ApplicationException(sys_src_x64 + " is not signed.");
				}

				generateINFFilesForPlatform(inf_src_x64, sys_src_x64, sys6_src_x64, dst_x64, version, build, date, false);
			}
			else
			{
				if (ExeSignChecker.CheckFileDigitalSignature(sys_src_x86) == false || ExeSignChecker.IsKernelModeSignedFile(sys_src_x86) == false)
				{
					throw new ApplicationException(sys_src_x86 + " is not signed.");
				}

				generateINFFilesForPlatform(inf_src_x86, sys_src_x86, sys6_src_x86, dst_x86, version, build, date, false);
			}

			Con.WriteLine("Generating INF Files for Windows 8 Ok.");
		}
		static void generateINFFilesForPlatform(string inf, string sys, string sys6, string dstDir, int ver, int build, DateTime date, bool selow)
		{

			string cdfFileName = Path.Combine(dstDir, "inf.cdf");
			string cdfFileName2 = Path.Combine(dstDir, "inf2.cdf");
			string catFileName = Path.Combine(dstDir, "inf.cat");
			string catFileName2 = Path.Combine(dstDir, "inf2.cat");
			StringWriter sw = new StringWriter();
			StringWriter sw2 = new StringWriter();

			string txt = File.ReadAllText(inf, Str.ShiftJisEncoding);

			IO.DeleteFilesAndSubDirsInDir(dstDir);
			IO.MakeDirIfNotExists(dstDir);

			string utility_dirname = Path.Combine(Paths.BaseDirName, @"BuildFiles\Utility");
			string makecat1 = Path.Combine(dstDir, "makecat.exe");
			string makecat2 = Path.Combine(dstDir, "makecat.exe.manifest");
			string makecat3 = Path.Combine(dstDir, "Microsoft.Windows.Build.Signing.wintrust.dll.manifest");
			string makecat4 = Path.Combine(dstDir, "wintrust.dll");
			File.Copy(Path.Combine(utility_dirname, "makecat.exe"), makecat1, true);
			File.Copy(Path.Combine(utility_dirname, "makecat.exe.manifest"), makecat2, true);
			File.Copy(Path.Combine(utility_dirname, "Microsoft.Windows.Build.Signing.wintrust.dll.manifest"), makecat3, true);
			File.Copy(Path.Combine(utility_dirname, "wintrust.dll"), makecat4, true);

			string dst_sys_name = Path.Combine(dstDir, Path.GetFileName(sys));
			File.Copy(sys, dst_sys_name, true);

			string dst_sys6_name = null;
			if (sys6 != null)
			{
				dst_sys6_name = Path.Combine(dstDir, Path.GetFileName(sys6));
				File.Copy(sys6, dst_sys6_name, true);
			}

			sw.WriteLine("[CatalogHeader]");
			sw2.WriteLine("[CatalogHeader]");

			sw.WriteLine("name=inf.cat");
			sw2.WriteLine("name=inf2.cat");

			sw2.WriteLine("CatalogVersion=2");
			sw2.WriteLine("HashAlgorithms=SHA256");
			sw2.WriteLine("PageHashes=true");

			sw.WriteLine();
			sw2.WriteLine();

			sw.WriteLine("[CatalogFiles]");
			sw2.WriteLine("[CatalogFiles]");
			
			sw.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_sys_name));
			sw2.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_sys_name));

			if (sys6 != null)
			{
				sw.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_sys6_name));
				sw2.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_sys6_name));
			}

			int i;
			for (i = 1; i < 128; i++)
			{
				string name = "VPN";
				if (i >= 2)
				{
					name += i.ToString();
				}

				if (selow)
				{
					name = "selow";
				}

				//string mac = "00AC0011" + i.ToString("X2") + "01";
				string mac = "000001000001";
				string sys_name = "Neo_" + name + ".sys";

				string body = txt;
				body = Str.ReplaceStr(body, "$TAG_SYS_NAME$", sys_name);
				body = Str.ReplaceStr(body, "$TAG_INSTANCE_NAME$", name);
				body = Str.ReplaceStr(body, "$TAG_MAC_ADDRESS$", mac);
				body = Str.ReplaceStr(body, "$YEAR$", date.Year.ToString("D4"));
				body = Str.ReplaceStr(body, "$MONTH$", date.Month.ToString("D2"));
				body = Str.ReplaceStr(body, "$DAY$", date.Day.ToString("D2"));
				body = Str.ReplaceStr(body, "$VER_MAJOR$", (ver / 100).ToString());
				body = Str.ReplaceStr(body, "$VER_MINOR$", (ver % 100).ToString());
				body = Str.ReplaceStr(body, "$VER_BUILD$", build.ToString());
				body = Str.ReplaceStr(body, "[Manufacturer]", "CatalogFile.NT\t\t\t\t= inf_" + name + ".cat\r\n\r\n[Manufacturer]");

				string dst_inf_name = Path.Combine(dstDir, "INF_" + name + ".inf");

				if (selow)
				{
					dst_inf_name = Path.Combine(dstDir, Path.GetFileName(inf));
				}

				if (selow)
				{
					body += "\r\n; Auto Generated " + Str.DateTimeToStrShortWithMilliSecs(DateTime.Now) + "\r\n\r\n";
				}

				File.WriteAllText(dst_inf_name, body, Str.ShiftJisEncoding);

				sw.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_inf_name));
				sw2.WriteLine("<hash>{0}={0}", Path.GetFileName(dst_inf_name));

				if (selow)
				{
					break;
				}
			}
			sw.WriteLine();
			sw2.WriteLine();

			File.WriteAllText(cdfFileName, sw.ToString());
			File.WriteAllText(cdfFileName2, sw2.ToString());

			// generate catalog file
			Directory.SetCurrentDirectory(dstDir);
			ExecCommand(Paths.MakeCatFilename, string.Format("\"{0}\"", cdfFileName));
			ExecCommand(makecat1, string.Format("\"{0}\"", cdfFileName2));

			// sign catalog file
			CodeSign.SignFile(catFileName, catFileName, "Catalog File", false);
			CodeSign.SignFile(catFileName2, catFileName2, "Catalog File", false);

			// delete cdf file
			File.Delete(cdfFileName);
			File.Delete(cdfFileName2);

			// delete sys file
			File.Delete(dst_sys_name);

			File.Delete(makecat1);
			File.Delete(makecat2);
			File.Delete(makecat3);
			File.Delete(makecat4);

			if (sys6 != null)
			{
				File.Delete(dst_sys6_name);
			}
		}

		static string process_inf_file(string src_inf_txt, int build, int ver, DateTime date, string sys_name, string name, string catfile, bool replace_mac_address)
		{
			string body = src_inf_txt;

			if (Str.IsEmptyStr(sys_name) == false)
			{
				body = Str.ReplaceStr(body, "$TAG_SYS_NAME$", sys_name);
			}
			if (Str.IsEmptyStr(name) == false)
			{
				body = Str.ReplaceStr(body, "$TAG_INSTANCE_NAME$", name);
			}
			if (replace_mac_address)
			{
				body = Str.ReplaceStr(body, "$TAG_MAC_ADDRESS$", "000001000001");
			}
			body = Str.ReplaceStr(body, "$YEAR$", date.Year.ToString("D4"));
			body = Str.ReplaceStr(body, "$MONTH$", date.Month.ToString("D2"));
			body = Str.ReplaceStr(body, "$DAY$", date.Day.ToString("D2"));
			body = Str.ReplaceStr(body, "$VER_MAJOR$", (ver / 100).ToString());
			body = Str.ReplaceStr(body, "$VER_MINOR$", (ver % 100).ToString());
			body = Str.ReplaceStr(body, "$VER_BUILD$", build.ToString());

			if (Str.IsEmptyStr(catfile) == false)
			{
				body = Str.ReplaceStr(body, "$CATALOG_FILENAME$", catfile);
				body = Str.ReplaceStr(body, ";CatalogFile.NT", "CatalogFile.NT");
			}

			body += "\r\n; Auto Generated " + Str.DateTimeToStrShortWithMilliSecs(DateTime.Now) + "\r\n\r\n";

			return body;
		}

		static void make_cat_file(string dir, string[] filename_list, string catname, bool win8, bool no_sign)
		{
			string utility_dirname = Path.Combine(Paths.BaseDirName, @"BuildFiles\Utility");
			string makecat1 = Path.Combine(dir, "makecat.exe");
			string makecat2 = Path.Combine(dir, "makecat.exe.manifest");
			string makecat3 = Path.Combine(dir, "Microsoft.Windows.Build.Signing.wintrust.dll.manifest");
			string makecat4 = Path.Combine(dir, "wintrust.dll");
			File.Copy(Path.Combine(utility_dirname, "makecat.exe"), makecat1, true);
			File.Copy(Path.Combine(utility_dirname, "makecat.exe.manifest"), makecat2, true);
			File.Copy(Path.Combine(utility_dirname, "Microsoft.Windows.Build.Signing.wintrust.dll.manifest"), makecat3, true);
			File.Copy(Path.Combine(utility_dirname, "wintrust.dll"), makecat4, true);

			StringWriter sw2 = new StringWriter();
			sw2.WriteLine("[CatalogHeader]");
			sw2.WriteLine("name=" + catname);

			if (win8)
			{
				sw2.WriteLine("CatalogVersion=2");
				sw2.WriteLine("HashAlgorithms=SHA256");
				sw2.WriteLine("PageHashes=true");
			}

			sw2.WriteLine();

			sw2.WriteLine("[CatalogFiles]");

			foreach (string filename in filename_list)
			{
				sw2.WriteLine("<hash>{0}={0}", filename);
			}

			sw2.WriteLine();
			
			string cdf_file_name = catname + ".cdf";

			Directory.SetCurrentDirectory(dir);

			File.WriteAllText(cdf_file_name, sw2.ToString());
			ExecCommand(makecat1, string.Format("\"{0}\"", cdf_file_name));

			if (no_sign == false)
			{
				CodeSign.SignFile(catname, catname, "Catalog File", false);
			}

			File.Delete(cdf_file_name);

			File.Delete(makecat1);
			File.Delete(makecat2);
			File.Delete(makecat3);
			File.Delete(makecat4);
		}

		public static void MakeDriverPackage()
		{
			int build, version;
			string buildname;
			DateTime date;
			int i;

			ReadBuildInfoFromTextFile(out build, out version, out buildname, out date);

			date = date.AddDays(-1);

			string dst_dir = Path.Combine(Paths.BaseDirName, @"tmp\MakeDriverPackage");
			string src_dir = Path.Combine(Paths.BaseDirName, @"BuiltDriverPackages");
			IO.DeleteFilesAndSubDirsInDir(dst_dir);
			IO.MakeDirIfNotExists(dst_dir);

			// Neo9x x86
			IO.MakeDir(Path.Combine(dst_dir, @"Neo9x\x86"));
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo9x\x86\Neo9x_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo9x\x86\Neo9x_x86.inf")), build, version, date, null, null, null, false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Neo9x\x86\Neo9x_x86.sys"), Path.Combine(dst_dir, @"Neo9x\x86\Neo9x_x86.sys"));

			// Neo x86
			IO.MakeDir(Path.Combine(dst_dir, @"Neo\x86"));
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo\x86\Neo_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo\x86\Neo_x86.inf")), build, version, date, null, null, null, false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Neo\x86\Neo_x86.sys"), Path.Combine(dst_dir, @"Neo\x86\Neo_x86.sys"));

			// Neo x64
			IO.MakeDir(Path.Combine(dst_dir, @"Neo\x64"));
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo\x64\Neo_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo\x64\Neo_x64.inf")), build, version, date, null, null, null, false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Neo\x64\Neo_x64.sys"), Path.Combine(dst_dir, @"Neo\x64\Neo_x64.sys"));

			// Neo6 x86
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6\x86"));
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6\x86\Neo6_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.inf")), build, version, date, null, null, null, false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.sys"), Path.Combine(dst_dir, @"Neo6\x86\Neo6_x86.sys"));

			// Neo6 x64
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6\x64"));
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6\x64\Neo6_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.inf")), build, version, date, null, null, null, false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.sys"), Path.Combine(dst_dir, @"Neo6\x64\Neo6_x64.sys"));

			// Neo6 for Windows 8 x86
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6_Win8\x86"));
			List<string> cat_src_filename = new List<string>();
			cat_src_filename.Add("Neo6_x86.sys");
			for (i = 1; i < 128; i++)
			{
				string name = "VPN";
				if (i >= 2)
				{
					name += i.ToString();
				}
				string sys_name = "Neo_" + name + ".sys";
				IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6_Win8\x86\Neo6_x86_" + name + ".inf"),
					process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.inf")), build, version, date, sys_name, name, string.Format("inf_{0}.cat", name), true), Str.ShiftJisEncoding, false);
				cat_src_filename.Add("Neo6_x86_" + name + ".inf");
			}
			IO.FileCopy(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.sys"), Path.Combine(dst_dir, @"Neo6_Win8\x86\Neo6_x86.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Neo6_Win8\x86"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"Neo6_Win8\x86"), cat_src_filename.ToArray(), "inf2.cat", true, false);

			// Neo6 for Windows 8 x64
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6_Win8\x64"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("Neo6_x64.sys");
			for (i = 1; i < 128; i++)
			{
				string name = "VPN";
				if (i >= 2)
				{
					name += i.ToString();
				}
				string sys_name = "Neo_" + name + ".sys";
				IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6_Win8\x64\Neo6_x64_" + name + ".inf"),
					process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.inf")), build, version, date, sys_name, name, string.Format("inf_{0}.cat", name), true), Str.ShiftJisEncoding, false);
				cat_src_filename.Add("Neo6_x64_" + name + ".inf");
			}
			IO.FileCopy(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.sys"), Path.Combine(dst_dir, @"Neo6_Win8\x64\Neo6_x64.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Neo6_Win8\x64"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"Neo6_Win8\x64"), cat_src_filename.ToArray(), "inf2.cat", true, false);
			
			// Neo6 for Windows 10 x86
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6_Win10\x86"));
			for (i = 1; i < 128; i++)
			{
				string name = "VPN";
				if (i >= 2)
				{
					name += i.ToString();
				}
				cat_src_filename = new List<string>();
				cat_src_filename.Add("Neo6_x86_" + name + ".sys");
				string sys_name = "Neo6_x86_" + name + ".sys";
				IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6_Win10\x86\Neo6_x86_" + name + ".inf"),
					process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.inf")), build, version, date, sys_name, name, string.Format("Neo6_x86_{0}.cat", name), true), Str.ShiftJisEncoding, false);
				cat_src_filename.Add("Neo6_x86_" + name + ".inf");
				IO.FileCopy(Path.Combine(src_dir, @"Neo6\x86\Neo6_x86.sys"), Path.Combine(dst_dir, @"Neo6_Win10\x86\Neo6_x86_" + name + ".sys"));
				make_cat_file(Path.Combine(dst_dir, @"Neo6_Win10\x86"), cat_src_filename.ToArray(), "Neo6_x86_" + name + ".cat", true, true);
			}

			// Neo6 for Windows 10 x64
			IO.MakeDir(Path.Combine(dst_dir, @"Neo6_Win10\x64"));
			for (i = 1; i < 128; i++)
			{
				string name = "VPN";
				if (i >= 2)
				{
					name += i.ToString();
				}
				cat_src_filename = new List<string>();
				cat_src_filename.Add("Neo6_x64_" + name + ".sys");
				string sys_name = "Neo6_x64_" + name + ".sys";
				IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Neo6_Win10\x64\Neo6_x64_" + name + ".inf"),
					process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.inf")), build, version, date, sys_name, name, string.Format("Neo6_x64_{0}.cat", name), true), Str.ShiftJisEncoding, false);
				cat_src_filename.Add("Neo6_x64_" + name + ".inf");
				IO.FileCopy(Path.Combine(src_dir, @"Neo6\x64\Neo6_x64.sys"), Path.Combine(dst_dir, @"Neo6_Win10\x64\Neo6_x64_" + name + ".sys"));
				make_cat_file(Path.Combine(dst_dir, @"Neo6_Win10\x64"), cat_src_filename.ToArray(), "Neo6_x64_" + name + ".cat", true, true);
			}

			IO.CopyDir(Path.Combine(src_dir, "See"), Path.Combine(dst_dir, "See"), null, false, false);

			// SeLow x86 for Windows 8.1
			IO.MakeDir(Path.Combine(dst_dir, @"SeLow_Win8\x86"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("SeLow_x86.sys");
			cat_src_filename.Add("SeLow_x86.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"SeLow_Win8\x86\SeLow_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"SeLow\x86\SeLow_x86.inf")), build, version, date, null, null, "SeLow_Win8_x86.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"SeLow\x86\SeLow_x86.sys"), Path.Combine(dst_dir, @"SeLow_Win8\x86\SeLow_x86.sys"));
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win8\x86"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win8\x86"), cat_src_filename.ToArray(), "inf2.cat", true, false);

			// SeLow x64 for Windows 8.1
			IO.MakeDir(Path.Combine(dst_dir, @"SeLow_Win8\x64"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("SeLow_x64.sys");
			cat_src_filename.Add("SeLow_x64.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"SeLow_Win8\x64\SeLow_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"SeLow\x64\SeLow_x64.inf")), build, version, date, null, null, "SeLow_Win8_x64.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"SeLow\x64\SeLow_x64.sys"), Path.Combine(dst_dir, @"SeLow_Win8\x64\SeLow_x64.sys"));
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win8\x64"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win8\x64"), cat_src_filename.ToArray(), "inf2.cat", true, false);

			// SeLow x86 for Windows 10
			IO.MakeDir(Path.Combine(dst_dir, @"SeLow_Win10\x86"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("SeLow_x86.sys");
			cat_src_filename.Add("SeLow_x86.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"SeLow_Win10\x86\SeLow_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"SeLow\x86\SeLow_x86.inf")), build, version, date, null, null, "SeLow_Win10_x86.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"SeLow\x86\SeLow_x86.sys"), Path.Combine(dst_dir, @"SeLow_Win10\x86\SeLow_x86.sys"));
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win10\x86"), cat_src_filename.ToArray(), "SeLow_Win10_x86.cat", true, false);

			// SeLow x64 for Windows 10
			IO.MakeDir(Path.Combine(dst_dir, @"SeLow_Win10\x64"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("SeLow_x64.sys");
			cat_src_filename.Add("SeLow_x64.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"SeLow_Win10\x64\SeLow_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"SeLow\x64\SeLow_x64.inf")), build, version, date, null, null, "SeLow_Win10_x64.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"SeLow\x64\SeLow_x64.sys"), Path.Combine(dst_dir, @"SeLow_Win10\x64\SeLow_x64.sys"));
			make_cat_file(Path.Combine(dst_dir, @"SeLow_Win10\x64"), cat_src_filename.ToArray(), "SeLow_Win10_x64.cat", true, false);

			// Wfp x86
			IO.MakeDir(Path.Combine(dst_dir, @"Wfp\x86"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("pxwfp_x86.sys");
			cat_src_filename.Add("pxwfp_x86.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Wfp\x86\pxwfp_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Wfp\x86\pxwfp_x86.inf")), build, version, date, null, null, "pxwfp_x86.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Wfp\x86\pxwfp_x86.sys"), Path.Combine(dst_dir, @"Wfp\x86\pxwfp_x86.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Wfp\x86"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"Wfp\x86"), cat_src_filename.ToArray(), "inf2.cat", true, false);

			// Wfp x64
			IO.MakeDir(Path.Combine(dst_dir, @"Wfp\x64"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("pxwfp_x64.sys");
			cat_src_filename.Add("pxwfp_x64.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Wfp\x64\pxwfp_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Wfp\x64\pxwfp_x64.inf")), build, version, date, null, null, "pxwfp_x64.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Wfp\x64\pxwfp_x64.sys"), Path.Combine(dst_dir, @"Wfp\x64\pxwfp_x64.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Wfp\x64"), cat_src_filename.ToArray(), "inf.cat", false, false);
			make_cat_file(Path.Combine(dst_dir, @"Wfp\x64"), cat_src_filename.ToArray(), "inf2.cat", true, false);

			// Wfp x86 for Windows 10
			IO.MakeDir(Path.Combine(dst_dir, @"Wfp_Win10\x86"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("pxwfp_x86.sys");
			cat_src_filename.Add("pxwfp_x86.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Wfp_Win10\x86\pxwfp_x86.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Wfp\x86\pxwfp_x86.inf")), build, version, date, null, null, "pxwfp_Win10_x86.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Wfp\x86\pxwfp_x86.sys"), Path.Combine(dst_dir, @"Wfp_Win10\x86\pxwfp_x86.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Wfp_Win10\x86"), cat_src_filename.ToArray(), "pxwfp_Win10_x86.cat", true, false);

			// Wfp x64 for Windows 10
			IO.MakeDir(Path.Combine(dst_dir, @"Wfp_Win10\x64"));
			cat_src_filename = new List<string>();
			cat_src_filename.Add("pxwfp_x64.sys");
			cat_src_filename.Add("pxwfp_x64.inf");
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, @"Wfp_Win10\x64\pxwfp_x64.inf"),
				process_inf_file(IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, @"Wfp\x64\pxwfp_x64.inf")), build, version, date, null, null, "pxwfp_Win10_x64.cat", false), Str.ShiftJisEncoding, false);
			IO.FileCopy(Path.Combine(src_dir, @"Wfp\x64\pxwfp_x64.sys"), Path.Combine(dst_dir, @"Wfp_Win10\x64\pxwfp_x64.sys"));
			make_cat_file(Path.Combine(dst_dir, @"Wfp_Win10\x64"), cat_src_filename.ToArray(), "pxwfp_Win10_x64.cat", true, false);

			string tmp_body = IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, "make_whql_submission.cm_"));
			tmp_body = Str.ReplaceStr(tmp_body, "test_tag", Str.DateTimeToStrShort(DateTime.Now) + "_Build_" + build.ToString());
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, "make_whql_submission.cmd"), tmp_body, Str.ShiftJisEncoding);

			IO.FileCopy(Path.Combine(src_dir, "2_merge_whql_sign.cm_"), Path.Combine(dst_dir, "2_merge_whql_sign.cm_"));

			tmp_body = IO.ReadAllTextWithAutoGetEncoding(Path.Combine(src_dir, "Memo.txt"));
			tmp_body = Str.ReplaceStr(tmp_body, "tag_ver", (version / 100).ToString() + "." + (version % 100).ToString());
			tmp_body = Str.ReplaceStr(tmp_body, "tag_build", build.ToString());
			IO.WriteAllTextWithEncoding(Path.Combine(dst_dir, "Memo.txt"), tmp_body, Str.ShiftJisEncoding);

			Kernel.Run(Path.Combine(Env.WindowsDir, "explorer.exe"), "\"" + dst_dir + "\"");
		}

		// Sign for all binary files (series mode)
		public static void SignAllBinaryFilesSerial()
		{
			string[] files = Directory.GetFiles(Paths.BinDirName, "*", SearchOption.AllDirectories);

			foreach (string file in files)
			{
				if (IsFileSignable(file))
				{
					bool isDriver = file.EndsWith(".sys", StringComparison.InvariantCultureIgnoreCase);

					// Check whether this file is signed
					bool isSigned = ExeSignChecker.CheckFileDigitalSignature(file);
					if (isSigned && isDriver)
					{
						isSigned = ExeSignChecker.IsKernelModeSignedFile(file);
					}

					Con.WriteLine("The file '{0}': {1}.", file, isSigned ? "Already signed" : "Not yet signed");

					if (isSigned == false)
					{
						Con.WriteLine("Signing...");

						CodeSign.SignFile(file, file, "VPN Software", isDriver);
					}
				}
			}
		}

		// Sign for all binary files (parallel mode)
		public static void SignAllBinaryFiles()
		{
			string[] files = Directory.GetFiles(Paths.BinDirName, "*", SearchOption.AllDirectories);

			List<string> filename_list = new List<string>();

			foreach (string file in files)
			{
				if (IsFileSignable(file))
				{
					bool isDriver = file.EndsWith(".sys", StringComparison.InvariantCultureIgnoreCase);

					// Check whether this file is signed
					bool isSigned = ExeSignChecker.CheckFileDigitalSignature(file);
					if (isSigned && isDriver)
					{
						isSigned = ExeSignChecker.IsKernelModeSignedFile(file);
					}

					Con.WriteLine("The file '{0}': {1}.", file, isSigned ? "Already signed" : "Not yet signed");

					if (isSigned == false)
					{
						filename_list.Add(file);
					}
				}
			}

			Con.WriteLine("Start ProcessWorkQueue for Signing...\n");
			ThreadObj.ProcessWorkQueue(sign_thread, 40, filename_list.ToArray());
			Con.WriteLine("ProcessWorkQueue for Signing completed.\n");
		}

		// Binary file signature thread
		static void sign_thread(object param)
		{
			string filename = (string)param;
			bool isDriver = filename.EndsWith(".sys", StringComparison.InvariantCultureIgnoreCase);

			Con.WriteLine("Signing...");

			CodeSign.SignFile(filename, filename, "VPN Software", isDriver);
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
