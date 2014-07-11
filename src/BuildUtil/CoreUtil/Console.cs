// CoreUtil
// 
// Copyright (C) 2012-2014 Daiyuu Nobori. All Rights Reserved.
// Copyright (C) 2012-2014 SoftEther VPN Project at University of Tsukuba. All Rights Reserved.
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
using System.Web.Mail;
using System.Reflection;
using System.Runtime.InteropServices;

#if ASPNET
using Resources.BuildUtil.Properties;
#else
using BuildUtil.Properties;
#endif

namespace CoreUtil
{
	public static class Con
	{
		static ConsoleService cs = null;

		public static ConsoleService ConsoleService
		{
			get { return Con.cs; }
		}

		public static void SetConsoleService(ConsoleService svc)
		{
			cs = svc;
		}

		public static void UnsetConsoleService()
		{
			cs = null;
		}

		public static string ReadLine()
		{
			return ReadLine("");
		}
		public static string ReadLine(string prompt)
		{
			return ReadLine(prompt, false);
		}
		public static string ReadLine(string prompt, bool noFile)
		{
			if (cs != null)
			{
				return cs.ReadLine(prompt, noFile);
			}
			else
			{
				Console.Write(prompt);
				return Console.ReadLine();
			}
		}

		public static void WriteLine()
		{
			WriteLine("");
		}

		public static void WriteLine(object arg)
		{
			if (cs != null)
			{
				cs.WriteLine(arg);
			}
			else
			{
				Console.WriteLine(arg);
			}
		}

		public static void WriteLine(string str)
		{
			if (cs != null)
			{
				cs.WriteLine(str);
			}
			else
			{
				Console.WriteLine(str);
			}
		}

		public static void WriteLine(string str, object arg)
		{
			if (cs != null)
			{
				cs.WriteLine(str, arg);
			}
			else
			{
				Console.WriteLine(str, arg);
			}
		}

		public static void WriteLine(string str, params object[] args)
		{
			if (cs != null)
			{
				cs.WriteLine(str, args);
			}
			else
			{
				Console.WriteLine(str, args);
			}
		}
	}

	public class ConsoleUserCancelException : Exception
	{
		public ConsoleUserCancelException(string msg)
			: base(msg)
		{
		}
	}

	public class ConsoleEvalMinMaxParam
	{
		public readonly string ErrorMessageString;
		public readonly int MinValue, MaxValue;

		public ConsoleEvalMinMaxParam(string errorMessageString, int minValue, int maxValue)
		{
			this.ErrorMessageString = errorMessageString;
			this.MinValue = minValue;
			this.MaxValue = maxValue;
		}
	}

	public enum ConsoleType
	{
		Local,
		Csv,
	}

	public class ConsoleParam
	{
		public readonly string Name;
		public readonly ConsolePromptProcDelegate PromptProc;
		public readonly object PromptProcParam;	
		public readonly ConsoleEvalProcDelegate EvalProc;	
		public readonly object EvalProcParam;	
		internal string Tmp = null;			
		public ConsoleParam(string name)
			: this(name, null, null)
		{
		}
		public ConsoleParam(string name,
			ConsolePromptProcDelegate promptProc,
			object promptProcParam)
			: this(name, promptProc, promptProcParam, null, null)
		{
		}
		public ConsoleParam(string name,
			ConsolePromptProcDelegate promptProc,
			object promptProcParam,
			ConsoleEvalProcDelegate evalProc,
			object evalProcParam)
		{
			this.Name = name;
			this.PromptProc = promptProc;
			this.PromptProcParam = promptProcParam;
			this.EvalProc = evalProc;
			this.EvalProcParam = evalProcParam;
		}
	}

	public delegate string ConsolePromptProcDelegate(ConsoleService c, object param);
	public delegate bool ConsoleEvalProcDelegate(ConsoleService c, string str, object param);

	delegate void ConsoleFreeDelegate();
	delegate string ConsoleReadLineDelegate(string prompt, bool nofile);
	delegate string ConsoleReadPasswordDelegate(string prompt);
	delegate bool ConsoleWriteDelegate(string str);
	delegate int ConsoleGetWidthDelegate();

	public class ConsoleParamValueList
	{
		List<ConsoleParamValue> o;

		public ConsoleParamValueList()
		{
			o = new List<ConsoleParamValue>();
		}

		public IEnumerable<ConsoleParamValue> Values
		{
			get
			{
				int i;
				for (i = 0; i < o.Count; i++)
				{
					yield return o[i];
				}
			}
		}

		public void Add(ConsoleParamValue v)
		{
			if (o.Contains(v) == false)
			{
				o.Add(v);
			}
		}

		public ConsoleParamValue this[string name]
		{
			get
			{
				ConsoleParamValue v = new ConsoleParamValue(name, "", 0);

				int i = o.IndexOf(v);
				if (i == -1)
				{
					return new ConsoleParamValue(name, "", 0);
				}

				return o[i];
			}
		}

		public ConsoleParamValue DefaultParam
		{
			get
			{
				foreach (ConsoleParamValue c in o)
				{
					if (c.IsDefaultParam)
					{
						return c;
					}
				}

				return new ConsoleParamValue("", "", 0, true);
			}
		}

		public string GetStr(string name)
		{
			ConsoleParamValue v = this[name];
			if (v == null)
			{
				return null;
			}

			return v.StrValue;
		}

		public int GetInt(string name)
		{
			ConsoleParamValue v = this[name];
			if (v == null)
			{
				return 0;
			}

			return v.IntValue;
		}

		public bool GetYes(string name)
		{
			return Str.StrToBool(name);
		}
	}

	public class ConsoleParamValue : IComparable<ConsoleParamValue>, IEquatable<ConsoleParamValue>
	{
		public readonly string Name;			
		public readonly string StrValue;	
		public readonly int IntValue;			
		public readonly bool BoolValue;			
		public readonly bool IsEmpty;			
		public readonly bool IsDefaultParam;	

		public ConsoleParamValue(string name, string strValue, int intValue)
			: this(name, strValue, intValue, false)
		{
		}
		public ConsoleParamValue(string name, string strValue, int intValue, bool isDefaultParam)
		{
			this.Name = name;
			this.IntValue = intValue;
			this.StrValue = strValue;
			this.BoolValue = Str.StrToBool(strValue);
			this.IsDefaultParam = isDefaultParam;

			this.IsEmpty = Str.IsEmptyStr(strValue);
		}

		public int CompareTo(ConsoleParamValue other)
		{
			return Str.StrCmpiRetInt(this.Name, other.Name);
		}

		public bool Equals(ConsoleParamValue other)
		{
			return Str.StrCmpi(this.Name, other.Name);
		}
	}

	public class ConsoleCommandParam : Attribute
	{
	}

	public class ConsoleCommandMethod : Attribute
	{
		public readonly string Description;
		public readonly string ArgsHelp;
		public readonly string BodyHelp;
		public readonly SortedList<string, string> ParamHelp;

		internal BindingFlags bindingFlag;
		internal MemberInfo memberInfo;
		internal MethodInfo methodInfo;
		internal string name;

		public ConsoleCommandMethod(string description, string argsHelp, string bodyHelp, params string[] paramHelp)
		{
			this.Description = description;
			this.ArgsHelp = argsHelp;
			this.BodyHelp = bodyHelp;
			this.ParamHelp = new SortedList<string, string>(new StrComparer(false));

			foreach (string s in paramHelp)
			{
				int i = s.IndexOf(":");
				if (i == -1)
				{
					throw new ArgumentException(s);
				}

				this.ParamHelp.Add(s.Substring(0, i), s.Substring(i + 1));
			}
		}
	}

	public static class ConsoleErrorCode
	{
		public const int ERR_BAD_COMMAND_OR_PARAM = -100001;
		public const int ERR_INNER_EXCEPTION = -100002;
		public const int ERR_USER_CANCELED = -100003;

		public static string ErrorCodeToString(int code)
		{
			bool b;

			return ErrorCodeToString(code, out b);
		}
		public static string ErrorCodeToString(int code, out bool unknownError)
		{
			unknownError = false;

			switch (code)
			{
				case ERR_BAD_COMMAND_OR_PARAM:
					return "Bad command or parameters.";

				case ERR_USER_CANCELED:
					return "User canceled.";

				case ERR_INNER_EXCEPTION:
				default:
					unknownError = true;
					return string.Format("Unknown Error {0}", code);
			}
		}
	}

	public class ConsoleService
	{
		IO inFile;			
		Buf inBuf;					
		IO outFile;						
		int win32_OldConsoleWidth;		

		public const int MaxPromptStrSize = 65536;
		public const int Win32DefaultConsoleWidth = 100;

		ConsoleType consoleType;
		public ConsoleType ConsoleType
		{
			get { return consoleType; }
		}

		int retCode;
		public int RetCode
		{
			get { return retCode; }
		}

		string retErrorMessage;
		public string RetErrorMessage
		{
			get
			{
				bool b;
				string s = ConsoleErrorCode.ErrorCodeToString(this.RetCode, out b);

				if (b)
				{
					s = this.retErrorMessage;
				}

				Str.NormalizeString(ref s);

				return s;
			}
		}

		ConsoleFreeDelegate free;

		ConsoleReadLineDelegate readLine;

		ConsoleReadPasswordDelegate readPassword;

		ConsoleWriteDelegate write;

		ConsoleGetWidthDelegate getWidth;

		SortedList<string, ConsoleCommandMethod> currentCmdList = null;


		private ConsoleService()
		{
		}

		public static int EntryPoint(string cmdLine, string programName, Type commandClass)
		{
			string s;
			return EntryPoint(cmdLine, programName, commandClass, out s);
		}
		public static int EntryPoint(string cmdLine, string programName, Type commandClass, out string lastErrorMessage)
		{
			int ret = 0;
			string infile, outfile;
			string csvmode;
			ConsoleService c;

			lastErrorMessage = "";

			infile = ParseCommand(cmdLine, "in");
			outfile = ParseCommand(cmdLine, "out");
			if (Str.IsEmptyStr(infile))
			{
				infile = null;
			}
			if (Str.IsEmptyStr(outfile))
			{
				outfile = null;
			}
			c = ConsoleService.NewLocalConsoleService(infile, outfile);

			csvmode = ParseCommand(cmdLine, "csv");
			if (csvmode != null)
			{
				c.consoleType = ConsoleType.Csv;
			}

			if (c.DispatchCommand(cmdLine, ">", commandClass) == false)
			{
				ret = ConsoleErrorCode.ERR_BAD_COMMAND_OR_PARAM;
			}
			else
			{
				ret = c.retCode;
			}

			lastErrorMessage = c.RetErrorMessage;

			return ret;
		}

		public bool WriteLine(object value)
		{
			return WriteLine(value.ToString());
		}
		public bool WriteLine(string str)
		{
			return localWrite(str);
		}
		public bool WriteLine(string format, object arg0)
		{
			return WriteLine(string.Format(format, arg0));
		}
		public bool WriteLine(string format, params object[] arg)
		{
			return WriteLine(string.Format(format, arg));
		}

		public string ReadLine(string prompt)
		{
			return ReadLine(prompt, false);
		}
		public string ReadLine(string prompt, bool noFile)
		{
			return localReadLine(prompt, noFile);
		}

		public string ReadPassword(string prompt)
		{
			return localReadPassword(prompt);
		}

		public static ConsolePromptProcDelegate Prompt
		{
			get { return new ConsolePromptProcDelegate(prompt); }
		}
		static string prompt(ConsoleService c, object param)
		{
			string p = (param == null) ? Resources.CMD_PROMPT : (string)param;

			return c.readLine(p, true);
		}

		public static ConsoleEvalProcDelegate EvalIsFile
		{
			get { return new ConsoleEvalProcDelegate(evalIsFile); }
		}
		static bool evalIsFile(ConsoleService c, string str, object param)
		{
			string tmp;
			if (c == null || str == null)
			{
				return false;
			}

			tmp = str;

			if (Str.IsEmptyStr(tmp))
			{
				c.write(Resources.CMD_FILE_NAME_EMPTY);
				return false;
			}

			if (IO.IsFileExists(tmp) == false)
			{
				c.write(Str.FormatC(Resources.CMD_FILE_NOT_FOUND, tmp));

				return false;
			}

			return true;
		}

		public static ConsoleEvalProcDelegate EvalInt1
		{
			get { return new ConsoleEvalProcDelegate(evalInt1); }
		}
		static bool evalInt1(ConsoleService c, string str, object param)
		{
			string p = (param == null) ? Resources.CMD_EVAL_INT : (string)param;

			if (Str.StrToInt(str) == 0)
			{
				c.write(p);

				return false;
			}

			return true;
		}

		public static ConsoleEvalProcDelegate EvalNotEmpty
		{
			get { return new ConsoleEvalProcDelegate(evalNotEmpty); }
		}
		static bool evalNotEmpty(ConsoleService c, string str, object param)
		{
			string p = (param == null) ? Resources.CMD_EVAL_NOT_EMPTY : (string)param;

			if (Str.IsEmptyStr(str) == false)
			{
				return true;
			}

			c.write(p);

			return false;
		}

		public static ConsoleEvalProcDelegate EvalMinMax
		{
			get { return new ConsoleEvalProcDelegate(evalMinMax); }
		}
		static bool evalMinMax(ConsoleService c, string str, object param)
		{
			string tag;
			int v;
			if (param == null)
			{
				return false;
			}

			ConsoleEvalMinMaxParam e = (ConsoleEvalMinMaxParam)param;

			if (Str.IsEmptyStr(e.ErrorMessageString))
			{
				tag = Resources.CMD_EVAL_MIN_MAX;
			}
			else
			{
				tag = e.ErrorMessageString;
			}

			v = Str.StrToInt(str);

			if (v >= e.MinValue && v <= e.MaxValue)
			{
				return true;
			}
			else
			{
				c.write(Str.FormatC(tag, e.MinValue, e.MaxValue));

				return false;
			}
		}

		public void PrintCmdHelp(string cmdName, List<string> paramList)
		{
			string tmp;
			string buf;
			string description, args, help;
			List<string> t;
			int width;
			int i;
			string space;
			if (cmdName == null || paramList == null)
			{
				return;
			}

			width = GetConsoleWidth() - 2;

			description = this.currentCmdList[cmdName].Description;
			args = this.currentCmdList[cmdName].ArgsHelp;
			help = this.currentCmdList[cmdName].BodyHelp;

			space = Str.MakeCharArray(' ', 2);

			tmp = Str.FormatC(Resources.CMD_HELP_TITLE, cmdName);
			this.write(tmp);
			this.write("");

			this.write(Resources.CMD_HELP_DESCRIPTION);
			t = Str.StrArrayToList(SeparateStringByWidth(description, width - 2));
			for (i = 0; i < t.Count; i++)
			{
				buf = Str.FormatC("%S%s", space, t[i]);
				this.write(buf);
			}
			this.write("");

			this.write(Resources.CMD_HELP_HELP);
			t = Str.StrArrayToList(SeparateStringByWidth(help, width - 2));
			for (i = 0; i < t.Count; i++)
			{
				buf = Str.FormatC("%S%s", space, t[i]);
				this.write(buf);
			}
			this.write("");

			this.write(Resources.CMD_HELP_USAGE);
			t = Str.StrArrayToList(SeparateStringByWidth(args, width - 2));
			for (i = 0; i < t.Count; i++)
			{
				buf = Str.FormatC("%S%s", space, t[i]);
				this.write(buf);
			}

			if (paramList.Count >= 1)
			{
				this.write("");
				this.write(Resources.CMD_HELP_ARGS);
				PrintCandidateHelp(cmdName, paramList.ToArray(), 2, this.currentCmdList);
			}
		}

		public void PrintCandidateHelp(string cmdName, string[] candidateList, int leftSpace, SortedList<string, ConsoleCommandMethod> ccList)
		{
			int console_width;
			int max_keyword_width;
			List<string> o;
			int i;
			string tmpbuf;
			string left_space_array;
			string max_space_array;
			if (candidateList == null)
			{
				return;
			}

			console_width = GetConsoleWidth() - 1;

			left_space_array = Str.MakeCharArray(' ', leftSpace);

			o = new List<string>();

			max_keyword_width = 0;

			for (i = 0; i < candidateList.Length; i++)
			{
				int keyword_width;

				o.Add(candidateList[i]);

				keyword_width = Str.GetStrWidth(candidateList[i]);
				if (cmdName != null)
				{
					if (candidateList[i].StartsWith("[", StringComparison.InvariantCultureIgnoreCase) == false)
					{
						keyword_width += 1;
					}
					else
					{
						keyword_width -= 2;
					}
				}

				max_keyword_width = Math.Max(max_keyword_width, keyword_width);
			}

			max_space_array = Str.MakeCharArray(' ', max_keyword_width);

			for (i = 0; i < o.Count; i++)
			{
				string tmp;
				string name = o[i];
				List<string> t;
				string help;
				int j;
				int keyword_start_width = leftSpace;
				int descript_start_width = leftSpace + max_keyword_width + 1;
				int descript_width;
				string space;

				if (console_width >= (descript_start_width + 5))
				{
					descript_width = console_width - descript_start_width - 3;
				}
				else
				{
					descript_width = 2;
				}

				if (cmdName != null && name.StartsWith("[", StringComparison.InvariantCultureIgnoreCase) == false)
				{
					tmp = Str.FormatC("/%s", name);
				}
				else
				{
					if (cmdName == null)
					{
						tmp = name;
					}
					else
					{
						if (name.Length >= 1)
						{
							tmp = name.Substring(1);
						}
						else
						{
							tmp = "";
						}

						if (tmp.Length >= 1)
						{
							tmp = tmp.Substring(0, tmp.Length - 1);
						}
					}
				}

				if (cmdName == null)
				{
					help = ccList[name].Description;
				}
				else
				{
					if (ccList[cmdName].ParamHelp.ContainsKey(name))
					{
						help = ccList[cmdName].ParamHelp[name];
					}
					else
					{
						help = Resources.CMD_UNKNOWN_PARAM;
					}
				}

				space = Str.MakeCharArray(' ', max_keyword_width - Str.GetStrWidth(name) -
					(cmdName == null ? 0 : (name.StartsWith("[", StringComparison.InvariantCultureIgnoreCase) == false ? 1 : -2)));

				t = Str.StrArrayToList(SeparateStringByWidth(help, descript_width));

				for (j = 0; j < t.Count; j++)
				{
					if (j == 0)
					{
						tmpbuf = Str.FormatC("%S%S%S - %s",
							left_space_array, tmp, space, t[j]);
					}
					else
					{
						tmpbuf = Str.FormatC("%S%S   %s",
							left_space_array, max_space_array, t[j]);
					}

					this.write(tmpbuf);
				}
			}
		}

		public static string[] SeparateStringByWidth(string str, int width)
		{
			if (str == null)
			{
				return new string[0];
			}
			if (width <= 0)
			{
				width = 1;
			}

			StringBuilder tmp = new StringBuilder();
			int len, i;
			List<string> o = new List<string>();

			str += (char)0;
			len = str.Length;

			for (i = 0; i < len; i++)
			{
				char c = str[i];

				switch (c)
				{
					case (char)0:
					case '\r':
					case '\n':
						if (c == '\r')
						{
							if (str[i + 1] == '\n')
							{
								i++;
							}
						}

						o.Add(tmp.ToString());
						tmp = new StringBuilder();
						break;

					default:
						tmp.Append(c);
						if (Str.GetStrWidth(tmp.ToString()) >= width)
						{
							o.Add(tmp.ToString());
							tmp = new StringBuilder();
						}
						break;
				}
			}

			if (o.Count == 0)
			{
				o.Add("");
			}

			return o.ToArray();
		}

		public static bool IsHelpStr(string str)
		{
			if (str == null)
			{
				return false;
			}

			if (Str.IsStrInList(str, true,
				"help", "?", "man", "/man", "-man", "--man",
				"/help", "/?", "-help", "-?",
				"/h", "--help", "--?"))
			{
				return true;
			}

			return false;
		}

		public bool DispatchCommand(string execCommandOrNull, string prompt, Type commandClass)
		{
			return DispatchCommand(execCommandOrNull, prompt, commandClass, null);
		}
		public bool DispatchCommand(string execCommandOrNull, string prompt, Type commandClass, object invokerInstance)
		{
			SortedList<string, ConsoleCommandMethod> cmdList = GetCommandList(commandClass);

			currentCmdList = cmdList;
			try
			{
				string str, tmp, cmd_name;
				bool b_exit = false;
				string cmd_param;
				int ret = 0;
				List<string> t, candidate;
				int i;

				if (Str.IsEmptyStr(execCommandOrNull))
				{
				RETRY:
					tmp = prompt;
					str = this.readLine(tmp, false);

					if (str != null && Str.IsEmptyStr(str))
					{
						goto RETRY;
					}
				}
				else
				{
					if (prompt != null)
					{
						if (this.consoleType != ConsoleType.Csv)
						{
						}
					}
					str = execCommandOrNull;
				}

				if (str == null)
				{
					return false;
				}

				str = Str.TrimCrlf(str).Trim();

				if (Str.IsEmptyStr(str))
				{
					return true;
				}

				if (SeparateCommandAndParam(str, out cmd_name, out cmd_param) == false)
				{
					return true;
				}

				if (cmd_name.Length >= 2 && cmd_name[0] == '?' && cmd_name[1] != '?')
				{
					cmd_name = cmd_name.Substring(1);
					cmd_param = "/?";
				}

				if (cmd_name.Length >= 2 && cmd_name.EndsWith("?") && cmd_name[cmd_name.Length - 2] != '?')
				{
					cmd_name = cmd_name.Substring(0, cmd_name.Length - 1);
					cmd_param = "/?";
				}

				t = new List<string>();
				for (i = 0; i < cmdList.Count; i++)
				{
					t.Add(cmdList.Keys[i]);
				}

				if (IsHelpStr(cmd_name))
				{
					if (Str.IsEmptyStr(cmd_param))
					{
						this.write(Str.FormatC(Resources.CMD_HELP_1, t.Count));

						string[] candidateList = t.ToArray();

						PrintCandidateHelp(null, candidateList, 1, cmdList);

						this.write("");
						this.write(Resources.CMD_HELP_2);
					}
					else
					{
						string tmp2, tmp3;
						if (SeparateCommandAndParam(cmd_param, out tmp2, out tmp3))
						{
							bool b = true;

							if (IsHelpStr(tmp2))
							{
								b = false;
							}

							if (b)
							{
								DispatchCommand(Str.FormatC("%S /help", tmp2), null, commandClass, invokerInstance);
							}
						}
					}
				}
				else if (Str.StrCmpi(cmd_name, "exit") ||
					Str.StrCmpi(cmd_name, "quit"))
				{
					b_exit = true;
				}
				else
				{
					candidate = Str.StrArrayToList(GetRealnameCandidate(cmd_name, t.ToArray()));

					if (candidate == null || candidate.Count == 0)
					{
						this.write(Str.FormatC(Resources.CON_UNKNOWN_CMD, cmd_name));

						this.retCode = ConsoleErrorCode.ERR_BAD_COMMAND_OR_PARAM;
					}
					else if (candidate.Count >= 2)
					{
						this.write(Str.FormatC(Resources.CON_AMBIGIOUS_CMD, cmd_name));
						this.write(Resources.CON_AMBIGIOUS_CMD_1);
						string[] candidateArray = candidate.ToArray();

						PrintCandidateHelp(null, candidateArray, 1, cmdList);
						this.write(Resources.CON_AMBIGIOUS_CMD_2);

						this.retCode = ConsoleErrorCode.ERR_BAD_COMMAND_OR_PARAM;
					}
					else
					{
						string real_cmd_name;
						int j;

						real_cmd_name = candidate[0];

						for (j = 0; j < cmdList.Count; j++)
						{
							if (Str.Equals(cmdList.Values[j].name, real_cmd_name))
							{
								if (this.consoleType != ConsoleType.Csv)
								{
									this.write(Str.FormatC(Resources.CMD_EXEC_MSG_NAME,
										cmdList.Values[j].name,
										cmdList.Values[j].Description));
								}

								object srcObject = null;
								if (cmdList.Values[j].methodInfo.IsStatic == false)
								{
									srcObject = invokerInstance;
								}
								object[] paramList =
								{
									this,
									real_cmd_name,
									cmd_param,
								};

								try
								{
									ret = (int)cmdList.Values[j].methodInfo.Invoke(srcObject, paramList);
								}
								catch (TargetInvocationException ex)
								{
									Exception ex2 = ex.GetBaseException();

									if (ex2 is ConsoleUserCancelException)
									{
										this.write(Resources.CON_USER_CANCELED);
										this.write("");
										this.retCode = ConsoleErrorCode.ERR_USER_CANCELED;
									}
									else
									{
										this.write(ex2.ToString());
										this.write("");

										this.retCode = ConsoleErrorCode.ERR_INNER_EXCEPTION;
										this.retErrorMessage = ex2.Message;
									}

									return true;
								}

								if (ret == -1)
								{
									b_exit = true;
								}
								else
								{
									this.retCode = ret;
								}
							}
						}
					}
				}

				if (b_exit)
				{
					return false;
				}

				return true;
			}
			finally
			{
				currentCmdList = null;
			}
		}

		public static SortedList<string, ConsoleCommandMethod> GetCommandList(Type commandClass)
		{
			SortedList<string, ConsoleCommandMethod> cmdList = new SortedList<string, ConsoleCommandMethod>(new StrComparer(false));

			BindingFlags[] searchFlags =
			{
				BindingFlags.Static | BindingFlags.NonPublic,
				BindingFlags.Static | BindingFlags.Public,
				BindingFlags.Instance | BindingFlags.NonPublic,
				BindingFlags.Instance | BindingFlags.Public,
			};

			foreach (BindingFlags bFlag in searchFlags)
			{
				MemberInfo[] members = commandClass.GetMembers(bFlag);

				foreach (MemberInfo info in members)
				{
					if ((info.MemberType & MemberTypes.Method) != 0)
					{
						MethodInfo mInfo = commandClass.GetMethod(info.Name, bFlag);

						object[] customAtts = mInfo.GetCustomAttributes(true);

						foreach (object att in customAtts)
						{
							if (att is ConsoleCommandMethod)
							{
								ConsoleCommandMethod cc = (ConsoleCommandMethod)att;
								cc.bindingFlag = bFlag;
								cc.memberInfo = info;
								cc.methodInfo = mInfo;
								cc.name = info.Name;

								cmdList.Add(info.Name, cc);

								break;
							}
						}
					}
				}
			}

			return cmdList;
		}

		public int GetConsoleWidth()
		{
			int size = this.getWidth();

			if (size == 0)
			{
				size = 80;
			}

			if (size < 32)
			{
				size = 32;
			}

			if (size > 65535)
			{
				size = 65535;
			}

			return size;
		}

		public static bool SeparateCommandAndParam(string src, out string cmd, out string param)
		{
			int i, len;
			StringBuilder tmp;
			string src_tmp;
			cmd = param = null;
			if (src == null)
			{
				return false;
			}

			src_tmp = Str.TrimCrlf(src).Trim();

			len = src_tmp.Length;
			tmp = new StringBuilder();

			for (i = 0; i < (len + 1); i++)
			{
				char c;

				if (i != len)
				{
					c = src_tmp[i];
				}
				else
				{
					c = (char)0;
				}

				switch (c)
				{
					case (char)0:
					case ' ':
					case '\t':
						if (Str.IsEmptyStr(tmp.ToString()))
						{
							return false;
						}
						cmd = tmp.ToString().Trim();
						goto ESCAPE;

					default:
						tmp.Append(c);
						break;
				}
			}

		ESCAPE:
			param = src_tmp.Substring(tmp.Length).Trim();

			return true;
		}

		public static string[] GetRealnameCandidate(string inputName, string[] realNameList)
		{
			List<string> o = new List<string>();
			if (inputName == null || realNameList == null)
			{
				return new string[0];
			}

			int i;
			bool ok = false;
			for (i = 0; i < realNameList.Length; i++)
			{
				string name = realNameList[i];

				if (Str.StrCmpi(name, inputName))
				{
					o.Add(name);
					ok = true;
					break;
				}
			}

			if (ok == false)
			{
				for (i = 0; i < realNameList.Length; i++)
				{
					string name = realNameList[i];

					if (IsOmissionName(inputName, name) ||
						IsNameInRealName(inputName, name))
					{
						o.Add(name);
						ok = true;
					}
				}
			}

			if (ok)
			{
				return o.ToArray();
			}
			else
			{
				return new string[0];
			}
		}

		public static bool IsOmissionName(string inputName, string realName)
		{
			string oname;
			if (inputName == null || realName == null)
			{
				return false;
			}

			if (Str.IsAllUpperStr(realName))
			{
				return false;
			}

			oname = GetOmissionName(realName);

			if (Str.IsEmptyStr(oname))
			{
				return false;
			}

			if (oname.StartsWith(inputName, StringComparison.InvariantCultureIgnoreCase))
			{
				return true;
			}

			if (inputName.StartsWith(oname, StringComparison.InvariantCultureIgnoreCase))
			{
				if (realName.EndsWith(inputName.Substring(oname.Length), StringComparison.InvariantCultureIgnoreCase))
				{
					return true;
				}
			}

			return false;
		}

		public static string GetOmissionName(string src)
		{
			int i, len;
			if (src == null)
			{
				return null;
			}

			string dst = "";
			len = src.Length;

			for (i = 0; i < len; i++)
			{
				char c = src[i];

				if ((c >= '0' && c <= '9') ||
					(c >= 'A' && c <= 'Z'))
				{
					dst += c;
				}
			}

			return dst;
		}

		public static bool IsNameInRealName(string inputName, string realName)
		{
			if (inputName == null || realName == null)
			{
				return false;
			}

			if (realName.StartsWith(inputName, StringComparison.InvariantCultureIgnoreCase))
			{
				return true;
			}

			return false;
		}

		public ConsoleParamValueList ParseCommandList(string cmdName, string command, ConsoleParam[] param)
		{
			ConsoleParamValueList ret = parseCommandLineMain(cmdName, command, param);

			if (ret == null)
			{
				throw new ConsoleUserCancelException("");
			}

			return ret;
		}
		private ConsoleParamValueList parseCommandLineMain(string cmdName, string command, ConsoleParam[] param)
		{
			int i;
			ConsoleParamValueList o;
			List<string> param_list;
			List<string> real_name_list;
			bool help_mode = false;
			string tmp;
			bool ok = true;
			if (command == null || cmdName == null)
			{
				return null;
			}

			for (i = 0; i < param.Length; i++)
			{
				if (Str.IsEmptyStr(param[i].Name) == false)
				{
					if (param[i].Name.StartsWith("["))
					{
						param[i].Tmp = "";
					}
					else
					{
						param[i].Tmp = null;
					}
				}
				else
				{
					param[i].Tmp = "";
				}
			}

			param_list = Str.StrArrayToList(GetCommandNameList(command));

			real_name_list = new List<string>();

			for (i = 0; i < param.Length; i++)
			{
				real_name_list.Add(param[i].Name);
			}

			for (i = 0; i < param_list.Count; i++)
			{
				string s = param_list[i];

				if (Str.StrCmpi(s, "help") ||
					Str.StrCmpi(s, "?"))
				{
					help_mode = true;
					break;
				}
			}

			tmp = ParseCommand(command, "");
			if (tmp != null)
			{
				if (Str.StrCmpi(tmp, "?"))
				{
					help_mode = true;
				}
			}

			if (help_mode)
			{
				PrintCmdHelp(cmdName, real_name_list);
				return null;
			}

			for (i = 0; i < param_list.Count; i++)
			{
				string[] candidate = GetRealnameCandidate(param_list[i], real_name_list.ToArray());

				if (candidate != null && candidate.Length >= 1)
				{
					if (candidate.Length >= 2)
					{
						this.write(Str.FormatC(Resources.CON_AMBIGIOUS_PARAM,
							param_list[i]));

						this.write(Str.FormatC(Resources.CON_AMBIGIOUS_PARAM_1,
							cmdName));

						PrintCandidateHelp(cmdName, candidate, 1, this.currentCmdList);
						this.write(Resources.CON_AMBIGIOUS_PARAM_2);

						ok = false;
					}
					else
					{
						int j;
						string real_name = candidate[0];

						for (j = 0; j < param.Length; j++)
						{
							if (Str.StrCmpi(param[j].Name, real_name))
							{
								param[j].Tmp = param_list[i];
							}
						}
					}
				}
				else
				{
					this.write(Str.FormatC(Resources.CON_INVALID_PARAM,
						param_list[i],
						cmdName,
						cmdName));

					ok = false;
				}
			}

			if (ok == false)
			{
				return null;
			}

			o = new ConsoleParamValueList();

			for (i = 0; i < param.Length; i++)
			{
				ConsoleParam p = param[i];
				bool is_default_value = false;

				if (p.Tmp == "")
				{
					is_default_value = true;
				}

				if (p.Tmp != null || p.PromptProc != null)
				{
					string name = p.Name;
					string tmp2, str;

					if (p.Tmp != null)
					{
						tmp2 = p.Tmp;
					}
					else
					{
						tmp2 = p.Name;
					}

					str = ParseCommand(command, tmp2);

					if (str != null)
					{
						string unistr;
						bool ret;
					EVAL_VALUE:
						unistr = str;

						if (p.EvalProc != null)
						{
							ret = p.EvalProc(this, unistr, p.EvalProcParam);
						}
						else
						{
							ret = true;
						}

						if (ret == false)
						{
							string tmp3;
							if (p.PromptProc == null)
							{
								ok = false;
								break;
							}
							else
							{
								str = null;
								tmp3 = p.PromptProc(this, p.PromptProcParam);
								if (tmp3 == null)
								{
									ok = false;
									break;
								}
								else
								{
									this.write("");
									str = tmp3;
									goto EVAL_VALUE;
								}
							}
						}
						else
						{
							o.Add(new ConsoleParamValue(p.Name, str, Str.StrToInt(str), is_default_value));
						}
					}
					else
					{
						if (p.PromptProc != null)
						{
							string tmp4;
							tmp4 = p.PromptProc(this, p.PromptProcParam);
							if (tmp4 == null)
							{
								ok = false;
								break;
							}
							else
							{
								this.write("");
								str = tmp4;
								if (true)
								{
									string unistr;
									bool ret;
								EVAL_VALUE:
									unistr = str;

									if (p.EvalProc != null)
									{
										ret = p.EvalProc(this, unistr, p.EvalProcParam);
									}
									else
									{
										ret = true;
									}

									if (ret == false)
									{
										if (p.PromptProc == null)
										{
											ok = false;
											break;
										}
										else
										{
											str = null;
											tmp4 = p.PromptProc(this, p.PromptProcParam);
											if (tmp4 == null)
											{
												ok = false;
												break;
											}
											else
											{
												this.write("");
												str = tmp4;
												goto EVAL_VALUE;
											}
										}
									}
									else
									{
										o.Add(new ConsoleParamValue(p.Name, str, Str.StrToInt(str), is_default_value));
									}
								}
							}
						}
					}
				}
			}

			if (ok)
			{
				return o;
			}
			else
			{
				return null;
			}
		}

		public static string[] GetCommandNameList(string str)
		{
			if (str == null)
			{
				return new string[0];
			}

			string[] pl;
			ParseCommand(str, "dummy_str", out pl);

			return pl;
		}

		public static string ParseCommand(string str, string name)
		{
			string[] pl;
			return ParseCommand(str, name, out pl);
		}
		public static string ParseCommand(string str, string name, out string[] paramList)
		{
			int i;
			string tmp, ret = null;
			SortedList<string, int> o;
			paramList = null;
			if (str == null)
			{
				return null;
			}
			if (Str.IsEmptyStr(name))
			{
				name = null;
			}

			o = new SortedList<string, int>(new StrComparer(false));

			tmp = str.Trim();

			i = Str.SearchStr(tmp, "/CMD", 0, false);

			if (i >= 1 && tmp[i - 1] == '/')
			{
				i = -1;
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "/CMD\t", 0, false);
				if (i >= 1 && tmp[i - 1] == '/')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "/CMD:", 0, false);
				if (i >= 1 && tmp[i - 1] == '/')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "/CMD=", 0, false);
				if (i >= 1 && tmp[i - 1] == '/')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "-CMD ", 0, false);
				if (i >= 1 && tmp[i - 1] == '-')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "-CMD\t", 0, false);
				if (i >= 1 && tmp[i - 1] == '-')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "-CMD:", 0, false);
				if (i >= 1 && tmp[i - 1] == '-')
				{
					i = -1;
				}
			}
			if (i == -1)
			{
				i = Str.SearchStr(tmp, "-CMD=", 0, false);
				if (i >= 1 && tmp[i - 1] == '-')
				{
					i = -1;
				}
			}

			if (i != -1)
			{
				string s = "CMD";
				if (o != null)
				{
					if (o.ContainsKey(s) == false)
					{
						o.Add(s, 0);
					}
				}
				if (Str.StrCmpi(name, "CMD"))
				{
					ret = str.Substring(i + 5).Trim();
				}
				else
				{
					tmp = tmp.Substring(0, i);
				}
			}

			if (ret == null)
			{
				string[] t = Str.ParseCmdLine(tmp);

				if (t != null)
				{
					for (i = 0; i < t.Length; i++)
					{
						string token = t[i];

						if ((token[0] == '-' && token[1] != '-') ||
							(Str.StrCmpi(token, "--help")) ||
							(token[0] == '/' && token[1] != '/'))
						{
							int j;
							if (Str.StrCmpi(token, "--help"))
							{
								token = token.Substring(1);
							}

							j = Str.SearchStr(token, ":", 0, false);
							if (j == -1)
							{
								j = Str.SearchStr(token, "=", 0, false);
							}
							if (j != -1)
							{
								string tmp2;
								string a;

								tmp2 = token;
								if (tmp2.Length >= j)
								{
									tmp2 = tmp2.Substring(0, j);
								}

								a = tmp2.Substring(1);
								if (o != null)
								{
									if (o.ContainsKey(a) == false)
									{
										o.Add(a, 0);
									}
								}

								if (tmp2.Length >= 1 && Str.StrCmpi(name, tmp2.Substring(1)))
								{
									if (ret == null)
									{
										ret = token.Substring(j + 1);
									}
								}
							}
							else
							{
								string a = token.Substring(1);

								if (o != null)
								{
									if (o.ContainsKey(a) == false)
									{
										o.Add(a, 0);
									}

									if (Str.StrCmpi(name, token.Substring(1)))
									{
										if (ret == null)
										{
											ret = "";
										}
									}
								}
							}
						}
						else
						{
							if (name == null)
							{
								if (ret == null)
								{
									if (token.StartsWith("--"))
									{
										ret = token.Substring(1);
									}
									else if (token.StartsWith("//"))
									{
										ret = token.Substring(1);
									}
									else
									{
										ret = token;
									}
								}
							}
						}
					}
				}
			}

			if (o != null)
			{
				List<string> t = new List<string>();

				int j;
				for (j = 0; j < o.Count; j++)
				{
					t.Add(o.Keys[j]);
				}

				paramList = t.ToArray();
			}

			if (ret != null)
			{
				if (Str.StrCmpi(ret, "none") || Str.StrCmpi(ret, "null"))
				{
					ret = "";
				}
			}

			return ret;
		}

		public static ConsoleService NewLocalConsoleService()
		{
			return NewLocalConsoleService(null, null);
		}
		public static ConsoleService NewLocalConsoleService(string outFileName)
		{
			return NewLocalConsoleService(null, outFileName);
		}
		public static ConsoleService NewLocalConsoleService(string inFileName, string outFileName)
		{
			IO in_io = null, out_io = null;

			ConsoleService c = new ConsoleService();
			int old_size = 0;

			c.consoleType = ConsoleType.Local;
			c.free = new ConsoleFreeDelegate(c.localFree);
			c.readLine = new ConsoleReadLineDelegate(c.localReadLine);
			c.readPassword = new ConsoleReadPasswordDelegate(c.localReadPassword);
			c.write = new ConsoleWriteDelegate(c.localWrite);
			c.getWidth = new ConsoleGetWidthDelegate(c.localGetWidth);

			if (Str.IsEmptyStr(inFileName) == false)
			{
				try
				{
					in_io = IO.FileOpen(inFileName, false);
				}
				catch
				{
					c.write(Str.FormatC(Resources.CON_INFILE_ERROR, inFileName));
					return null;
				}
				c.write(Str.FormatC(Resources.CON_INFILE_START, inFileName));
			}

			if (Str.IsEmptyStr(outFileName) == false)
			{
				try
				{
					out_io = IO.FileCreate(outFileName);
				}
				catch
				{
					c.write(Str.FormatC(Resources.CON_OUTFILE_ERROR, outFileName));
					if (in_io != null)
					{
						in_io.Close();
					}

					return null;
				}
				c.write(Str.FormatC(Resources.CON_OUTFILE_START, outFileName));
			}

			c.inFile = in_io;
			c.outFile = out_io;
			c.win32_OldConsoleWidth = old_size;

			if (in_io != null)
			{
				byte[] data = in_io.ReadAll();

				c.inBuf = new Buf(data);
			}

			Con.SetConsoleService(c);

			return c;
		}

		void localFree()
		{
			if (inFile != null)
			{
				inFile.Close();
				inFile = null;
			}

			if (outFile != null)
			{
				outFile.Close();
				outFile = null;
			}
		}

		int localGetWidth()
		{
			int ret = Console.WindowWidth;

			if (ret <= 0)
			{
				ret = 1;
			}

			return ret;
		}

		string localReadLine(string prompt, bool noFile)
		{
			string ret;
			if (prompt == null)
			{
				prompt = ">";
			}

			writeOutFile(prompt, false);

			if (noFile == false && inBuf != null)
			{
				ret = readNextFromInFile();

				if (ret != null)
				{
					Console.Write(prompt);

					Console.WriteLine(ret);
				}
			}
			else
			{
				Console.Write(prompt);
				ret = Console.ReadLine();

				if (ret != null)
				{
					if (ret.IndexOf((char)0x04) != -1 || ret.IndexOf((char)0x1a) != -1)
					{
						ret = null;
					}
				}
			}

			if (ret != null)
			{
				writeOutFile(ret, true);
			}
			else
			{
				writeOutFile("[EOF]", true);
			}

			return ret;
		}

		string localReadPassword(string prompt)
		{
			if (prompt == null)
			{
				prompt = "Password>";
			}

			Console.Write(prompt);
			writeOutFile(prompt, false);

			string tmp = Str.PasswordPrompt();
			if (tmp != null)
			{
				writeOutFile("********", true);
				return tmp;
			}

			return null;
		}

		bool localWrite(string str)
		{
			Console.Write("{0}{1}",
				str,
				(str.EndsWith("\n") ? "" : "\n"));

			writeOutFile(str, true);

			return true;
		}

		string readNextFromInFile()
		{
			if (inBuf == null)
			{
				return null;
			}

			while (true)
			{
				string str = inBuf.ReadNextLineAsString();
				if (str == null)
				{
					return null;
				}

				str = str.Trim();

				if (Str.IsEmptyStr(str) == false)
				{
					return str;
				}
			}
		}

		void writeOutFile(string str, bool addLastCrlf)
		{
			if (outFile != null)
			{
				string tmp = Str.NormalizeCrlf(str);

				outFile.Write(Str.Utf8Encoding.GetBytes(str));

				if (str.EndsWith("\n") == false && addLastCrlf)
				{
					outFile.Write(Str.Utf8Encoding.GetBytes(Env.NewLine));
				}

				outFile.Flush();
			}
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
