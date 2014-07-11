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
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;
using System.Xml.Serialization;
using System.Web.Mail;
using System.Runtime.InteropServices;

namespace CoreUtil
{
	[FlagsAttribute]
	public enum PrintFFLags
	{
		Minus = 1,
		Plus = 2,
		Zero = 4,
		Blank = 8,
		Sharp = 16,
	}

	public class PrintFParsedParam
	{
		public bool Ok = false;
		public readonly PrintFFLags Flags = 0;
		public readonly int Width = 0;
		public readonly int Precision = 0;
		public readonly bool NoPrecision = true;
		public readonly string Type = "";

		static PrintFFLags charToFlag(char c)
		{
			switch (c)
			{
				case '-':
					return PrintFFLags.Minus;

				case '+':
					return PrintFFLags.Plus;

				case '0':
					return PrintFFLags.Zero;

				case ' ':
					return PrintFFLags.Blank;

				case '#':
					return PrintFFLags.Sharp;
			}

			return 0;
		}

		public string GetString(object param)
		{
			int i;
			StringBuilder sb;
			string tmp = "(error)";
			double f;
			bool signed = false;

			switch (this.Type)
			{
				case "c":
				case "C":
					if (param is char)
					{
						tmp += (char)param;
					}
					else if (param is string)
					{
						string s = (string)param;
						if (s.Length >= 1)
						{
							tmp += s[0];
						}
					}
					break;

				case "d":
				case "i":
					sb = new StringBuilder();
					int count = this.Width;
					if (this.Precision != 0)
					{
						count = this.Precision;
					}
					for (i = 1; i < this.Precision; i++)
					{
						sb.Append("#");
					}
					sb.Append("0");

					if (param is int)
					{
						tmp = ((int)param).ToString(sb.ToString());
					}
					else if (param is long)
					{
						tmp = ((long)param).ToString(sb.ToString());
					}
					else if (param is uint)
					{
						tmp = ((int)((uint)param)).ToString(sb.ToString());
					}
					else if (param is ulong)
					{
						tmp = ((long)((ulong)param)).ToString(sb.ToString());
					}
					else if (param is decimal)
					{
						tmp = ((decimal)param).ToString(sb.ToString());
					}
					signed = true;

					break;

				case "u":
					sb = new StringBuilder();
					for (i = 1; i < this.Precision; i++)
					{
						sb.Append("#");
					}
					sb.Append("0");

					if (param is int)
					{
						tmp = ((uint)((int)param)).ToString(sb.ToString());
					}
					else if (param is long)
					{
						tmp = ((ulong)((long)param)).ToString(sb.ToString());
					}
					else if (param is uint)
					{
						tmp = ((uint)param).ToString(sb.ToString());
					}
					else if (param is ulong)
					{
						tmp = ((ulong)param).ToString(sb.ToString());
					}
					else if (param is decimal)
					{
						tmp = ((decimal)param).ToString(sb.ToString());
					}

					break;

				case "x":
				case "X":
					sb = new StringBuilder();
					sb.Append(this.Type);
					sb.Append(this.Precision.ToString());

					if (param is int)
					{
						tmp = ((uint)((int)param)).ToString(sb.ToString());
					}
					else if (param is long)
					{
						tmp = ((ulong)((long)param)).ToString(sb.ToString());
					}
					else if (param is uint)
					{
						tmp = ((uint)param).ToString(sb.ToString());
					}
					else if (param is ulong)
					{
						tmp = ((ulong)param).ToString(sb.ToString());
					}

					break;

				case "e":
				case "E":
				case "f":
					f = 0;

					if (param is int)
					{
						f = (double)((int)param);
					}
					else if (param is long)
					{
						f = (double)((long)param);
					}
					else if (param is uint)
					{
						f = (double)((uint)param);
					}
					else if (param is ulong)
					{
						f = (double)((ulong)param);
					}
					else if (param is decimal)
					{
						f = (double)((long)param);
					}
					else if (param is float)
					{
						f = (double)((float)param);
					}
					else if (param is double)
					{
						f = (double)param;
					}
					else
					{
						break;
					}

					int prectmp = Precision;
					if (prectmp == 0 && NoPrecision)
					{
						prectmp = 6;
					}

					tmp = f.ToString(string.Format("{0}{1}", Type, prectmp));

					break;

				case "s":
				case "S":
					if (param == null)
					{
						tmp = "(null)";
					}
					else
					{
						tmp = param.ToString();
					}
					break;
			}

			int normalWidth = Str.GetStrWidth(tmp);
			int targetWidth = Math.Max(this.Width, normalWidth);

			if ((this.Flags & PrintFFLags.Plus) != 0)
			{
				if (signed)
				{
					if (tmp.StartsWith("-") == false)
					{
						tmp = "+" + tmp;
					}
				}
			}
			else
			{
				if ((this.Flags & PrintFFLags.Blank) != 0)
				{
					if (signed)
					{
						if (tmp.StartsWith("-") == false)
						{
							tmp = " " + tmp;
						}
					}
				}
			}

			if ((this.Flags & PrintFFLags.Minus) != 0)
			{
				int w = targetWidth - Str.GetStrWidth(tmp);
				if (w < 0)
				{
					w = 0;
				}

				tmp += Str.MakeCharArray(' ', w);
			}
			else if ((this.Flags & PrintFFLags.Zero) != 0)
			{
				int w = targetWidth - Str.GetStrWidth(tmp);
				if (w < 0)
				{
					w = 0;
				}

				tmp = Str.MakeCharArray('0', w) + tmp;
			}
			else
			{
				int w = targetWidth - Str.GetStrWidth(tmp);
				if (w < 0)
				{
					w = 0;
				}

				tmp = Str.MakeCharArray(' ', w) + tmp;
			}

			if ((this.Flags & PrintFFLags.Sharp) != 0)
			{
				if (Type == "x" || Type == "X")
				{
					tmp = "0x" + tmp;
				}
			}

			return tmp;
		}

		public PrintFParsedParam(string str)
		{
			Str.NormalizeString(ref str);

			if (str.StartsWith("%") == false)
			{
				return;
			}

			str = str.Substring(1);

			Queue<char> q = new Queue<char>();
			foreach (char c in str)
			{
				q.Enqueue(c);
			}

			while (q.Count >= 1)
			{
				char c = q.Peek();
				PrintFFLags f = charToFlag(c);

				if (f == 0)
				{
					break;
				}

				this.Flags |= f;
				q.Dequeue();
			}

			Queue<char> q2 = new Queue<char>();

			while (q.Count >= 1)
			{
				bool bf = false;
				char c = q.Peek();

				switch (c)
				{
					case 'h':
					case 'l':
					case 'I':
					case 'c':
					case 'C':
					case 'd':
					case 'i':
					case 'o':
					case 'u':
					case 'x':
					case 'X':
					case 'e':
					case 'E':
					case 'f':
					case 'g':
					case 'G':
					case 'n':
					case 'p':
					case 's':
					case 'S':
						bf = true;
						break;

					default:
						q2.Enqueue(c);
						break;
				}

				if (bf)
				{
					break;
				}

				q.Dequeue();
			}

			string[] widthAndPrec = (new string(q2.ToArray())).Split('.');

			if (widthAndPrec.Length == 1)
			{
				this.Width = Str.StrToInt(widthAndPrec[0]);
			}
			else if (widthAndPrec.Length == 2)
			{
				this.Width = Str.StrToInt(widthAndPrec[0]);
				this.Precision = Str.StrToInt(widthAndPrec[1]);
				this.NoPrecision = false;
			}

			this.Width = Math.Max(this.Width, 0);
			this.Precision = Math.Max(this.Precision, 0);


			while (q.Count >= 1)
			{
				char c = q.Peek();
				bool bf = false;

				switch (c)
				{
					case 'c':
					case 'C':
					case 'd':
					case 'i':
					case 'o':
					case 'u':
					case 'x':
					case 'X':
					case 'e':
					case 'E':
					case 'f':
					case 'g':
					case 'G':
					case 'a':
					case 'A':
					case 'n':
					case 'p':
					case 's':
					case 'S':
						bf = true;
						break;

					default:
						break;
				}

				if (bf)
				{
					break;
				}

				q.Dequeue();
			}

			this.Type = new string(q.ToArray());
			if (this.Type.Length >= 1)
			{
				this.Type = this.Type.Substring(0, 1);
			}

			this.Ok = (Str.IsEmptyStr(this.Type) == false);
		}
	}

	public class StrEqualityComparer : IEqualityComparer<string>
	{
		bool caseSensitive;

		public StrEqualityComparer()
		{
			this.caseSensitive = false;
		}

		public StrEqualityComparer(bool caseSensitive)
		{
			this.caseSensitive = caseSensitive;
		}

		public bool Equals(string x, string y)
		{
			return x.Equals(y, caseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase);
		}

		public int GetHashCode(string obj)
		{
			return obj.GetHashCode();
		}
	}


	public class StrComparer : IComparer<string>
	{
		bool caseSensitive;

		public StrComparer()
		{
			this.caseSensitive = false;
		}

		public StrComparer(bool caseSensitive)
		{
			this.caseSensitive = caseSensitive;
		}

		public int Compare(string x, string y)
		{
			return string.Compare(x, y, !caseSensitive);
		}
	}

	public delegate bool RemoveStringFunction(string str);

	public static class Str
	{
		public static string NormalizeStrSoftEther(string str)
		{
			return NormalizeStrSoftEther(str, false);
		}
		public static string NormalizeStrSoftEther(string str, bool trim)
		{
			bool b = false;
			StringReader sr = new StringReader(str);
			StringWriter sw = new StringWriter();
			while (true)
			{
				string line = sr.ReadLine();
				if (line == null)
				{
					break;
				}
				if (b)
				{
					sw.WriteLine();
				}
				b = true;
				line = normalizeStrSoftEtherInternal(line);
				sw.Write(line);
			}

			int len = str.Length;

			try
			{
				if (str[len - 1] == '\n' || str[len - 1] == '\r')
				{
					sw.WriteLine();
				}
			}
			catch
			{
			}

			str = sw.ToString();

			if (trim)
			{
				str = str.Trim();
			}

			return str;
		}
		static string normalizeStrSoftEtherInternal(string str)
		{
			if (str.Trim().Length == 0)
			{
				return "";
			}

			int i;
			StringBuilder sb1 = new StringBuilder();
			for (i = 0; i < str.Length; i++)
			{
				char c = str[i];

				if (c == ' ' || c == '　' || c == '\t')
				{
					sb1.Append(c);
				}
				else
				{
					break;
				}
			}
			string str2 = str.Substring(i).Trim();

			string str1 = sb1.ToString();

			str1 = ReplaceStr(str1, "　", "  ");
			str1 = ReplaceStr(str1, "\t", "    ");

			return str1 + normalizeStrSoftEtherInternal2(str2);
		}
		static string normalizeStrSoftEtherInternal2(string str)
		{
			NormalizeString(ref str, true, true, false, true);
			char[] chars = str.ToCharArray();
			StringBuilder sb = new StringBuilder();

			int i;
			for (i = 0; i < chars.Length; i++)
			{
				char c = chars[i];
				bool insert_space = false;
				bool insert_space2 = false;

				char c1 = (char)0;
				if (i >= 1)
				{
					c1 = chars[i - 1];
				}

				char c2 = (char)0;
				if (i < (chars.Length - 1))
				{
					c2 = chars[i + 1];
				}

				if (c == '\'' || c1 == '\'' || c2 == '\'' || c == '\"' || c1 == '\"' || c2 == '\"' || c == '>' || c1 == '>' || c2 == '>' || c == '<' || c1 == '<' || c2 == '<')
				{
				}
				else if (c == '(' || c == '[' || c == '{' || c == '<')
				{
					if (c1 != '「' && c1 != '『' && c1 != '。' && c1 != '、' && c1 != '・')
					{
						insert_space = true;
					}
				}
				else if (c == ')' || c == ']' || c == '}' || c == '>')
				{
					if (c2 != '.' && c2 != ',' && c2 != '。' && c2 != '、')
					{
						insert_space2 = true;
					}
				}
				else if (c == '～')
				{
					if (c1 != '～')
					{
						insert_space = true;
					}

					if (c2 != '～')
					{
						insert_space2 = true;
					}
				}
				else if (IsZenkaku(c) == false)
				{
					if (IsZenkaku(c1))
					{
						if (c != '.' && c != ',' && c != ';' && c != ':' && c1 != '※' && c1 != '〒' && c1 != '℡' && c1 != '「' && c1 != '『' && c1 != '。' && c1 != '、' && c1 != '・')
						{
							insert_space = true;
						}
					}
				}
				else
				{
					if (IsZenkaku(c1) == false)
					{
						if (c != '。' && c != '、' && c != '」' && c != '』' && c != '・' && c1 != '(' && c1 != '[' && c1 != '{' && c1 != '<' && c1 != ';' && c1 != ':')
						{
							insert_space = true;
						}
					}
				}

				if (insert_space)
				{
					sb.Append(' ');
				}

				sb.Append(c);

				if (insert_space2)
				{
					sb.Append(' ');
				}
			}

			str = sb.ToString();

			NormalizeString(ref str, true, true, false, true);

			return str;
		}

		public static bool IsZenkaku(char c)
		{
			return !((c >= (char)0) && (c <= (char)256));
		}

		public static string[] DivideStringMulti(string str, bool caseSensitive, params string[] keywords)
		{
			List<string> ret = new List<string>();
			int next = 0;

			while (true)
			{
				int foundIndex;
				string foundKeyword;
				int r = Str.SearchStrMulti(str, next, caseSensitive, out foundIndex, out foundKeyword, keywords);
				if (r == -1)
				{
					ret.Add(str.Substring(next));
					break;
				}
				else
				{
					ret.Add(str.Substring(next, r - next));
					ret.Add(foundKeyword);
					next = r + foundKeyword.Length;
				}
			}

			return ret.ToArray();
		}

		public static bool IsSuitableEncodingForString(string str, Encoding enc)
		{
			try
			{
				str = Str.NormalizeCrlf(str);

				byte[] utf1 = Str.Utf8Encoding.GetBytes(str);

				byte[] b = enc.GetBytes(str);
				string str2 = enc.GetString(b);

				byte[] utf2 = Str.Utf8Encoding.GetBytes(str2);

				return Util.CompareByte(utf1, utf2);
			}
			catch
			{
				return false;
			}
		}

		public static bool IsCharNumOrAlpha(char c)
		{
			if (c >= 'a' && c <= 'z')
			{
				return true;
			}
			if (c >= 'A' && c <= 'Z')
			{
				return true;
			}
			if (c >= '0' && c <= '9')
			{
				return true;
			}
			return false;
		}
		public static bool IsStringNumOrAlpha(string s)
		{
			foreach (char c in s)
			{
				if (IsCharNumOrAlpha(c) == false)
				{
					return false;
				}
			}
			return true;
		}

		public static string[] StrToStrLineBySplitting(string str)
		{
			StringReader r = new StringReader(str);
			List<string> ret = new List<string>();

			while (true)
			{
				string line = r.ReadLine();
				if (line == null)
				{
					break;
				}

				if (IsEmptyStr(line) == false)
				{
					ret.Add(line.Trim());
				}
			}

			return ret.ToArray();
		}

		public static string GetLeft(string str, int len)
		{
			if (str == null)
			{
				return null;
			}
			if (str.Length > len)
			{
				return str.Substring(0, len);
			}
			else
			{
				return str;
			}
		}

		public static string[] SplitStringForSearch(string str)
		{
			bool b = false;
			int i, len;
			len = str.Length;
			List<string> ret = new List<string>();
			string currentStr = "";

			for (i = 0; i < len; i++)
			{
				char c = str[i];

				if (c == '\"')
				{
					b = !b;
					if (b == false)
					{
						currentStr = currentStr.Trim();
						if (Str.IsEmptyStr(currentStr) == false)
						{
							ret.Add(currentStr);
							currentStr = "";
						}
					}
				}
				else
				{
					if (b == false && (c == ' ' || c == '　' || c == '\t'))
					{
						currentStr = currentStr.Trim();
						if (Str.IsEmptyStr(currentStr) == false)
						{
							ret.Add(currentStr);
							currentStr = "";
						}
					}
					else
					{
						currentStr += c;
					}
				}
			}

			currentStr = currentStr.Trim();
			if (Str.IsEmptyStr(currentStr) == false)
			{
				ret.Add(currentStr);
			}

			return ret.ToArray();
		}

		public static string AppendZeroToNumString(string str, int numKeta)
		{
			int n = numKeta - str.Length;

			if (n >= 1)
			{
				return MakeCharArray('0', n) + str;
			}
			else
			{
				return str;
			}
		}

		public static Encoding CheckBOM(byte[] data)
		{
			int i;
			return CheckBOM(data, out i);
		}
		public static Encoding CheckBOM(byte[] data, out int bomNumBytes)
		{
			bomNumBytes = 0;
			try
			{
				if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0xfe && data[3] == 0xff)
				{
					bomNumBytes = 3;
					return Encoding.GetEncoding("utf-32BE");
				}
				else if (data[0] == 0xff && data[1] == 0xfe && data[2] == 0x00 && data[3] == 0x00)
				{
					bomNumBytes = 4;
					return Encoding.GetEncoding("utf-32");
				}
				else if (data[0] == 0xff && data[1] == 0xfe)
				{
					bomNumBytes = 2;
					return Encoding.GetEncoding("utf-16");
				}
				else if (data[0] == 0xfe && data[1] == 0xff)
				{
					bomNumBytes = 2;
					return Encoding.GetEncoding("unicodeFFFE");
				}
				else if (data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
				{
					bomNumBytes = 3;
					return Encoding.GetEncoding("utf-8");
				}
				else
				{
					return null;
				}
			}
			catch
			{
				return null;
			}
		}

		public static byte[] GetBOM(Encoding encoding)
		{
			if (Str.StrCmpi(encoding.BodyName, "utf-32BE"))
			{
				return new byte[] { 0x00, 0x00, 0xfe, 0xff };
			}
			else if (Str.StrCmpi(encoding.BodyName, "utf-32"))
			{
				return new byte[] {0xff, 0xfe, 0x00, 0x00 };
			}
			else if (Str.StrCmpi(encoding.BodyName, "utf-16"))
			{
				return new byte[] { 0xff, 0xfe };
			}
			else if (Str.StrCmpi(encoding.BodyName, "unicodeFFFE"))
			{
				return new byte[] { 0xfe, 0xff };
			}
			else if (Str.StrCmpi(encoding.BodyName, "utf-8"))
			{
				return new byte[] { 0xef, 0xbb, 0xbf };
			}
			else
			{
				return null;
			}
		}

		public static byte[] ConvertEncoding(byte[] srcData, Encoding destEncoding)
		{
			return ConvertEncoding(srcData, destEncoding, false);
		}
		public static byte[] ConvertEncoding(byte[] srcData, Encoding destEncoding, bool appendBom)
		{
			Encoding srcEncoding = GetEncoding(srcData);
			if (srcEncoding == null)
			{
				srcEncoding = Str.ShiftJisEncoding;
			}

			int nb;
			if (CheckBOM(srcData, out nb) != null)
			{
				srcData = Util.RemoveStartByteArray(srcData, nb);
			}

			string str = srcEncoding.GetString(srcData);

			byte[] b1 = null;
			if (appendBom)
			{
				b1 = GetBOM(destEncoding);
			}
			byte[] b2 = destEncoding.GetBytes(str);

			return Util.CombineByteArray(b1, b2);
		}

		public static string ReadTextFile(string filename)
		{
			byte[] data = IO.ReadFileData(filename);
			int bomSize = 0;

			Encoding enc = GetEncoding(data, out bomSize);
			if (enc == null)
			{
				enc = Str.Utf8Encoding;
			}
			if (bomSize >= 1)
			{
				data = Util.CopyByte(data, bomSize);
			}

			return enc.GetString(data);
		}

		public static void WriteTextFile(string filename, Encoding enc, bool writeBom)
		{
			Buf buf = new Buf();
			byte[] bom = GetBOM(enc);
			if (writeBom && bom != null && bom.Length >= 1)
			{
				buf.Write(bom);
			}
			buf.Write(enc.GetBytes(filename));

			buf.SeekToBegin();

			File.WriteAllBytes(filename, buf.Read());
		}

		public static Encoding GetEncoding(byte[] data)
		{
			int i;
			return GetEncoding(data, out i);
		}
		public static Encoding GetEncoding(byte[] data, out int bomSize)
		{
			const byte bESC = 0x1B;
			const byte bAT = 0x40;
			const byte bDollar = 0x24;
			const byte bAnd = 0x26;
			const byte bOP = 0x28;
			const byte bB = 0x42;
			const byte bD = 0x44;
			const byte bJ = 0x4A;
			const byte bI = 0x49;
			bomSize = 0;

			int len = data.Length;
			int binary = 0;
			int ucs2 = 0;
			int sjis = 0;
			int euc = 0;
			int utf8 = 0;
			byte b1, b2;

			Encoding bomEncoding = CheckBOM(data, out bomSize);
			if (bomEncoding != null)
			{
				return bomEncoding;
			}

			for (int i = 0; i < len; i++)
			{
				if (data[i] <= 0x06 || data[i] == 0x7F || data[i] == 0xFF)
				{
					//'binary'
					binary++;
					if (len - 1 > i && data[i] == 0x00
						&& i > 0 && data[i - 1] <= 0x7F)
					{
						//smells like raw unicode
						ucs2++;
					}
				}
			}


			if (binary > 0)
			{
				if (ucs2 > 0)
				{
					//JIS
					//ucs2(Unicode)

					int n1 = 0, n2 = 0;
					for (int i = 0; i < (len / 2); i++)
					{
						byte e1 = data[i * 2];
						byte e2 = data[i * 2 + 1];

						if (e1 == 0 && e2 != 0)
						{
							n1++;
						}
						else if (e1 != 0 && e2 == 0)
						{
							n2++;
						}
					}

					if (n1 > n2)
					{
						return Encoding.GetEncoding("unicodeFFFE");
					}
					else
					{
						return System.Text.Encoding.Unicode;
					}
				}
				else
				{
					//binary
					return null;
				}
			}

			for (int i = 0; i < len - 1; i++)
			{
				b1 = data[i];
				b2 = data[i + 1];

				if (b1 == bESC)
				{
					if (b2 >= 0x80)
						//not Japanese
						//ASCII
						return System.Text.Encoding.ASCII;
					else if (len - 2 > i &&
						b2 == bDollar && data[i + 2] == bAT)
						//JIS_0208 1978
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
					else if (len - 2 > i &&
						b2 == bDollar && data[i + 2] == bB)
						//JIS_0208 1983
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
					else if (len - 5 > i &&
						b2 == bAnd && data[i + 2] == bAT && data[i + 3] == bESC &&
						data[i + 4] == bDollar && data[i + 5] == bB)
						//JIS_0208 1990
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
					else if (len - 3 > i &&
						b2 == bDollar && data[i + 2] == bOP && data[i + 3] == bD)
						//JIS_0212
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
					else if (len - 2 > i &&
						b2 == bOP && (data[i + 2] == bB || data[i + 2] == bJ))
						//JIS_ASC
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
					else if (len - 2 > i &&
						b2 == bOP && data[i + 2] == bI)
						//JIS_KANA
						//JIS
						return System.Text.Encoding.GetEncoding(50220);
				}
			}

			for (int i = 0; i < len - 1; i++)
			{
				b1 = data[i];
				b2 = data[i + 1];
				if (((b1 >= 0x81 && b1 <= 0x9F) || (b1 >= 0xE0 && b1 <= 0xFC)) &&
					((b2 >= 0x40 && b2 <= 0x7E) || (b2 >= 0x80 && b2 <= 0xFC)))
				{
					sjis += 2;
					i++;
				}
			}
			for (int i = 0; i < len - 1; i++)
			{
				b1 = data[i];
				b2 = data[i + 1];
				if (((b1 >= 0xA1 && b1 <= 0xFE) && (b2 >= 0xA1 && b2 <= 0xFE)) ||
					(b1 == 0x8E && (b2 >= 0xA1 && b2 <= 0xDF)))
				{
					euc += 2;
					i++;
				}
				else if (len - 2 > i &&
					b1 == 0x8F && (b2 >= 0xA1 && b2 <= 0xFE) &&
					(data[i + 2] >= 0xA1 && data[i + 2] <= 0xFE))
				{
					euc += 3;
					i += 2;
				}
			}
			for (int i = 0; i < len - 1; i++)
			{
				b1 = data[i];
				b2 = data[i + 1];
				if ((b1 >= 0xC0 && b1 <= 0xDF) && (b2 >= 0x80 && b2 <= 0xBF))
				{
					utf8 += 2;
					i++;
				}
				else if (len - 2 > i &&
					(b1 >= 0xE0 && b1 <= 0xEF) && (b2 >= 0x80 && b2 <= 0xBF) &&
					(data[i + 2] >= 0x80 && data[i + 2] <= 0xBF))
				{
					utf8 += 3;
					i += 2;
				}
			}

			if (euc > sjis && euc > utf8)
				//EUC
				return System.Text.Encoding.GetEncoding(51932);
			else if (sjis > euc && sjis > utf8)
				//SJIS
				return System.Text.Encoding.GetEncoding(932);
			else if (utf8 > euc && utf8 > sjis)
				//UTF8
				return System.Text.Encoding.UTF8;

			return null;
		}

		public static bool StartsWithMulti(string str, StringComparison comp, params string[] keys)
		{
			NormalizeString(ref str);

			foreach (string key in keys)
			{
				if (str.StartsWith(key, comp))
				{
					return true;
				}
			}

			return false;
		}

		public static bool IsCharForMail(char c)
		{
			switch (c)
			{
				case '<':
				case '>':
				case ' ':
				case ';':
				case ':':
				case '/':
				case '(':
				case ')':
				case '&':
				case ',':
				case '%':
				case '$':
				case '#':
				case '\"':
				case '\'':
				case '!':
				case '=':
				case '\\':
					return false;
			}

			if (c >= 0x80)
			{
				return false;
			}

			if (IsAscii(c) == false)
			{
				return false;
			}

			return true;
		}

		public static string LinkMailtoOnText(string text)
		{
			NormalizeString(ref text);

			StringBuilder sb = new StringBuilder();

			string tmp = "";

			int i;
			for (i = 0; i < text.Length; i++)
			{
				char c = text[i];

				if (IsCharForMail(c) == false)
				{
					if (Str.CheckMailAddress(tmp) == false)
					{
						tmp += c;
						sb.Append(tmp);
						tmp = "";
					}
					else
					{
						sb.AppendFormat("<a href=\"mailto:{0}\">{0}</a>", tmp);
						sb.Append(c);
						tmp = "";
					}
				}
				else
				{
					tmp += c;
				}
			}
			if (Str.CheckMailAddress(tmp) == false)
			{
				sb.Append(tmp);
				tmp = "";
			}
			else
			{
				sb.AppendFormat("<a href=\"mailto:{0}\">{0}</a>", tmp);
				tmp = "";
			}

			return sb.ToString();
		}

		public static string LinkUrlOnText(string text, string target)
		{
			int findStart = 0;

			NormalizeString(ref text);
			NormalizeString(ref target);

			StringBuilder sb = new StringBuilder();

			while (true)
			{
				int foundStrIndex;
				int foundIndex = FindStrings(text, findStart, StringComparison.InvariantCultureIgnoreCase, out foundStrIndex,
					"http://", "https://", "ftp://", "telnet://", "mailto://", "news://");

				if (foundIndex != -1)
				{
					int i;
					int endOfUrl = -1;
					for (i = foundIndex; i < text.Length; i++)
					{
						char c = text[i];

						if (IsValidForUrl(c) == false)
						{
							endOfUrl = i;
							break;
						}

						if (c == '<' || c == '&')
						{
							if (StartsWithMulti(text.Substring(i), StringComparison.InvariantCultureIgnoreCase,
								HtmlSpacing, HtmlCrlf, HtmlBr, HtmlLt, HtmlGt))
							{
								endOfUrl = i;
								break;
							}
						}
					}

					if (endOfUrl == -1)
					{
						endOfUrl = text.Length;
					}

					string url = text.Substring(foundIndex, endOfUrl - foundIndex);
					string beforeUrl = text.Substring(findStart, foundIndex - findStart);

					sb.Append(beforeUrl);

					if (Str.IsEmptyStr(target) == false)
					{
						sb.AppendFormat("<a href=\"{0}\" target=\"{2}\">{1}</a>", url, url, target);
					}
					else
					{
						sb.AppendFormat("<a href=\"{0}\">{1}</a>", url, url);
					}

					findStart = endOfUrl;
				}
				else
				{
					sb.Append(text.Substring(findStart));

					break;
				}
			}

			return LinkMailtoOnText(sb.ToString());
		}

		public static int FindStrings(string str, int findStartIndex, StringComparison comp, out int foundKeyIndex, params string[] keys)
		{
			int ret = -1;
			foundKeyIndex = -1;
			int n = 0;

			foreach (string key in keys)
			{
				int i = str.IndexOf(key, findStartIndex, comp);

				if (i != -1)
				{
					if (ret == -1)
					{
						ret = i;
						foundKeyIndex = n;
					}
					else
					{
						if (ret > i)
						{
							ret = i;
							foundKeyIndex = n;
						}
					}
				}

				n++;
			}

			return ret;
		}

		public static bool IsValidForUrl(char c)
		{
			if (c >= '0' && c <= '9')
			{
				return true;
			}
			if (c >= 'a' && c <= 'z')
			{
				return true;
			}
			if (c >= 'A' && c <= 'Z')
			{
				return true;
			}
			switch (c)
			{
				case '_':
				case '-':
				case '?':
				case '!':
				case '\"':
				case ',':
				case '\'':
				case '/':
				case '\\':
				case '&':
				case ';':
				case '%':
				case '#':
				case '@':
				case '~':
				case ':':
				case '=':
				case '+':
				case '*':
				case '$':
				case '.':
					return true;
			}

			return false;
		}

		public static List<string> RemoteStringFromList(List<string> str, RemoveStringFunction func)
		{
			List<string> ret = new List<string>();

			foreach (string s in str)
			{
				if (func(s) == false)
				{
					ret.Add(s);
				}
			}

			return ret;
		}

		public const string ConstZenkaku = "｀｛｝０１２３４５６７８９／＊－＋！”＃＄％＆’（）＝￣｜￥［］＠；：＜＞？＿＾　ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ‘";
		public const string ConstHankaku = "`{}0123456789/*-+!\"#$%&'()=~|\\[]@;:<>?_^ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'";
		public const string ConstKanaZenkaku = "ー「」アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンァゥェォャュョッィ゛゜";
		public const string ConstKanaHankaku = "ｰ｢｣ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝｧｩｪｫｬｭｮｯｨﾞﾟ";

		public static void RemoveSpace(ref string str)
		{
			NormalizeString(ref str);

			str = str.Replace(" ", "").Replace("　", "").Replace("\t", "");
		}

		public static void TrimStartWith(ref string str, string key, StringComparison sc)
		{
			if (str.StartsWith(key, sc))
			{
				str = str.Substring(key.Length);
			}
		}

		public static void TrimEndsWith(ref string str, string key, StringComparison sc)
		{
			if (str.EndsWith(key, sc))
			{
				str = str.Substring(0, str.Length - key.Length);
			}
		}

		public static void RemoveSpaceChar(ref string str)
		{
			if (Str.IsEmptyStr(str))
			{
				return;
			}

			StringBuilder sb = new StringBuilder();

			foreach (char c in str)
			{
				if (c == ' ' || c == '\t' || c == '　')
				{
				}
				else
				{
					sb.Append(c);
				}
			}

			str = sb.ToString();
		}

		public static void NormalizeStringStandard(ref string str)
		{
			NormalizeString(ref str, true, true, false, true);
		}
		public static void NormalizeString(ref string str, bool space, bool toHankaku, bool toZenkaku, bool toZenkakuKana)
		{
			NormalizeString(ref str);

			if (space)
			{
				str = NormalizeSpace(str);
			}

			if (toHankaku)
			{
				str = ZenkakuToHankaku(str);
			}

			if (toZenkaku)
			{
				str = HankakuToZenkaku(str);
			}

			if (toZenkakuKana)
			{
				str = KanaHankakuToZenkaku(str);
			}
		}

		public static string NormalizeSpace(string str)
		{
			NormalizeString(ref str);
			char[] sps =
			{
				' ', '　', '\t',
			};

			string[] tokens = str.Split(sps, StringSplitOptions.RemoveEmptyEntries);

			return Str.CombineStringArray(tokens, " ");
		}

		public static string KanaHankakuToZenkaku(string str)
		{
			NormalizeString(ref str);

			str = str.Replace("ｶﾞ", "ガ");
			str = str.Replace("ｷﾞ", "ギ");
			str = str.Replace("ｸﾞ", "グ");
			str = str.Replace("ｹﾞ", "ゲ");
			str = str.Replace("ｺﾞ", "ゴ");
			str = str.Replace("ｻﾞ", "ザ");
			str = str.Replace("ｼﾞ", "ジ");
			str = str.Replace("ｽﾞ", "ズ");
			str = str.Replace("ｾﾞ", "ゼ");
			str = str.Replace("ｿﾞ", "ゾ");
			str = str.Replace("ﾀﾞ", "ダ");
			str = str.Replace("ﾁﾞ", "ヂ");
			str = str.Replace("ﾂﾞ", "ヅ");
			str = str.Replace("ﾃﾞ", "デ");
			str = str.Replace("ﾄﾞ", "ド");
			str = str.Replace("ﾊﾞ", "バ");
			str = str.Replace("ﾋﾞ", "ビ");
			str = str.Replace("ﾌﾞ", "ブ");
			str = str.Replace("ﾍﾞ", "ベ");
			str = str.Replace("ﾎﾞ", "ボ");

			char[] a = str.ToCharArray();
			int i;
			for (i = 0; i < a.Length; i++)
			{
				int j = ConstKanaHankaku.IndexOf(a[i]);

				if (j != -1)
				{
					a[i] = ConstKanaZenkaku[j];
				}
			}

			return new string(a);
		}

		public static string ZenkakuToHankaku(string str)
		{
			NormalizeString(ref str);

			str = ReplaceStr(str, "“", " \"");
			str = ReplaceStr(str, "”", "\" ");
			str = ReplaceStr(str, "‘", "'");
			str = ReplaceStr(str, "’", "'");

			char[] a = str.ToCharArray();
			int i;
			for (i = 0; i < a.Length; i++)
			{
				int j = ConstZenkaku.IndexOf(a[i]);

				if (j != -1)
				{
					a[i] = ConstHankaku[j];
				}
			}

			return new string(a);
		}

		public static string HankakuToZenkaku(string str)
		{
			NormalizeString(ref str);

			str = KanaHankakuToZenkaku(str);

			char[] a = str.ToCharArray();
			int i;
			for (i = 0; i < a.Length; i++)
			{
				int j = ConstHankaku.IndexOf(a[i]);

				if (j != -1)
				{
					a[i] = ConstZenkaku[j];
				}
			}

			return new string(a);
		}

		public const string HtmlSpacing = "&nbsp;";
		public const string HtmlCrlf = "<BR>";
		public const string HtmlBr = "<BR>";
		public const string HtmlLt = "&lt;";
		public const string HtmlGt = "&gt;";
		public const string HtmlAmp = "&amp;";
		public const int HtmlNumTabChar = 8;
		public static string HtmlTab
		{
			get
			{
				int i;
				StringBuilder sb = new StringBuilder();
				for (i = 0; i < HtmlNumTabChar; i++)
				{
					sb.Append(HtmlSpacing);
				}
				return sb.ToString();
			}
		}

		public static string ToUrl(string str, Encoding e)
		{
			Str.NormalizeString(ref str);
			return HttpUtility.UrlEncode(str, e);
		}

		public static string FromUrl(string str, Encoding e)
		{
			Str.NormalizeString(ref str);
			return HttpUtility.UrlDecode(str, e);
		}

		public static string FromHtml(string str)
		{
			str = Str.ReplaceStr(str, HtmlCrlf, "\r\n", false);

			str = str.Replace(HtmlSpacing, " ");

			str = str.Replace(HtmlLt, "<").Replace(HtmlGt, ">").Replace(HtmlAmp, "&");

			str = NormalizeCrlf(str);

			return str;
		}

		public static string ToHtml(string str)
		{
			return ToHtml(str, false);
		}
		public static string ToHtml(string str, bool forceAllSpaceToTag)
		{
			str = NormalizeCrlf(str);

			str = str.Replace("&", HtmlAmp);

			str = str.Replace("<", HtmlLt).Replace(">", HtmlGt);

			if (str.IndexOf(' ') != -1)
			{
				if (forceAllSpaceToTag)
				{
					str = str.Replace(" ", HtmlSpacing);
				}
				else
				{
					int i;
					StringBuilder sb = new StringBuilder();
					bool flag = false;

					for (i = 0; i < str.Length; i++)
					{
						char c = str[i];

						if (c == ' ')
						{
							if (flag == false)
							{
								flag = true;
								sb.Append(' ');
							}
							else
							{
								sb.Append(HtmlSpacing);
							}
						}
						else
						{
							flag = false;
							sb.Append(c);
						}
					}

					str = sb.ToString();
				}
			}

			str = str.Replace("\t", HtmlTab);

			str = str.Replace("\r\n", HtmlCrlf);

			return str;
		}

		public static bool IsPrintable(char c)
		{
			if (c >= 256)
			{
				return true;
			}

			if (c >= 32 && c <= 126)
			{
				return true;
			}

			return false;
		}
		public static bool IsPrintable(string str)
		{
			foreach (char c in str)
			{
				if (IsPrintable(c) == false)
				{
					return false;
				}
			}

			return true;
		}

		public static string Unescape(string str)
		{
			StringBuilder sb = new StringBuilder();

			int i;
			for (i = 0; i < str.Length; i++)
			{
				char c = str[i];

				if (IsPrintable(c) && c != '\\')
				{
					sb.Append(c);
				}
				else
				{
					string s = "" + c;
					switch (c)
					{
						case '\r':
							s = "\\r";
							break;

						case '\n':
							s = "\\n";
							break;

						case '\0':
							s = "\\0";
							break;

						case '\t':
							s = "\\t";
							break;

						case '\\':
							s = "\\\\";
							break;

						default:
							s = "0x" + Convert.ToString((int)c, 16);
							break;
					}
					sb.Append(s);
				}
			}

			return sb.ToString();
		}

		public static string Escape(string str)
		{
			StringBuilder sb = new StringBuilder();

			int i, j, hex;
			string padding = "00000000";
			str = str + padding;
			StringBuilder sb2;

			for (i = 0; i < str.Length - padding.Length; i++)
			{
				char c = str[i];
				char d = c;

				if (c == '\\')
				{
					char c1 = str[i + 1];

					switch (c1)
					{
						case '\'':
							d = '\'';
							i++;
							break;

						case '?':
							d = '?';
							i++;
							break;

						case '\\':
							d = '\\';
							i++;
							break;

						case 't':
							d = '\t';
							i++;
							break;

						case 'r':
							d = '\r';
							i++;
							break;

						case 'n':
							d = '\n';
							i++;
							break;

						case ' ':
							d = ' ';
							i++;
							break;

						case '　':
							d = '　';
							i++;
							break;

						case '\t':
							d = '\t';
							i++;
							break;

						case '0':
							d = '\0';
							i++;
							break;

						case 'x':
							i++;
							sb2 = new StringBuilder();
							for (j = 0; j < 4; j++)
							{
								char c2 = str[++i];

								if ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'))
								{
									sb2.Append(c2);
								}
								else
								{
									i--;
									break;
								}
							}
							hex = Convert.ToInt32(sb2.ToString(), 16);
							d = (char)hex;
							break;

						default:
							if (c1 >= '0' && c1 <= '7')
							{
								sb2 = new StringBuilder();
								for (j = 0; j < 3; j++)
								{
									char c2 = str[++i];

									if (c2 >= '0' && c2 <= '7')
									{
										sb2.Append(c2);
									}
									else
									{
										i--;
										break;
									}
								}
								hex = Convert.ToInt32(sb2.ToString(), 8);
								d = (char)hex;
							}
							else
							{
								d = '\\';
								i++;
							}
							break;
					}
				}

				if (d != '\0')
				{
					sb.Append(d);
				}
				else
				{
					break;
				}
			}

			return sb.ToString();
		}

		public static int GetStrWidth(string str)
		{
			int ret = 0;
			foreach (char c in str)
			{
				if (c <= 255)
				{
					ret++;
				}
				else
				{
					ret += 2;
				}
			}
			return ret;
		}

		public static string TrimCrlf(string str)
		{
			int len;
			if (str == null)
			{
				return "";
			}
			len = str.Length;
			if (len == 0)
			{
				return "";
			}

			if (str[len - 1] == '\n')
			{
				if (len >= 2 && str[len - 2] == '\r')
				{
					str = str.Substring(0, len - 2);
				}

				str = str.Substring(0, len - 1);
			}
			else if (str[len - 1] == '\r')
			{
				str = str.Substring(0, len - 1);
			}

			return str;
		}

		public static bool IsAllUpperStr(string str)
		{
			int i, len;
			if (str == null)
			{
				return false;
			}

			len = str.Length;

			for (i = 0; i < len; i++)
			{
				char c = str[i];

				if ((c >= '0' && c <= '9') ||
					(c >= 'A' && c <= 'Z'))
				{
				}
				else
				{
					return false;
				}
			}

			return true;
		}

		public static List<string> StrArrayToList(string[] strArray)
		{
			List<string> ret = new List<string>();

			foreach (string s in strArray)
			{
				ret.Add(s);
			}

			return ret;
		}

		private static string[] __new_ParseCmdLine(string str)
		{
			List<string> o;
			int i, len, mode;
			char c;
			StringBuilder tmp;
			bool ignore_space = false;
			if (str == null)
			{
				return new string[0];
			}

			o = new List<string>();
			tmp = new StringBuilder();

			mode = 0;
			len = str.Length;
			for (i = 0; i < len; i++)
			{
				c = str[i];

				switch (mode)
				{
					case 0:
						if (c == ' ' || c == '\t')
						{
						}
						else
						{
							if (c == '\"')
							{
								if (str[i + 1] == '\"')
								{
									tmp.Append("\"");
									i++;
								}
								else
								{
									ignore_space = true;
								}
							}
							else
							{
								tmp.Append(c);
							}
						}

						mode = 1;
						break;

					case 1:
						if (ignore_space == false && (c == ' ' || c == '\t'))
						{
							o.Add(tmp.ToString());

							tmp = new StringBuilder();
							mode = 0;
						}
						else
						{
							if (c == '\"')
							{
								if (str[i + 1] == '\"')
								{
									tmp.Append("\"");
									i++;
								}
								else
								{
									if (ignore_space == false)
									{
										ignore_space = true;
									}
									else
									{
										ignore_space = false;
									}
								}
							}
							else
							{
								tmp.Append(c);
							}
						}
						break;

				}
			}

			if (tmp.Length >= 1)
			{
				o.Add(tmp.ToString());
			}

			List<string> ret = new List<string>();
			foreach (string s in o)
			{
				ret.Add(s);
			}

			return ret.ToArray();
		}

		public static int CompareString(string s1, string s2)
		{
			try
			{
				return string.Compare(s1, s2, true);
			}
			catch
			{
				return 0;
			}
		}
		public static int CompareStringCaseSensitive(string s1, string s2)
		{
			try
			{
				return string.Compare(s1, s2, false);
			}
			catch
			{
				return 0;
			}
		}

		public static string ReplaceStr(string str, string oldKeyword, string newKeyword)
		{
			return ReplaceStr(str, oldKeyword, newKeyword, false);
		}
		public static string ReplaceStr(string str, string oldKeyword, string newKeyword, bool caseSensitive)
		{
			int len_string, len_old, len_new;
			if (str == null || oldKeyword == null || newKeyword == null)
			{
				return null;
			}

			if (caseSensitive == false)
			{
				return str.Replace(oldKeyword, newKeyword);
			}

			int i, j, num;
			StringBuilder sb = new StringBuilder();

			len_string = str.Length;
			len_old = oldKeyword.Length;
			len_new = newKeyword.Length;

			i = j = num = 0;

			while (true)
			{
				i = SearchStr(str, oldKeyword, i, caseSensitive);
				if (i == -1)
				{
					sb.Append(str.Substring(j, len_string - j));
					break;
				}

				num++;

				sb.Append(str.Substring(j, i - j));
				sb.Append(newKeyword);

				i += len_old;
				j = i;
			}

			return sb.ToString();
		}

		public static int SearchStrMulti(string str, int start, bool caseSensitive, out int foundIndex, out string foundKeyword, params string[] keywords)
		{
			int i;
			foundIndex = -1;
			foundKeyword = "";
			int ret = -1;
			int min = int.MaxValue;
			for (i = 0; i < keywords.Length; i++)
			{
				string keyword = keywords[i];
				int r = Str.SearchStr(str, keyword, start, caseSensitive);
				if (r != -1)
				{
					if (min > r)
					{
						min = r;
						foundKeyword = str.Substring(r, keyword.Length);
						foundIndex = i;
					}
				}
			}

			if (foundIndex != -1)
			{
				ret = min;
			}

			return ret;
		}

		public static int SearchStr(string str, string keyword, int start)
		{
			return SearchStr(str, keyword, start, false);
		}
		public static int SearchStr(string str, string keyword, int start, bool caseSensitive)
		{
			if (str == null || keyword == null)
			{
				return -1;
			}

			try
			{
				return str.IndexOf(keyword, start, (caseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase));
			}
			catch
			{
				return -1;
			}
		}

		public static void Printf(string fmt, params object[] args)
		{
			if (args.Length == 0)
			{
				Console.Write(fmt);
			}
			else
			{
				Console.Write(FormatC(fmt, args));
			}
		}

		public static string FormatC(string fmt)
		{
			return FormatC(fmt, new object[0]);
		}
		public static string FormatC(string fmt, params object[] args)
		{
			int i, len;
			StringBuilder tmp;
			List<string> o;
			int mode = 0;
			int pos = 0;
			if (fmt == null)
			{
				return null;
			}

			len = fmt.Length;
			tmp = new StringBuilder();
			o = new List<string>();

			mode = 0;

			for (i = 0; i < len; i++)
			{
				char c = fmt[i];

				if (mode == 0)
				{
					switch (c)
					{
						case '%':
							if (fmt[i + 1] == '%')
							{
								i++;
								tmp.Append("%");
							}
							else
							{
								mode = 1;
								o.Add(tmp.ToString());
								tmp = new StringBuilder();

								tmp.Append(c);
							}
							break;

						default:
							tmp.Append(c);
							break;
					}
				}
				else
				{
					switch (c)
					{
						case 'c':
						case 'C':
						case 'd':
						case 'i':
						case 'o':
						case 'u':
						case 'x':
						case 'X':
						case 'e':
						case 'E':
						case 'f':
						case 'g':
						case 'G':
						case 'a':
						case 'A':
						case 'n':
						case 'p':
						case 's':
						case 'S':
							tmp.Append(c);

							PrintFParsedParam pp = new PrintFParsedParam(tmp.ToString());
							string s;
							if (pp.Ok)
							{
								s = pp.GetString(args[pos++]);
							}
							else
							{
								s = "(parse_error)";
							}

							o.Add(s);

							tmp = new StringBuilder();
							mode = 0;
							break;

						default:
							tmp.Append(c);
							break;
					}
				}
			}

			if (tmp.Length >= 1)
			{
				o.Add(tmp.ToString());
			}

			StringBuilder retstr = new StringBuilder();
			foreach (string stmp in o)
			{
				retstr.Append(stmp);
			}

			return retstr.ToString();
		}

		static Encoding asciiEncoding = Encoding.ASCII;
		public static Encoding AsciiEncoding
		{
			get { return asciiEncoding; }
		}

		static Encoding shiftJisEncoding = Encoding.GetEncoding("shift_jis");
		public static Encoding ShiftJisEncoding
		{
			get { return shiftJisEncoding; }
		}

		static Encoding iso2022JpEncoding = Encoding.GetEncoding("ISO-2022-JP");
		public static Encoding ISO2022JPEncoding
		{
			get { return iso2022JpEncoding; }
		}

		static Encoding eucJpEncoding = Encoding.GetEncoding("euc-jp");
		public static Encoding EucJpEncoding
		{
			get { return eucJpEncoding; }
		}

		static Encoding iso88591Encoding = Encoding.GetEncoding("iso-8859-1");
		public static Encoding ISO88591Encoding
		{
			get { return iso88591Encoding; }
		}

		static Encoding gb2312Encoding = Encoding.GetEncoding("gb2312");
		public static Encoding GB2312Encoding
		{
			get { return gb2312Encoding; }
		}

		static Encoding utf8Encoding = Encoding.UTF8;
		public static Encoding Utf8Encoding
		{
			get { return utf8Encoding; }
		}

		static Encoding uniEncoding = Encoding.Unicode;
		public static Encoding UniEncoding
		{
			get { return uniEncoding; }
		}

		public static void NormalizeString(ref string str)
		{
			if (str == null)
			{
				str = "";
			}

			str = str.Trim();
		}

		public static string PasswordPrompt()
		{
			Queue<char> ret = new Queue<char>();
			bool escape = false;

			while (true)
			{
				ConsoleKeyInfo ki = Console.ReadKey(true);
				char c = ki.KeyChar;

				if (c >= 0x20 && c <= 0x7e)
				{
					ret.Enqueue(c);
					Console.Write("*");
				}
				else if (c == 0x04 || c == 0x1a || c == 0x0d || c == 0x0a)
				{
					if (c == 0x04 || c == 0x1a)
					{
						escape = true;
					}
					break;
				}
				else if (c == 0x08)
				{
					Console.Write(c);
					Console.Write(" ");
					Console.Write(c);

					if (ret.Count >= 1)
					{
						ret.Dequeue();
					}
				}
			}

			Console.WriteLine();

			if (escape)
			{
				return null;
			}

			return new string(ret.ToArray());
		}

		public static bool CheckStrLen(string str, int maxLen)
		{
			if (str == null)
			{
				return false;
			}

			if (str.Length > maxLen)
			{
				return false;
			}

			return true;
		}

		public static bool IsSafe(string s)
		{
			foreach (char c in s)
			{
				if (IsSafe(c) == false)
				{
					return false;
				}
			}

			return true;
		}

		public static bool IsSafe(char c)
		{
			char[] b = Path.GetInvalidFileNameChars();

			foreach (char bb in b)
			{
				if (bb == c)
				{
					return false;
				}
			}

			if (c == '\\' || c == '/')
			{
				return false;
			}

			return true;
		}

		public static string MakeSafePathName(string name)
		{
			char[] a = name.ToCharArray();
			char[] b = Path.GetInvalidFileNameChars();
			StringBuilder sb = new StringBuilder();

			int i;
			for (i = 0; i < a.Length; i++)
			{
				int j;
				bool ok = true;

				for (j = 0; j < b.Length; j++)
				{
					if (b[j] == a[i])
					{
						ok = false;
						break;
					}
				}

				if (a[i] == '\\' || a[i] == '/')
				{
					ok = true;
					a[i] = '\\';
				}

				string s;

				if (ok == false)
				{
					s = "_" + ((int)a[i]).ToString() + "_";
				}
				else
				{
					s = "" + a[i];
				}

				sb.Append(s);
			}

			return sb.ToString();
		}

		public static string MakeSafeFileName(string name)
		{
			char[] a = name.ToCharArray();
			char[] b = Path.GetInvalidFileNameChars();
			StringBuilder sb = new StringBuilder();

			int i;
			for (i = 0; i < a.Length; i++)
			{
				int j;
				bool ok = true;

				for (j = 0; j < b.Length; j++)
				{
					if (b[j] == a[i])
					{
						ok = false;
						break;
					}
				}

				string s;

				if (ok == false)
				{
					s = "_" + ((int)a[i]).ToString() + "_";
				}
				else
				{
					s = "" + a[i];
				}

				sb.Append(s);
			}

			return sb.ToString();
		}

		public static object CloneObject(object o)
		{
			return BinaryToObject(ObjectToBinary(o));
		}

		public static object AnyToObject(byte[] data)
		{
			if (data.Length >= 5)
			{
				if (Str.StrCmpi(Encoding.ASCII.GetString(data, 0, 5), "<SOAP"))
				{
					return XMLDataToObject(data);
				}
			}

			return BinaryToObject(data);
		}

		public static byte[] ObjectToBinary(object o)
		{
			BinaryFormatter f = new BinaryFormatter();
			MemoryStream ms = new MemoryStream();
			f.Serialize(ms, o);

			return ms.ToArray();
		}

		public static object BinaryToObject(byte[] data)
		{
			BinaryFormatter f = new BinaryFormatter();
			MemoryStream ms = new MemoryStream();
			ms.Write(data, 0, data.Length);
			ms.Position = 0;

			return f.Deserialize(ms);
		}

		public static string ObjectToXMLString(object o)
		{
			SoapFormatter f = new SoapFormatter();
			MemoryStream ms = new MemoryStream();
			f.Serialize(ms, o);
			ms.Position = 0;

			StreamReader r = new StreamReader(ms);

			return r.ReadToEnd();
		}
		public static byte[] ObjectToXMLData(object o)
		{
			SoapFormatter f = new SoapFormatter();
			MemoryStream ms = new MemoryStream();
			f.Serialize(ms, o);
			ms.Position = 0;

			return ms.ToArray();
		}

		public static object XMLStringToObject(string data)
		{
			SoapFormatter f = new SoapFormatter();
			MemoryStream ms = new MemoryStream();
			StreamWriter w = new StreamWriter(ms);
			w.Write(data);
			w.Flush();

			ms.Position = 0;

			return f.Deserialize(ms);
		}
		public static object XMLDataToObject(byte[] data)
		{
			SoapFormatter f = new SoapFormatter();
			MemoryStream ms = new MemoryStream();
			ms.Write(data, 0, data.Length);

			ms.Position = 0;

			return f.Deserialize(ms);
		}

		public static string CombineStringArray(string[] str)
		{
			return CombineStringArray(str, "");
		}
		public static string CombineStringArray(string[] str, string sepstr)
		{
			int i;
			StringBuilder b = new StringBuilder();

			for (i = 0; i < str.Length; i++)
			{
				string s = str[i];

				b.Append(s);

				if ((str.Length - 1) != i)
				{
					b.Append(sepstr);
				}
			}

			return b.ToString();
		}

		public static string TruncStr(string str, int len)
		{
			if (str == null)
			{
				return "";
			}
			if (str.Length <= len)
			{
				return str;
			}
			else
			{
				return str.Substring(0, len);
			}
		}

		public static string GenRandStr()
		{
			return ByteToStr(Secure.HashSHA1(Guid.NewGuid().ToByteArray()));
		}

		public static byte[] HashStr(string str)
		{
			return Secure.HashSHA1(Encoding.UTF8.GetBytes(str));
		}
		public static ulong HashStrToLong(string str)
		{
			Buf b = new Buf();
			b.Write(HashStr(str));
			b.SeekToBegin();
			return b.ReadInt64();
		}

		public static string ByteToStr(byte[] data)
		{
			return ByteToStr(data, "");
		}
		public static string ByteToStr(byte[] data, string paddingStr)
		{
			StringBuilder sb = new StringBuilder();

			int i;
			for (i = 0; i < data.Length; i++)
			{
				byte b = data[i];
				sb.Append(b.ToString("X2"));

				if (i != (data.Length - 1))
				{
					sb.Append(paddingStr);
				}
			}

			return sb.ToString();
		}

		public static string RandToStr6(string rand)
		{
			byte[] hash = HashStr(rand + "coreutil");
			return ByteToStr(hash).Substring(0, 6);
		}

		public static bool IsAscii(char c)
		{
			if (c >= '0' && c <= '9')
			{
				return true;
			}
			if (c >= 'A' && c <= 'Z')
			{
				return true;
			}
			if (c >= 'a' && c <= 'z')
			{
				return true;
			}
			if (c == '!' || c == '\"' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
				c == '(' || c == ')' || c == '-' || c == ' ' || c == '=' || c == '~' || c == '^' || c == '_' ||
				c == '\\' || c == '|' || c == '{' || c == '}' || c == '[' || c == ']' || c == '@' ||
				c == '*' || c == '+' || c == '.' || c == '<' || c == '>' ||
				c == ',' || c == '?' || c == '/' || c == ' ' || c == '^' || c == '\'')
			{
				return true;
			}
			return false;
		}
		public static bool IsAscii(string str)
		{
			foreach (char c in str)
			{
				if (IsAscii(c) == false)
				{
					return false;
				}
			}
			return true;
		}

		public static string GetBpsStr(int size)
		{
			return GetBpsStr(size);
		}
		public static string GetBpsStr(long size)
		{
			if (size >= 1000000000000L)
			{
				return ((double)(size) / 1000.0f / 1000.0f / 1000.0f / 1000.0f).ToString(".00") + " Tbps";
			}
			if (size >= 1000 * 1000 * 1000)
			{
				return ((double)(size) / 1000.0f / 1000.0f / 1000.0f).ToString(".00") + " Gbps";
			}
			if (size >= 1000 * 1000)
			{
				return ((double)(size) / 1000.0f / 1000.0f).ToString(".00") + " Mbps";
			}
			if (size >= 1000)
			{
				return ((double)(size) / 1000.0f).ToString(".00") + " Kbps";
			}
			return ((double)(size)).ToString() + " bps";
		}

		public static string GetFileSizeStr(int size)
		{
			return GetFileSizeStr(size);
		}
		public static string GetFileSizeStr(long size)
		{
			if (size >= 1099511627776L)
			{
				return ((double)(size) / 1024.0f / 1024.0f / 1024.0f / 1024.0f).ToString(".00") + " TB";
			}
			if (size >= 1024 * 1024 * 1024)
			{
				return ((double)(size) / 1024.0f / 1024.0f / 1024.0f).ToString(".00") + " GB";
			}
			if (size >= 1024 * 1024)
			{
				return ((double)(size) / 1024.0f / 1024.0f).ToString(".00") + " MB";
			}
			if (size >= 1024)
			{
				return ((double)(size) / 1024.0f).ToString(".00") + " KB";
			}
			return ((double)(size)).ToString() + " Bytes";
		}

		public static string IntToStr(int i)
		{
			return i.ToString();
		}
		public static string IntToStr(uint i)
		{
			return i.ToString();
		}

		public static string LongToStr(long i)
		{
			return i.ToString();
		}
		public static string LongToStr(ulong i)
		{
			return i.ToString();
		}

		public static bool StrToBool(string s)
		{
			if (s == null)
			{
				return false;
			}

			Str.NormalizeString(ref s, true, true, false, false);

			if (s.StartsWith("y", StringComparison.InvariantCultureIgnoreCase))
			{
				return true;
			}

			if (s.StartsWith("t", StringComparison.InvariantCultureIgnoreCase))
			{
				return true;
			}

			if (Str.StrToInt(s) != 0)
			{
				return true;
			}

			return false;
		}

		public static int StrToInt(string str)
		{
			try
			{
				Str.RemoveSpaceChar(ref str);
				Str.NormalizeString(ref str, true, true, false, false);
				str = str.Replace(",", "");
				return int.Parse(str);
			}
			catch
			{
				return 0;
			}
		}
		public static uint StrToUInt(string str)
		{
			try
			{
				Str.RemoveSpaceChar(ref str);
				Str.NormalizeString(ref str, true, true, false, false);
				str = str.Replace(",", "");
				return uint.Parse(str);
			}
			catch
			{
				return 0;
			}
		}

		public static long StrToLong(string str)
		{
			try
			{
				Str.RemoveSpaceChar(ref str);
				Str.NormalizeString(ref str, true, true, false, false);
				str = str.Replace(",", "");
				return long.Parse(str);
			}
			catch
			{
				return 0;
			}
		}
		public static ulong StrToULong(string str)
		{
			try
			{
				Str.RemoveSpaceChar(ref str);
				Str.NormalizeString(ref str, true, true, false, false);
				str = str.Replace(",", "");
				return ulong.Parse(str);
			}
			catch
			{
				return 0;
			}
		}

		public static bool IsStrDateTime(string str)
		{
			try
			{
				Str.NormalizeString(ref str, true, true, false, false);
				StrToDateTime(str);
				return true;
			}
			catch
			{
				return false;
			}
		}
		public static DateTime StrToDateTime(string str, bool toUtc)
		{
			return StrToDateTime(str).ToUniversalTime();
		}
		public static DateTime StrToDateTime(string str)
		{
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Trim();
			string[] sps =
				{
					" ",
					"_",
					"　",
					"\t",
				};

			string[] tokens = str.Split(sps, StringSplitOptions.RemoveEmptyEntries);

			if (tokens.Length != 2)
			{
				int r1 = str.IndexOf("年", StringComparison.InvariantCultureIgnoreCase);
				int r2 = str.IndexOf("月", StringComparison.InvariantCultureIgnoreCase);
				int r3 = str.IndexOf("日", StringComparison.InvariantCultureIgnoreCase);

				if (r1 != -1 && r2 != -1 && r3 != -1)
				{
					tokens = new string[2];

					tokens[0] = str.Substring(0, r3 + 1);
					tokens[1] = str.Substring(r3 + 1);
				}
			}

			if (tokens.Length == 2)
			{
				DateTime dt1 = StrToDate(tokens[0]);
				DateTime dt2 = StrToTime(tokens[1]);

				return dt1.Date + dt2.TimeOfDay;
			}
			else if (tokens.Length == 1)
			{
				if (tokens[0].Length == 14)
				{
					// yyyymmddhhmmss
					DateTime dt1 = StrToDate(tokens[0].Substring(0, 8));
					DateTime dt2 = StrToTime(tokens[0].Substring(8));

					return dt1.Date + dt2.TimeOfDay;
				}
				else if (tokens[0].Length == 12)
				{
					// yymmddhhmmss
					DateTime dt1 = StrToDate(tokens[0].Substring(0, 6));
					DateTime dt2 = StrToTime(tokens[0].Substring(6));

					return dt1.Date + dt2.TimeOfDay;
				}
				else
				{
					DateTime dt1 = StrToDate(tokens[0]);

					return dt1.Date;
				}
			}

			throw new ArgumentException();
		}

		public static bool IsStrTime(string str)
		{
			try
			{
				Str.NormalizeString(ref str, true, true, false, false);
				StrToTime(str);
				return true;
			}
			catch
			{
				return false;
			}
		}
		public static DateTime StrToTime(string str, bool toUtc)
		{
			return StrToTime(str).ToUniversalTime();
		}
		public static DateTime StrToTime(string str)
		{
			string[] sps = 
				{
					"/",
					"-",
					":",
					"時",
					"分",
					"秒",
				};
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Trim();

			string[] tokens;

			tokens = str.Split(sps, StringSplitOptions.RemoveEmptyEntries);
			if (tokens.Length == 3)
			{
				// hh:mm:ss
				string hourStr = tokens[0];
				string minuteStr = tokens[1];
				string secondStr = tokens[2];
				int hour = -1;
				int minute = -1;
				int second = -1;

				if ((hourStr.Length == 1 || hourStr.Length == 2) && IsNumber(hourStr))
				{
					hour = StrToInt(hourStr);
				}
				if ((minuteStr.Length == 1 || minuteStr.Length == 2) && IsNumber(minuteStr))
				{
					minute = StrToInt(minuteStr);
				}
				if ((secondStr.Length == 1 || secondStr.Length == 2) && IsNumber(secondStr))
				{
					second = StrToInt(secondStr);
				}

				if (hour < 0 || hour >= 25 || minute < 0 || minute >= 60 || second < 0 || second >= 60)
				{
					throw new ArgumentException();
				}

				return new DateTime(2000, 1, 1, hour, minute, second);
			}
			else if (tokens.Length == 2)
			{
				// hh:mm
				string hourStr = tokens[0];
				string minuteStr = tokens[1];
				int hour = -1;
				int minute = -1;
				int second = 0;

				if ((hourStr.Length == 1 || hourStr.Length == 2) && IsNumber(hourStr))
				{
					hour = StrToInt(hourStr);
				}
				if ((minuteStr.Length == 1 || minuteStr.Length == 2) && IsNumber(minuteStr))
				{
					minute = StrToInt(minuteStr);
				}

				if (hour < 0 || hour >= 25 || minute < 0 || minute >= 60 || second < 0 || second >= 60)
				{
					throw new ArgumentException();
				}

				return new DateTime(2000, 1, 1, hour, minute, second);
			}
			else if (tokens.Length == 1)
			{
				string hourStr = tokens[0];
				int hour = -1;
				int minute = 0;
				int second = 0;

				if ((hourStr.Length == 1 || hourStr.Length == 2) && IsNumber(hourStr))
				{
					// hh
					hour = StrToInt(hourStr);
				}
				else
				{
					if ((hourStr.Length == 4) && IsNumber(hourStr))
					{
						// hhmm
						int i = StrToInt(hourStr);
						hour = i / 100;
						minute = i % 100;
					}
					else if ((hourStr.Length == 6) && IsNumber(hourStr))
					{
						// hhmmss
						int i = StrToInt(hourStr);
						hour = i / 10000;
						minute = ((i % 10000) / 100);
						second = i % 100;
					}
				}

				if (hour < 0 || hour >= 25 || minute < 0 || minute >= 60 || second < 0 || second >= 60)
				{
					throw new ArgumentException();
				}

				return new DateTime(2000, 1, 1, hour, minute, second);
			}

			throw new ArgumentException();
		}

		public static bool IsStrDate(string str)
		{
			try
			{
				Str.NormalizeString(ref str, true, true, false, false);
				StrToDate(str);
				return true;
			}
			catch
			{
				return false;
			}
		}
		public static DateTime StrToDate(string str, bool toUtc)
		{
			return StrToDate(str).ToUniversalTime();
		}
		public static DateTime StrToDate(string str)
		{
			string[] sps = 
				{
					"/",
					"/",
					"-",
					":",
					"年",
					"月",
					"日",
				};
			str = str.Trim();
			Str.NormalizeString(ref str, true, true, false, false);

			string[] youbi =
			{
				"月", "火", "水", "木", "金", "土", "日",
			};

			foreach (string ys in youbi)
			{
				string ys2 = string.Format("({0})", ys);

				str = str.Replace(ys2, "");
			}

			string[] tokens;

			tokens = str.Split(sps, StringSplitOptions.RemoveEmptyEntries);
			if (tokens.Length == 3)
			{
				// yyyy/mm/dd
				string yearStr = tokens[0];
				string monthStr = tokens[1];
				string dayStr = tokens[2];
				int year = 0;
				int month = 0;
				int day = 0;

				if ((yearStr.Length == 1 || yearStr.Length == 2) && IsNumber(yearStr))
				{
					year = 2000 + StrToInt(yearStr);
				}
				else if (yearStr.Length == 4 && IsNumber(yearStr))
				{
					year = StrToInt(yearStr);
				}

				if ((monthStr.Length == 1 || monthStr.Length == 2) && IsNumber(monthStr))
				{
					month = StrToInt(monthStr);
				}
				if ((dayStr.Length == 1 || dayStr.Length == 2) && IsNumber(dayStr))
				{
					day = StrToInt(dayStr);
				}

				if (year < 1800 || year >= 2100 || month <= 0 || month >= 13 || day <= 0 || day >= 32)
				{
					throw new ArgumentException();
				}

				return new DateTime(year, month, day);
			}
			else if (tokens.Length == 1)
			{
				if (str.Length == 8)
				{
					// yyyymmdd
					string yearStr = str.Substring(0, 4);
					string monthStr = str.Substring(4, 2);
					string dayStr = str.Substring(6, 2);
					int year = int.Parse(yearStr);
					int month = int.Parse(monthStr);
					int day = int.Parse(dayStr);

					if (year < 1800 || year >= 2100 || month <= 0 || month >= 13 || day <= 0 || day >= 32)
					{
						throw new ArgumentException();
					}

					return new DateTime(year, month, day);
				}
				else if (str.Length == 6)
				{
					// yymmdd
					string yearStr = str.Substring(0, 2);
					string monthStr = str.Substring(2, 2);
					string dayStr = str.Substring(4, 2);
					int year = int.Parse(yearStr) + 2000;
					int month = int.Parse(monthStr);
					int day = int.Parse(dayStr);

					if (year < 1800 || year >= 2100 || month <= 0 || month >= 13 || day <= 0 || day >= 32)
					{
						throw new ArgumentException();
					}

					return new DateTime(year, month, day);
				}
			}

			throw new ArgumentException();
		}

		public static string TimeToStr(DateTime dt)
		{
			return TimeToStr(dt, false);
		}
		public static string TimeToStr(DateTime dt, CoreLanguage lang)
		{
			return TimeToStr(dt, false, lang);
		}
		public static string TimeToStr(DateTime dt, bool toLocalTime)
		{
			return TimeToStr(dt, toLocalTime, CoreLanguageClass.CurrentThreadLanguage);
		}
		public static string TimeToStr(DateTime dt, bool toLocalTime, CoreLanguage lang)
		{
			string s = DateTimeToStr(dt, toLocalTime, lang);

			string[] tokens = s.Split(' ');

			return tokens[1];
		}
		public static string TimeToStrShort(DateTime dt)
		{
			return TimeToStrShort(dt, false);
		}
		public static string TimeToStrShort(DateTime dt, bool toLocalTime)
		{
			string s = DateTimeToStrShort(dt, toLocalTime);

			string[] tokens = s.Split('_');

			return tokens[1];
		}

		public static string DateToStr(DateTime dt)
		{
			return DateToStr(dt, false);
		}
		public static string DateToStr(DateTime dt, CoreLanguage lang)
		{
			return DateToStr(dt, false, lang);
		}
		public static string DateToStr(DateTime dt, bool toLocalTime)
		{
			return DateToStr(dt, toLocalTime, false);
		}
		public static string DateToStr(DateTime dt, bool toLocalTime, CoreLanguage lang)
		{
			return DateToStr(dt, toLocalTime, false, lang);
		}
		public static string DateToStr(DateTime dt, bool toLocalTime, bool noDayOfWeek)
		{
			return DateToStr(dt, toLocalTime, noDayOfWeek, CoreLanguageClass.CurrentThreadLanguage);
		}
		public static string DateToStr(DateTime dt, bool toLocalTime, bool noDayOfWeek, CoreLanguage lang)
		{
			string s = DateTimeToStr(dt, toLocalTime, lang);

			string[] tokens = s.Split(' ');

			string ret = tokens[0];

			if (noDayOfWeek)
			{
				string[] tokens2 = s.Split('(');

				ret = tokens2[0];
			}

			return ret;
		}
		public static string DateToStrShort(DateTime dt)
		{
			return DateToStrShort(dt, false);
		}
		public static string DateToStrShort(DateTime dt, bool toLocalTime)
		{
			string s = DateTimeToStrShort(dt, toLocalTime);

			string[] tokens = s.Split('_');

			return tokens[0];
		}

		public static string DayOfWeekToStr(CoreLanguage lang, int d)
		{
			if (lang == CoreLanguage.Japanese)
			{
				string[] youbi =
				{
					"日", "月", "火", "水", "木", "金", "土", 
				};

				return youbi[d];
			}
			else
			{
				string[] youbi =
				{
					"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", 
				};

				return youbi[d];
			}
		}

		public static string DateTimeToStr(DateTime dt)
		{
			return DateTimeToStr(dt, false);
		}
		public static string DateTimeToStr(DateTime dt, CoreLanguage lang)
		{
			return DateTimeToStr(dt, false, lang);
		}
		public static string DateTimeToStr(DateTime dt, bool toLocalTime)
		{
			return DateTimeToStr(dt, toLocalTime, CoreLanguageClass.CurrentThreadLanguage);
		}
		public static string DateTimeToStr(DateTime dt, bool toLocalTime, CoreLanguage lang)
		{
			if (toLocalTime)
			{
				dt = dt.ToLocalTime();
			}

			if (lang == CoreLanguage.Japanese)
			{
				return dt.ToString("yyyy年M月d日") + "(" + DayOfWeekToStr(lang, (int)dt.DayOfWeek) + ")" + dt.ToString(" H時m分s秒");
			}
			else
			{
				return dt.ToString("yyyy-MM-dd(") + DayOfWeekToStr(lang, (int)dt.DayOfWeek) + dt.ToString(") H:mm:ss");
			}
		}
		public static string DateTimeToStrShort(DateTime dt)
		{
			return DateTimeToStrShort(dt, false);
		}
		public static string DateTimeToStrShort(DateTime dt, bool toLocalTime)
		{
			if (toLocalTime)
			{
				dt = dt.ToLocalTime();
			}

			return dt.ToString("yyyyMMdd_HHmmss");
		}
		public static string DateTimeToStrShortWithMilliSecs(DateTime dt)
		{
			return DateTimeToStrShortWithMilliSecs(dt, false);
		}
		public static string DateTimeToStrShortWithMilliSecs(DateTime dt, bool toLocalTime)
		{
			if (toLocalTime)
			{
				dt = dt.ToLocalTime();
			}

			long ticks = dt.Ticks % 10000000;
			if (ticks >= 9990000)
			{
				ticks = 9990000;
			}

			string msecStr = ((decimal)ticks / (decimal)10000000).ToString(".000");

			return dt.ToString("yyyyMMdd_HHmmss") + "." + msecStr.Split('.')[1];
		}

		public static string Base64ToSafe64(string str)
		{
			return str.Replace('=', '(').Replace('+', ')').Replace('/', '_');
		}
		public static string Safe64ToBase64(string str)
		{
			return str.Replace('(', '=').Replace(')', '+').Replace('_', '/');
		}

		public static string Base64Encode(byte[] data)
		{
			try
			{
				return Convert.ToBase64String(data);
			}
			catch
			{
				return "";
			}
		}

		public static byte[] Base64Decode(string str)
		{
			try
			{
				return Convert.FromBase64String(str);
			}
			catch
			{
				return new byte[0];
			}
		}

		public static byte[] StrToByte(string str)
		{
			Str.NormalizeString(ref str, true, true, false, false);
			return Base64Decode(Safe64ToBase64(str));
		}

		public static string Encode64(string str)
		{
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(str)).Replace("/", "(").Replace("+", ")");
		}

		public static string Decode64(string str)
		{
			return Encoding.UTF8.GetString(Convert.FromBase64String(str.Replace(")", "+").Replace("(", "/")));
		}


		public static bool CheckMailAddress(string str)
		{
			str = str.Trim();
			if (str.Length == 0)
			{
				return false;
			}

			string[] tokens = str.Split('@');

			if (tokens.Length != 2)
			{
				return false;
			}

			string a = tokens[0];
			string b = tokens[1];

			if (a.Length == 0 || b.Length == 0)
			{
				return false;
			}

			if (b.IndexOf(".") == -1)
			{
				return false;
			}

			return IsAscii(str);
		}

		public static bool StrCmpi(string s1, string s2)
		{
			try
			{
				if (s1.Equals(s2, StringComparison.InvariantCultureIgnoreCase))
				{
					return true;
				}

				return false;
			}
			catch
			{
				return false;
			}
		}

		public static bool StrCmp(string s1, string s2)
		{
			try
			{
				if (s1 == s2)
				{
					return true;
				}

				return false;
			}
			catch
			{
				return false;
			}
		}
		public static string ByteToHex(byte[] data)
		{
			return ByteToHex(data, "");
		}
		public static string ByteToHex(byte[] data, string paddingStr)
		{
			StringBuilder ret = new StringBuilder();
			foreach (byte b in data)
			{
				string s = b.ToString("X");
				if (s.Length == 1)
				{
					s = "0" + s;
				}

				ret.Append(s);

				if (paddingStr != null)
				{
					ret.Append(paddingStr);
				}
			}

			return ret.ToString().Trim();
		}

		public static byte[] HexToByte(string str)
		{
			try
			{
				List<byte> o = new List<byte>();
				string tmp = "";
				int i, len;

				str = str.ToUpper().Trim();
				len = str.Length;

				for (i = 0; i < len; i++)
				{
					char c = str[i];
					if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))
					{
						tmp += c;
						if (tmp.Length == 2)
						{
							byte b = Convert.ToByte(tmp, 16);
							o.Add(b);
							tmp = "";
						}
					}
					else if (c == ' ' || c == ',' || c == '-' || c == ';')
					{
					}
					else
					{
						break;
					}
				}

				return o.ToArray();
			}
			catch
			{
				return new byte[0];
			}
		}

		public static string[] GetLines(string str)
		{
			List<string> a = new List<string>();
			StringReader sr = new StringReader(str);
			while (true)
			{
				string s = sr.ReadLine();
				if (s == null)
				{
					break;
				}
				a.Add(s);
			}
			return a.ToArray();
		}

		public static string LinesToStr(string[] lines)
		{
			StringWriter sw = new StringWriter();
			foreach (string s in lines)
			{
				sw.WriteLine(s);
			}
			return sw.ToString();
		}

		public static bool IsEmptyStr(string str)
		{
			if (str == null || str.Trim().Length == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		public static bool IsSolidStr(string str)
		{
			return !IsEmptyStr(str);
		}

		public static bool IsSplitChar(char c, string splitStr)
		{
			if (splitStr == null)
			{
				splitStr = StrToken.DefaultSplitStr;
			}

			foreach (char t in splitStr)
			{
				string a = "" + t;
				string b = "" + c;
				if (Str.StrCmpi(a, b))
				{
					return true;
				}
			}

			return false;
		}

		public static bool GetKeyAndValue(string str, out string key, out string value)
		{
			return GetKeyAndValue(str, out key, out value, null);
		}
		public static bool GetKeyAndValue(string str, out string key, out string value, string splitStr)
		{
			uint mode = 0;
			string keystr = "", valuestr = "";
			if (splitStr == null)
			{
				splitStr = StrToken.DefaultSplitStr;
			}

			foreach (char c in str)
			{
				switch (mode)
				{
					case 0:
						if (IsSplitChar(c, splitStr) == false)
						{
							mode = 1;
							keystr += c;
						}
						break;

					case 1:
						if (IsSplitChar(c, splitStr) == false)
						{
							keystr += c;
						}
						else
						{
							mode = 2;
						}
						break;

					case 2:
						if (IsSplitChar(c, splitStr) == false)
						{
							mode = 3;
							valuestr += c;
						}
						break;

					case 3:
						valuestr += c;
						break;
				}
			}

			if (mode == 0)
			{
				value = "";
				key = "";
				return false;
			}
			else
			{
				value = valuestr;
				key = keystr;
				return true;
			}
		}

		public static int StrCmpRetInt(string s1, string s2)
		{
			return string.Compare(s1, s2, false);
		}
		public static int StrCmpiRetInt(string s1, string s2)
		{
			return string.Compare(s1, s2, true);
		}

		public static bool IsStrInList(string str, params string[] args)
		{
			return IsStrInList(str, true, args);
		}
		public static bool IsStrInList(string str, bool ignoreCase, params string[] args)
		{
			foreach (string s in args)
			{
				if (ignoreCase)
				{
					if (StrCmpi(str, s))
					{
						return true;
					}
				}
				else
				{
					if (StrCmp(str, s))
					{
						return true;
					}
				}
			}

			return false;
		}

		public static bool IsDouble(string str)
		{
			double v;
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Replace(",", "");
			return double.TryParse(str, out v);
		}

		public static bool IsLong(string str)
		{
			long v;
			Str.RemoveSpaceChar(ref str);
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Replace(",", "");
			return long.TryParse(str, out v);
		}

		public static bool IsInt(string str)
		{
			int v;
			Str.RemoveSpaceChar(ref str);
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Replace(",", "");
			return int.TryParse(str, out v);
		}

		public static bool IsNumber(string str)
		{
			str = str.Trim();
			Str.RemoveSpaceChar(ref str);
			Str.NormalizeString(ref str, true, true, false, false);
			str = str.Replace(",", "");

			foreach (char c in str)
			{
				if (IsNumber(c) == false)
				{
					return false;
				}
			}

			return true;
		}
		public static bool IsNumber(char c)
		{
			if (c >= '0' && c <= '9')
			{
			}
			else if (c == '-')
			{
			}
			else
			{
				return false;
			}

			return true;
		}

		public static bool InStr(string str, string keyword)
		{
			return InStr(str, keyword, false);
		}
		public static bool InStr(string str, string keyword, bool caseSensitive)
		{
			if (str.IndexOf(keyword, (caseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase)) == -1)
			{
				return false;
			}

			return true;
		}

		public static string MakeCharArray(char c, int len)
		{
			return new string(c, len);
		}

		public static string NormalizeCrlf(string str)
		{
			return NormalizeCrlf(str, new byte[] { 13, 10 });
		}
		public static string NormalizeCrlf(string str, byte[] crlfData)
		{
			byte[] srcData = Str.Utf8Encoding.GetBytes(str);
			byte[] destData = NormalizeCrlf(srcData, crlfData);
			return Str.Utf8Encoding.GetString(destData);
		}
		public static byte[] NormalizeCrlf(byte[] srcData)
		{
			return NormalizeCrlf(srcData, new byte[] { 13, 10 });
		}
		public static byte[] NormalizeCrlf(byte[] srcData, byte[] crlfData)
		{
			Buf ret = new Buf();

			int i;
			Buf b = new Buf();
			for (i = 0; i < srcData.Length; i++)
			{
				bool isNewLine = false;
				if (srcData[i] == 13)
				{
					if (i < (srcData.Length - 1) && srcData[i + 1] == 10)
					{
						i++;
					}
					isNewLine = true;
				}
				else if (srcData[i] == 10)
				{
					isNewLine = true;
				}

				if (isNewLine)
				{
					ret.Write(b.ByteData);
					ret.Write(crlfData);

					b.Clear();
				}
				else
				{
					b.WriteByte(srcData[i]);
				}
			}
			ret.Write(b.ByteData);

			return ret.ByteData;
		}

		public static string[] UniqueToken(string[] t)
		{
			Dictionary<string, object> o = new Dictionary<string, object>();
			List<string> ret = new List<string>();

			foreach (string s in t)
			{
				string key = s.ToUpper();

				if (o.ContainsKey(key) == false)
				{
					o.Add(key, new Object());

					ret.Add(s);
				}
			}

			return ret.ToArray();
		}

		public static string ToStr3(long v)
		{
			bool neg = false;

			if (v < 0)
			{
				neg = true;
				v = v * (long)-1;
			}

			string tmp, tmp2;
			int i;

			tmp = Str.LongToStr(v);

			tmp2 = "";
			for (i = tmp.Length - 1; i >= 0; i--)
			{
				tmp2 += tmp[i];
			}

			int len = tmp.Length;

			tmp = "";
			for (i = 0; i < len; i++)
			{
				if (i != 0 && (i % 3) == 0)
				{
					tmp += ",";
				}

				tmp += tmp2[i];
			}

			char[] array = tmp.ToCharArray();
			Array.Reverse(array);

			string str = new string(array);

			if (neg)
			{
				str = "-" + str;
			}

			return str;
		}

		public static string[] ParseCmdLine(string str)
		{
			List<string> o;
			int i, len, mode;
			string tmp;
			bool ignoreSpace = false;

			o = new List<string>();
			mode = 0;
			len = str.Length;

			tmp = "";

			for (i = 0; i < len; i++)
			{
				char c = str[i];

				switch (mode)
				{
					case 0:
						if (c == ' ' || c == '\t')
						{
						}
						else
						{
							if (c == '\"')
							{
								if ((i != (len - 1)) && str[i + 1] == '\"')
								{
									tmp += '\"';
									i++;
								}
								else
								{
									ignoreSpace = true;
								}
							}
							else
							{
								tmp += c;
							}

							mode = 1;
						}
						break;

					case 1:
						if (ignoreSpace == false && (c == ' ' || c == '\t'))
						{
							o.Add(tmp);
							tmp = "";
							mode = 0;
						}
						else
						{
							if (c == '\"')
							{
								if ((i != (len - 1)) && str[i + 1] == '\"')
								{
									tmp += '\"';
									i++;
								}
								else
								{
									if (ignoreSpace == false)
									{
										ignoreSpace = true;
									}
									else
									{
										ignoreSpace = false;
									}
								}
							}
							else
							{
								tmp += c;
							}
						}
						break;
				}
			}

			if (tmp.Length != 0)
			{
				o.Add(tmp);
				tmp = "";
			}

			return o.ToArray();
		}

		public static string ObjectToXMLSimple(object o)
		{
			return ObjectToXMLSimple(o, o.GetType());
		}
		public static string ObjectToXMLSimple(object o, Type t)
		{
			XmlSerializer xs = new XmlSerializer(t);

			MemoryStream ms = new MemoryStream();
			xs.Serialize(ms, o);

			return Str.Utf8Encoding.GetString(ms.ToArray());
		}

		public static object XMLToObjectSimple(string str, Type t)
		{
			XmlSerializer xs = new XmlSerializer(t);

			MemoryStream ms = new MemoryStream();
			byte[] data = Str.Utf8Encoding.GetBytes(str);
			ms.Write(data, 0, data.Length);
			ms.Position = 0;

			return xs.Deserialize(ms);
		}

		public static bool IsStrOkForXML(string str)
		{
			try
			{
				XmlCheckObjectInternal o = new XmlCheckObjectInternal();
				o.Str = str;

				string xmlstr = ObjectToXMLSimple(o);

				XMLToObjectSimple(xmlstr, typeof(XmlCheckObjectInternal));

				return true;
			}
			catch
			{
				return false;
			}
		}
	}

	public class XmlCheckObjectInternal
	{
		public string Str;
	}

	public class StrToken
	{
		string[] tokens;

		public string[] Tokens
		{
			get { return tokens; }
		}

		public string this[uint index]
		{
			get { return tokens[index]; }
		}

		public uint NumTokens
		{
			get
			{
				return (uint)Tokens.Length;
			}
		}

		const string defaultSplitStr = " ,\t\r\n";

		public static string DefaultSplitStr
		{
			get { return defaultSplitStr; }
		}

		public StrToken(string[] tokens)
		{
			List<string> a = new List<string>();
			foreach (string s in tokens)
			{
				a.Add(s);
			}

			this.tokens = a.ToArray();
		}

		public StrToken(string str)
			: this(str, null)
		{
		}
		public StrToken(string str, string splitStr)
		{
			if (splitStr == null)
			{
				splitStr = defaultSplitStr;
			}
			int i, len;
			len = splitStr.Length;
			char[] chars = new char[len];
			for (i = 0; i < len; i++)
			{
				chars[i] = splitStr[i];
			}
			tokens = str.Split(chars, StringSplitOptions.RemoveEmptyEntries);
		}
	}

	public class StrData
	{
		string strValue;

		public string StrValue
		{
			get { return strValue; }
		}

		public uint IntValue
		{
			get
			{
				return Str.StrToUInt(strValue);
			}
		}

		public ulong Int64Value
		{
			get
			{
				return Str.StrToULong(strValue);
			}
		}

		public bool BoolValue
		{
			get
			{
				string s = strValue.Trim();

				if (Str.IsEmptyStr(s))
				{
					return false;
				}
				if (s.StartsWith("true", StringComparison.CurrentCultureIgnoreCase))
				{
					return true;
				}
				if ("true".StartsWith(s, StringComparison.CurrentCultureIgnoreCase))
				{
					return true;
				}
				if (s.StartsWith("yes", StringComparison.CurrentCultureIgnoreCase))
				{
					return true;
				}
				if ("yes".StartsWith(s, StringComparison.CurrentCultureIgnoreCase))
				{
					return true;
				}

				if (Str.StrToUInt(s) != 0)
				{
					return true;
				}

				return false;
			}
		}

		public StrData(string str)
		{
			if (str == null)
			{
				str = "";
			}
			strValue = str;
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
