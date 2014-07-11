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
using System.Diagnostics;
using System.Web.Mail;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Net.Mail;
using System.Net.Mime;
using System.Reflection;
using CoreUtil;

namespace CoreUtil
{
	public class Stb
	{
		Dictionary<string, StbEntry> entryList;

		public string this[string name]
		{
			get
			{
				if (entryList.ContainsKey(name.ToUpper()))
				{
					return entryList[name.ToUpper()].String;
				}
				else
				{
					return "";
				}
			}
		}

		public Stb(string filename)
		{
			init(IO.ReadFile(filename));
		}

		public Stb(byte[] data)
		{
			init(data);
		}

		void init(byte[] data)
		{
			entryList = new Dictionary<string, StbEntry>();
			MemoryStream ms = new MemoryStream(data);
			StreamReader sr = new StreamReader(ms);
			string prefix = "";

			while (true)
			{
				string tmp = sr.ReadLine();
				if (tmp == null)
				{
					break;
				}

				StbEntry t = StbEntry.ParseTableLine(tmp, ref prefix);
				if (t != null)
				{
					if (entryList.ContainsKey(t.Name.ToUpper()) == false)
					{
						entryList.Add(t.Name.ToUpper(), t);
					}
				}
			}
		}

		const string standardStbFileName = "|strtable.stb";
		static string defaultStbFileName = standardStbFileName;
		static object lockObj = new object();
		static Stb defaultStb = null;
		public static string DefaultStbFileName
		{
			set
			{
				defaultStbFileName = value;
			}

			get
			{
				return defaultStbFileName;
			}
		}
		public static Stb DefaultStb
		{
			get
			{
				lock (lockObj)
				{
					if (defaultStb == null)
					{
						defaultStb = new Stb(Stb.DefaultStbFileName);
					}

					return defaultStb;
				}
			}
		}
		public static string SS(string name)
		{
			return DefaultStb[name];
		}
		public static uint II(string name)
		{
			return Str.StrToUInt(SS(name));
		}
	}

	public class StbEntry
	{
		string name;
		public string Name
		{
			get { return name; }
		}

		string str;
		public string String
		{
			get { return str; }
		}

		public StbEntry(string name, string str)
		{
			this.name = name;
			this.str = str;
		}
		public static StbEntry ParseTableLine(string line, ref string prefix)
		{
			int i, len;
			int string_start;
			int len_name;
			string name, name2;

			line = line.TrimStart(' ', '\t');
			len = line.Length;
			if (len == 0)
			{
				return null;
			}

			if (line[0] == '#' || (line[0] == '/' && line[1] == '/'))
			{
				return null;
			}

			bool b = false;
			len_name = 0;
			for (i = 0; i < line.Length; i++)
			{
				if (line[i] == ' ' || line[i] == '\t')
				{
					b = true;
					break;
				}
				len_name++;
			}

			if (b == false)
			{
				return null;
			}

			name = line.Substring(0, len_name);

			string_start = len_name;
			for (i = len_name; i < len; i++)
			{
				if (line[i] != ' ' && line[i] != '\t')
				{
					break;
				}
				string_start++;
			}
			if (i == len)
			{
				return null;
			}

			string str = line.Substring(string_start);

			str = UnescapeStr(str);

			if (Str.StrCmpi(name, "PREFIX"))
			{
				prefix = str;
				prefix = prefix.TrimStart();

				if (Str.StrCmpi(prefix, "$") || Str.StrCmpi(prefix, "NULL"))
				{
					prefix = "";
				}

				return null;
			}

			name2 = "";

			if (prefix != "")
			{
				name2 += prefix + "@";
			}

			name2 += name;

			return new StbEntry(name2, str);
		}

		public static string UnescapeStr(string str)
		{
			int i, len;
			string tmp;

			len = str.Length;
			tmp = "";

			for (i = 0; i < len; i++)
			{
				if (str[i] == '\\')
				{
					i++;
					switch (str[i])
					{
						case '\\':
							tmp += '\\';
							break;

						case ' ':
							tmp += ' ';
							break;

						case 'n':
						case 'N':
							tmp += '\n';
							break;

						case 'r':
						case 'R':
							tmp += '\r';
							break;

						case 't':
						case 'T':
							tmp += '\t';
							break;
					}
				}
				else
				{
					tmp += str[i];
				}
			}

			return tmp;
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
