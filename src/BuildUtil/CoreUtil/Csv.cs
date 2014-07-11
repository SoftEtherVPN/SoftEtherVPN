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


namespace CoreUtil
{
	class CsvTimeSpan
	{
		public DateTime StartDateTime;
		public DateTime EndDateTime;
		public int StartIndex;
		public int NumIndex;

		public CsvTimeSpan(DateTime startDateTime, DateTime endDateTime, int startIndex, int numIndex)
		{
			StartDateTime = startDateTime;
			EndDateTime = endDateTime;
			StartIndex = startIndex;
			NumIndex = numIndex;
		}
	}

	public class Csv
	{
		List<CsvEntry> entryList;
		Encoding encoding;
		static Encoding defaultEncoding = Str.ShiftJisEncoding;

		public Encoding Encoding
		{
			get
			{
				return encoding;
			}
			set
			{
				this.encoding = value;
			}
		}

		public CsvEntry First
		{
			get
			{
				return entryList[0];
			}
		}

		public CsvEntry Last
		{
			get
			{
				return entryList[entryList.Count - 1];
			}
		}

		public Csv()
			: this(defaultEncoding)
		{
		}
		public Csv(Encoding encoding)
		{
			init(null, encoding);
		}

		public Csv(string filename)
			: this(filename, defaultEncoding)
		{
		}
		public Csv(string filename, Encoding encoding)
		{
			init(Buf.ReadFromFile(filename), encoding);
		}

		public Csv(Buf data)
		{
			byte[] src = data.ByteData;
			int bomSize;

			Encoding enc = Str.CheckBOM(src, out bomSize);

			if (bomSize >= 1)
			{
				src = Util.RemoveStartByteArray(src, bomSize);
			}

			init(new Buf(src), enc);
		}
		public Csv(Buf data, Encoding encoding)
		{
			init(data, encoding);
		}

		void init(Buf data, Encoding encoding)
		{
			if (encoding == null)
			{
				encoding = defaultEncoding;
			}

			int bomSize = 0;
			Encoding enc2 = null;
			if (data != null)
			{
				enc2 = Str.CheckBOM(data.ByteData, out bomSize);
			}
			if (bomSize >= 1)
			{
				data = new Buf(Util.RemoveStartByteArray(data.ByteData, bomSize));
			}
			if (enc2 != null)
			{
				encoding = enc2;
			}
			this.encoding = encoding;

			entryList = new List<CsvEntry>();

			if (data != null)
			{
				MemoryStream ms = new MemoryStream(data.ByteData);
				StreamReader sr = new StreamReader(ms, this.encoding);

				while (true)
				{
					string s = sr.ReadLine();

					if (s == null)
					{
						break;
					}

					char[] sep = { ',' };
					string[] strings = s.Trim().Split(sep, StringSplitOptions.None);

					CsvEntry e = new CsvEntry(strings);
					Add(e);
				}
			}
		}

		public override string ToString()
		{
			StringBuilder b = new StringBuilder();

			foreach (CsvEntry e in entryList)
			{
				b.AppendLine(e.ToString());
			}

			return b.ToString();
		}

		public Buf ToBuf()
		{
			string s = ToString();

			Buf b = new Buf();

			byte[] bom = Str.GetBOM(this.Encoding);

			if (bom != null)
			{
				b.Write(bom);
			}

			b.Write(encoding.GetBytes(s));

			b.SeekToBegin();

			return b;
		}

		public void SaveToFile(string filename)
		{
			File.WriteAllBytes(filename, ToBuf().ByteData);
		}

		public void Add(CsvEntry e)
		{
			entryList.Add(e);
		}

		public int Count
		{
			get
			{
				return entryList.Count;
			}
		}

		public CsvEntry this[int index]
		{
			get
			{
				return entryList[index];
			}
		}

		public IEnumerable Items
		{
			get
			{
				int i;
				for (i = 0; i < entryList.Count; i++)
				{
					yield return entryList[i];
				}
			}
		}

		CsvCompare csvCompareMethod;
		int csvCompareIndex;
		Type csvCompareType;
		bool csvCompareReverse;

		int sortInternal(CsvEntry e1, CsvEntry e2)
		{
			if (csvCompareMethod != null)
			{
				object o1 = e1.Convert(csvCompareType, csvCompareIndex);
				object o2 = e2.Convert(csvCompareType, csvCompareIndex);

				return csvCompareMethod(o1, o2) * (csvCompareReverse ? -1 : 1);
			}
			else
			{
				IComparable o1 = (IComparable)e1.Convert(csvCompareType, csvCompareIndex);
				IComparable o2 = (IComparable)e2.Convert(csvCompareType, csvCompareIndex);

				return o1.CompareTo(o2) * (csvCompareReverse ? -1 : 1);
			}
		}

		public void Sort(Type type)
		{
			Sort(null, type);
		}
		public void Sort(CsvCompare cmp, Type type)
		{
			Sort(cmp, type, false);
		}
		public void Sort(Type type, bool reverse)
		{
			Sort(null, type, reverse);
		}
		public void Sort(CsvCompare cmp, Type type, bool reverse)
		{
			Sort(cmp, 0, type, reverse);
		}
		public void Sort(int index, Type type)
		{
			Sort(null, index, type);
		}
		public void Sort(CsvCompare cmp, int index, Type type)
		{
			Sort(cmp, 0, type, false);
		}
		public void Sort(int index, Type type, bool reverse)
		{
			Sort(null, index, type, reverse);
		}
		public void Sort(CsvCompare cmp, int index, Type type, bool reverse)
		{
			csvCompareMethod = cmp;
			csvCompareIndex = index;
			csvCompareType = type;
			csvCompareReverse = reverse;

			entryList.Sort(new Comparison<CsvEntry>(sortInternal));
		}

		public static int CompareString(object o1, object o2)
		{
			string s1 = (string)o1;
			string s2 = (string)o2;
			return s1.CompareTo(s2);
		}

		public static int CompareDatetime(object o1, object o2)
		{
			DateTime d1 = (DateTime)o1;
			DateTime d2 = (DateTime)o2;

			return d1.CompareTo(d2);
		}

		public void SetEncoding(Encoding e)
		{
			this.encoding = e;
		}

		public Csv Clone()
		{
			Csv csv = new Csv(this.encoding);

			foreach (CsvEntry e in entryList)
			{
				csv.Add(e.Clone());
			}

			return csv;
		}
	}

	public delegate int CsvCompare(object o1, object o2);

	public class CsvEntry
	{
		List<string> strings;

		public CsvEntry Clone()
		{
			string[] array = (string[])strings.ToArray().Clone();

			CsvEntry e = new CsvEntry(array);

			return e;
		}

		public CsvEntry(params string[] elements)
		{
			strings = new List<string>();
			foreach (string s in elements)
			{
				string str = s;

				if (str.StartsWith("\"") && str.EndsWith("\"") && str.Length >= 2)
				{
					str = str.Substring(1, str.Length - 2);
				}

				strings.Add(str);
			}
		}

		public string this[int index]
		{
			get
			{
				return strings[index];
			}
		}

		public int Count
		{
			get
			{
				return strings.Count;
			}
		}

		public override string ToString()
		{
			int i, num;
			string ret = "";

			num = strings.Count;
			for (i = 0; i < num; i++)
			{
				string s = strings[i];

				s = Str.ReplaceStr(s, ",", ".", false);
				s = Str.ReplaceStr(s, "\r\n", " ", false);
				s = Str.ReplaceStr(s, "\r", " ", false);
				s = Str.ReplaceStr(s, "\n", " ", false);

				ret += s;

				if ((i + 1) < num)
				{
					ret += ",";
				}
			}

			return ret;
		}

		Type lastType = null;
		object lastObject = null;
		int lastIndex = -1;

		public object Convert(Type type, int index)
		{
			if (lastType == type && lastIndex == index)
			{
				return lastObject;
			}

			lastType = type;
			lastIndex = index;
			lastObject = System.Convert.ChangeType(strings[index], type);

			return lastObject;
		}

		public DateTime ToDateTime(int index)
		{
			return (DateTime)Convert(typeof(DateTime), index);
		}
	}
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
