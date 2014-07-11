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
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CoreUtil
{
	public enum CoreLanguage
	{
		Japanese = 0,
		English = 1,
	}

	public class CoreLanguageClass
	{
		public readonly CoreLanguage Language;
		public readonly int Id;
		readonly string name;
		public string Name
		{
			get
			{
				if (name == "ja")
				{
					if (CoreLanguageList.RegardsJapanAsJP)
					{
						return "jp";
					}
				}

				return name;
			}
		}
		public readonly string TitleInEnglish;
		public readonly string TitleInNative;

		public CoreLanguageClass(CoreLanguage lang, int id, string name,
			string titleInEnglish, string titleInNative)
		{
			this.Language = lang;
			this.Id = id;
			this.name = name;
			this.TitleInEnglish = titleInEnglish;
			this.TitleInNative = titleInNative;
		}

		public static void SetCurrentThreadLanguageClass(CoreLanguageClass lang)
		{
			ThreadData.CurrentThreadData.DataList["current_thread_language"] = lang;
		}

		public static CoreLanguageClass CurrentThreadLanguageClass
		{
			get
			{
				return GetCurrentThreadLanguageClass();
			}

			set
			{
				SetCurrentThreadLanguageClass(value);
			}
		}

		public static CoreLanguage CurrentThreadLanguage
		{
			get
			{
				return CurrentThreadLanguageClass.Language;
			}
		}

		public static CoreLanguageClass GetCurrentThreadLanguageClass()
		{
			CoreLanguageClass lang = null;

			try
			{
				lang = (CoreLanguageClass)ThreadData.CurrentThreadData.DataList["current_thread_language"];
			}
			catch
			{
			}

			if (lang == null)
			{
				lang = CoreLanguageList.DefaultLanguage;

				SetCurrentThreadLanguageClass(lang);
			}

			return lang;
		}
	}

	public static class CoreLanguageList
	{
		public static readonly CoreLanguageClass DefaultLanguage;
		public static readonly CoreLanguageClass Japanese;
		public static readonly CoreLanguageClass English;
		public static bool RegardsJapanAsJP = false;

		public static readonly List<CoreLanguageClass> LanguageList = new List<CoreLanguageClass>();

		static CoreLanguageList()
		{
			CoreLanguageList.LanguageList = new List<CoreLanguageClass>();

			CoreLanguageList.Japanese = new CoreLanguageClass(CoreLanguage.Japanese,
				0, "ja", "Japanese", "日本語");
			CoreLanguageList.English = new CoreLanguageClass(CoreLanguage.English,
				1, "en", "English", "English");

			CoreLanguageList.DefaultLanguage = CoreLanguageList.Japanese;

			CoreLanguageList.LanguageList.Add(CoreLanguageList.Japanese);
			CoreLanguageList.LanguageList.Add(CoreLanguageList.English);
		}

		public static CoreLanguageClass GetLanguageClassByName(string name)
		{
			Str.NormalizeStringStandard(ref name);

			foreach (CoreLanguageClass c in LanguageList)
			{
				if (Str.StrCmpi(c.Name, name))
				{
					return c;
				}
			}

			return DefaultLanguage;
		}

		public static CoreLanguageClass GetLangugageClassByEnum(CoreLanguage lang)
		{
			foreach (CoreLanguageClass c in LanguageList)
			{
				if (c.Language == lang)
				{
					return c;
				}
			}

			return DefaultLanguage;
		}
	}

	public static class Util
	{
		public const int SizeOfInt32 = 4;
		public const int SizeOfInt16 = 2;
		public const int SizeOfInt64 = 8;
		public const int SizeOfInt8 = 1;

		public static byte[] ToByte(ushort i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static byte[] ToByte(short i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static byte[] ToByte(uint i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static byte[] ToByte(int i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static byte[] ToByte(ulong i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static byte[] ToByte(long i)
		{
			byte[] ret = BitConverter.GetBytes(i);
			Endian(ret);
			return ret;
		}
		public static ushort ByteToUShort(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToUInt16(c, 0);
		}
		public static short ByteToShort(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToInt16(c, 0);
		}
		public static uint ByteToUInt(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToUInt32(c, 0);
		}
		public static int ByteToInt(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToInt32(c, 0);
		}
		public static ulong ByteToULong(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToUInt64(c, 0);
		}
		public static long ByteToLong(byte[] b)
		{
			byte[] c = CloneByteArray(b);
			Endian(c);
			return BitConverter.ToInt64(c, 0);
		}

		public static byte[] ReadAllFromStream(Stream st)
		{
			byte[] tmp = new byte[32 * 1024];
			Buf b = new Buf();

			while (true)
			{
				int r = st.Read(tmp, 0, tmp.Length);

				if (r == 0)
				{
					break;
				}

				b.Write(tmp, 0, r);
			}

			return b.ByteData;
		}

		public static List<T> CloneList<T>(List<T> src)
		{
			List<T> ret = new List<T>();
			foreach (T t in src)
			{
				ret.Add(t);
			}
			return ret;
		}

		public static byte[] ExtractByteArray(byte[] data, int pos, int len)
		{
			byte[] ret = new byte[len];

			Util.CopyByte(ret, 0, data, pos, len);

			return ret;
		}

		public static T[] CombineArray<T>(params T[][] arrays)
		{
			List<T> o = new List<T>();
			foreach (T[] array in arrays)
			{
				foreach (T element in array)
				{
					o.Add(element);
				}
			}
			return o.ToArray();
		}

		public static byte[] CombineByteArray(byte[] b1, byte[] b2)
		{
			Buf b = new Buf();

			if (b1 != null)
			{
				b.Write(b1);
			}

			if (b2 != null)
			{
				b.Write(b2);
			}

			return b.ByteData;
		}

		public static byte[] RemoveStartByteArray(byte[] src, int numBytes)
		{
			if (numBytes == 0)
			{
				return src;
			}
			int num = src.Length - numBytes;
			byte[] ret = new byte[num];
			Util.CopyByte(ret, 0, src, numBytes, num);
			return ret;
		}

		public static DateTime[] GetYearNendoList(DateTime startYear, DateTime endYear)
		{
			startYear = GetStartOfNendo(startYear);
			endYear = GetEndOfNendo(endYear);

			if (startYear > endYear)
			{
				throw new ArgumentException();
			}

			List<DateTime> ret = new List<DateTime>();

			DateTime dt;
			for (dt = startYear; dt <= endYear; dt = GetStartOfNendo(dt.AddYears(1)))
			{
				ret.Add(dt);
			}

			return ret.ToArray();
		}

		public static DateTime[] GetYearList(DateTime startYear, DateTime endYear)
		{
			startYear = GetStartOfYear(startYear);
			endYear = GetEndOfYear(endYear);

			if (startYear > endYear)
			{
				throw new ArgumentException();
			}

			List<DateTime> ret = new List<DateTime>();

			DateTime dt;
			for (dt = startYear; dt <= endYear; dt = GetStartOfYear(dt.AddYears(1)))
			{
				ret.Add(dt);
			}

			return ret.ToArray();
		}

		public static DateTime[] GetMonthList(DateTime startMonth, DateTime endMonth)
		{
			startMonth = GetStartOfMonth(startMonth);
			endMonth = GetEndOfMonth(endMonth);

			if (startMonth > endMonth)
			{
				throw new ArgumentException();
			}

			List<DateTime> ret = new List<DateTime>();

			DateTime dt;
			for (dt = startMonth; dt <= endMonth; dt = GetStartOfMonth(dt.AddMonths(1)))
			{
				ret.Add(dt);
			}

			return ret.ToArray();
		}

		public static int GetAge(DateTime birthDay, DateTime now)
		{
			birthDay = birthDay.Date;
			now = now.Date;

			DateTime dayBirthDay = new DateTime(2000, birthDay.Month, birthDay.Day);
			DateTime dayNow = new DateTime(2000, now.Month, now.Day);

			int ret = now.Year - birthDay.Year;

			if (dayBirthDay > dayNow)
			{
				ret -= 1;
			}

			return Math.Max(ret, 0);
		}

		public static int GetNumOfDaysInMonth(DateTime dt)
		{
			DateTime dt1 = new DateTime(dt.Year, dt.Month, dt.Day);
			DateTime dt2 = dt1.AddMonths(1);
			TimeSpan span = dt2 - dt1;

			return span.Days;
		}

		public static int GetNumMonthSpan(DateTime dt1, DateTime dt2, bool kiriage)
		{
			if (dt1 > dt2)
			{
				DateTime dtt = dt2;
				dt2 = dt1;
				dt1 = dtt;
			}

			int i;
			DateTime dt = dt1;
			for (i = 0; ; i++)
			{
				if (kiriage)
				{
					if (dt >= dt2)
					{
						return i;
					}
				}
				else
				{
					if (dt >= dt2.AddMonths(1).AddTicks(-1))
					{
						return i;
					}
				}

				dt = dt.AddMonths(1);
			}
		}

		public static DateTime GetStartOfMonth(DateTime dt)
		{
			return new DateTime(dt.Year, dt.Month, 1);
		}

		public static DateTime GetEndOfMonth(DateTime dt)
		{
			return new DateTime(dt.Year, dt.Month, 1).AddMonths(1).AddSeconds(-1).Date;
		}

		public static DateTime GetStartOfYear(DateTime dt)
		{
			return new DateTime(dt.Year, 1, 1, 0, 0, 0);
		}

		public static DateTime GetEndOfYear(DateTime dt)
		{
			return GetStartOfYear(dt).AddYears(1).AddSeconds(-1).Date;
		}

		public static DateTime GetEndOfMonthForSettle(DateTime dt)
		{
			dt = new DateTime(dt.Year, dt.Month, 1).AddMonths(1).AddSeconds(-1).Date;
			if (dt.Month == 4 && (new DateTime(dt.Year, 4, 29).DayOfWeek == DayOfWeek.Sunday))
			{
				dt = dt.AddDays(1);
			}
			while ((dt.DayOfWeek == DayOfWeek.Sunday || dt.DayOfWeek == DayOfWeek.Saturday) ||
				(dt.Month == 12 && dt.Day >= 29) ||
				(dt.Month == 1 && dt.Day <= 3))
			{
				dt = dt.AddDays(1);
			}
			return dt;
		}

		public static DateTime GetStartOfDay(DateTime dt)
		{
			return dt.Date;
		}

		public static DateTime GetEndOfDate(DateTime dt)
		{
			return GetStartOfDay(dt).AddDays(1).AddTicks(-1);
		}

		public static int GetNendo(DateTime dt)
		{
			if (dt.Month >= 4)
			{
				return dt.Year;
			}
			else
			{
				return dt.Year - 1;
			}
		}

		public static DateTime GetStartOfNendo(DateTime dt)
		{
			return GetStartOfNendo(GetNendo(dt));
		}
		public static DateTime GetStartOfNendo(int nendo)
		{
			return new DateTime(nendo, 4, 1, 0, 0, 0).Date;
		}

		public static DateTime GetEndOfNendo(DateTime dt)
		{
			return GetEndOfNendo(GetNendo(dt));
		}
		public static DateTime GetEndOfNendo(int nendo)
		{
			return new DateTime(nendo + 1, 3, 31, 0, 0, 0).Date;
		}

		public static void Endian(byte[] b)
		{
			if (Env.IsLittleEndian)
			{
				Array.Reverse(b);
			}
		}
		public static byte[] EndianRetByte(byte[] b)
		{
			b = Util.CloneByteArray(b);

			Endian(b);

			return b;
		}
		public static UInt16 Endian(UInt16 v)
		{
			return Util.ByteToUShort(Util.EndianRetByte(Util.ToByte(v)));
		}
		public static UInt32 Endian(UInt32 v)
		{
			return Util.ByteToUInt(Util.EndianRetByte(Util.ToByte(v)));
		}
		public static UInt64 Endian(UInt64 v)
		{
			return Util.ByteToULong(Util.EndianRetByte(Util.ToByte(v)));
		}

		public static string SafeDomainStr(string str)
		{
			string ret = str.Replace("(", "").Replace(")", "").Replace(" ", "").Replace("-", "").Replace("#", "")
				.Replace("%", "").Replace("%", "").Replace("&", "").Replace(".", "");
			if (ret == "")
			{
				ret = "host";
			}

			return ret;
		}

		public static byte[] CopyByte(byte[] src)
		{
			return (byte[])src.Clone();
		}
		public static byte[] CopyByte(byte[] src, int srcOffset)
		{
			return CopyByte(src, srcOffset, src.Length - srcOffset);
		}
		public static byte[] CopyByte(byte[] src, int srcOffset, int size)
		{
			byte[] ret = new byte[size];
			CopyByte(ret, 0, src, srcOffset, size);
			return ret;
		}
		public static void CopyByte(byte[] dst, byte[] src, int srcOffset, int size)
		{
			CopyByte(dst, 0, src, srcOffset, size);
		}
		public static void CopyByte(byte[] dst, int dstOffset, byte[] src)
		{
			CopyByte(dst, dstOffset, src, 0, src.Length);
		}
		public static void CopyByte(byte[] dst, int dstOffset, byte[] src, int srcOffset, int size)
		{
			Array.Copy(src, srcOffset, dst, dstOffset, size);
		}

		public static bool IsZero(byte[] data)
		{
			return IsZero(data, 0, data.Length);
		}
		public static bool IsZero(byte[] data, int offset, int size)
		{
			int i;
			for (i = offset; i < offset + size; i++)
			{
				if (data[i] != 0)
				{
					return false;
				}
			}
			return true;
		}

		public static bool CompareByte(byte[] b1, byte[] b2)
		{
			if (b1.Length != b2.Length)
			{
				return false;
			}
			int i, len;
			len = b1.Length;
			for (i = 0; i < len; i++)
			{
				if (b1[i] != b2[i])
				{
					return false;
				}
			}
			return true;
		}

		public static int CompareByteRetInt(byte[] b1, byte[] b2)
		{
			int i;
			for (i = 0; ; i++)
			{
				int a1 = -1, a2 = -1;
				if (b1.Length < i)
				{
					a1 = (int)b1[i];
				}
				if (b2.Length < i)
				{
					a2 = (int)b2[i];
				}

				if (a1 > a2)
				{
					return 1;
				}
				else if (a1 < a2)
				{
					return -1;
				}
				if (a1 == -1 && a2 == -1)
				{
					return 0;
				}
			}
		}

		public static byte[] CloneByteArray(byte[] src)
		{
			byte[] ret = new byte[src.Length];

			Util.CopyByte(ret, src, 0, src.Length);

			return ret;
		}

		public static DateTime UnixTimeToDateTime(uint t)
		{
			return new DateTime(1970, 1, 1).AddSeconds(t);
		}

		public static uint DateTimeToUnixTime(DateTime dt)
		{
			TimeSpan ts = dt - new DateTime(1970, 1, 1);
			if (ts.Ticks < 0)
			{
				throw new InvalidDataException("dt");
			}

			return (uint)ts.TotalSeconds;
		}

		public static DateTime ConvertDateTime(ulong time64)
		{
			if (time64 == 0)
			{
				return new DateTime(0);
			}
			return new DateTime(((long)time64 + 62135629200000) * 10000);
		}

		public static ulong ConvertDateTime(DateTime dt)
		{
			if (dt.Ticks == 0)
			{
				return 0;
			}
			return (ulong)dt.Ticks / 10000 - 62135629200000;
		}

		public static TimeSpan ConvertTimeSpan(ulong tick)
		{
			return new TimeSpan((long)tick * 10000);
		}

		public static ulong ConvertTimeSpan(TimeSpan span)
		{
			return (ulong)span.Ticks / 10000;
		}

		public static ushort DateTimeToDosDate(DateTime dt)
		{
			return (ushort)(
				((uint)(dt.Year - 1980) << 9) |
				((uint)dt.Month << 5) |
				(uint)dt.Day);
		}

		public static ushort DateTimeToDosTime(DateTime dt)
		{
			return (ushort)(
				((uint)dt.Hour << 11) |
				((uint)dt.Minute << 5) |
				((uint)dt.Second >> 1));
		}

		public static bool IsNullOrEmpty(object o)
		{
			if (o == null)
			{
				return true;
			}

			if (o is string)
			{
				string s = (string)o;

				return Str.IsEmptyStr(s);
			}

			if (o is Array)
			{
				Array a = (Array)o;
				if (a.Length == 0)
				{
					return true;
				}
			}

			return false;
		}

		public static byte[] GetXmlSchemaFromType(Type type)
		{
			XmlSchemas sms = new XmlSchemas();
			XmlSchemaExporter ex = new XmlSchemaExporter(sms);
			XmlReflectionImporter im = new XmlReflectionImporter();
			XmlTypeMapping map = im.ImportTypeMapping(type);
			ex.ExportTypeMapping(map);
			sms.Compile(null, false);

			MemoryStream ms = new MemoryStream();
			StreamWriter sw = new StreamWriter(ms);
			foreach (System.Xml.Schema.XmlSchema sm in sms)
			{
				sm.Write(sw);
			}
			sw.Close();
			ms.Flush();

			byte[] data = ms.ToArray();
			return data;
		}
		public static string GetXmlSchemaFromTypeString(Type type)
		{
			byte[] data = GetXmlSchemaFromType(type);

			return Str.Utf8Encoding.GetString(data);
		}

		public static string ObjectToXmlString(object o)
		{
			byte[] data = ObjectToXml(o);

			return Str.Utf8Encoding.GetString(data);
		}
		public static byte[] ObjectToXml(object o)
		{
			if (o == null)
			{
				return null;
			}
			Type t = o.GetType();

			return ObjectToXml(o, t);
		}
		public static string ObjectToXmlString(object o, Type t)
		{
			byte[] data = ObjectToXml(o, t);

			return Str.Utf8Encoding.GetString(data);
		}
		public static byte[] ObjectToXml(object o, Type t)
		{
			if (o == null)
			{
				return null;
			}

			MemoryStream ms = new MemoryStream();
			XmlSerializer x = new XmlSerializer(t);

			x.Serialize(ms, o);

			return ms.ToArray();
		}

		public static object XmlToObject(string str, Type t)
		{
			if (Str.IsEmptyStr(str))
			{
				return null;
			}

			byte[] data = Str.Utf8Encoding.GetBytes(str);

			return XmlToObject(data, t);
		}
		public static object XmlToObject(byte[] data, Type t)
		{
			if (data == null || data.Length == 0)
			{
				return null;
			}

			MemoryStream ms = new MemoryStream();
			ms.Write(data, 0, data.Length);
			ms.Position = 0;

			XmlSerializer x = new XmlSerializer(t);

			return x.Deserialize(ms);
		}

		public static void NoOP(object o)
		{
		}
		public static void NoOP()
		{
		}

		public static bool False
		{
			get
			{
				return false;
			}
		}

		public static bool True
		{
			get
			{
				return true;
			}
		}

		public static int Zero
		{
			get
			{
				return 0;
			}
		}

		public static object ByteToStruct(byte[] src, Type type)
		{
			int size = src.Length;
			if (size != SizeOfStruct(type))
			{
				throw new SystemException("size error");
			}

			IntPtr p = Marshal.AllocHGlobal(size);

			try
			{
				Marshal.Copy(src, 0, p, size);

				return Marshal.PtrToStructure(p, type);
			}
			finally
			{
				Marshal.FreeHGlobal(p);
			}
		}

		public static byte[] StructToByte(object obj)
		{
			int size = SizeOfStruct(obj);
			IntPtr p = Marshal.AllocHGlobal(size);
			try
			{
				Marshal.StructureToPtr(obj, p, false);

				byte[] ret = new byte[size];

				Marshal.Copy(p, ret, 0, size);

				return ret;
			}
			finally
			{
				Marshal.FreeHGlobal(p);
			}
		}

		public static int SizeOfStruct(object obj)
		{
			return Marshal.SizeOf(obj);
		}
		public static int SizeOfStruct(Type type)
		{
			return Marshal.SizeOf(type);
		}

		public static XmlAndXsd GenerateXmlAndXsd(object obj)
		{
			XmlAndXsd ret = new XmlAndXsd();
			Type type = obj.GetType();

			ret.XsdFileName = Str.MakeSafeFileName(type.Name + ".xsd");
			ret.XsdData = GetXmlSchemaFromType(type);

			ret.XmlFileName = Str.MakeSafeFileName(type.Name + ".xml");
			string str = Util.ObjectToXmlString(obj);
			str = str.Replace(
				"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"",
				"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xsi:noNamespaceSchemaLocation=\""
				+ ret.XsdFileName
				+ "\"");
			ret.XmlData = Str.Utf8Encoding.GetBytes(str);

			return ret;
		}
	}

	public class XmlAndXsd
	{
		public byte[] XmlData;
		public byte[] XsdData;
		public string XmlFileName;
		public string XsdFileName;
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
