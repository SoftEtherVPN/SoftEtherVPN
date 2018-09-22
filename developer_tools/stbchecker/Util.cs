using System;
using System.Text;
using System.Collections;
using System.Security.Cryptography;
using System.Web;
using System.IO;
using System.Drawing;

public class Util
{
	public static string TruncStr(string str, int len)
	{
		if (str.Length <= len)
		{
			return str;
		}
		else
		{
			return str.Substring(len);
		}
	}

	public static string GenRand()
	{
		return ByteToStr(Hash(Guid.NewGuid().ToByteArray()));
	}

	public static bool StrCmpi(string s1, string s2)
	{
		try
		{
			if (s1.ToUpper() == s2.ToUpper())
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

	public static Encoding UTF8()
	{
		return Encoding.UTF8;
	}

	public static Encoding EucJP()
	{
		return Encoding.GetEncoding("euc-jp");
	}

	public static Encoding ShiftJIS()
	{
		return Encoding.GetEncoding("shift_jis");
	}

	public static byte[] Hash(string str)
	{
		return Hash(Encoding.UTF8.GetBytes(str));
	}

	public static byte[] Hash(byte[] data)
	{
		SHA1 sha1 = SHA1.Create();
		return sha1.ComputeHash(data);
	}

	public static string ByteToStr(byte[] data)
	{
		StringBuilder sb = new StringBuilder();
		foreach (byte b in data)
		{
			sb.Append(b.ToString("X2"));
		}

		return sb.ToString();
	}

	public static string RandToStr6(string rand)
	{
		byte[] hash = Hash(rand + "packetix.net");
		return ByteToStr(hash).Substring(0, 6);
	}

	public static bool CheckImageRand(string rand, string str)
	{
		string s = RandToStr6(rand);
		string tmp = str.ToUpper();
		tmp = tmp.Replace("O", "0").Replace("I", "1");
		return StrCmpi(s, tmp);
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
			c == ',' || c == '?' || c == '/')
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

	public static string GetFileSizeStr(int size)
	{
		if (size >= 1024 * 1024)
		{
			return ((double)(size) / 1024.0f / 1024.0f).ToString(".##") + " MB";
		}
		if (size >= 1024)
		{
			return ((double)(size) / 1024.0f).ToString(".##") + " KB";
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

	public static int StrToInt(string str)
	{
		try
		{
			return int.Parse(str);
		}
		catch
		{
			try
			{
				return (int)double.Parse(str);
			}
			catch
			{
				return 0;
			}
		}
	}
	public static uint StrToUInt(string str)
	{
		try
		{
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
			return ulong.Parse(str);
		}
		catch
		{
			return 0;
		}
	}

	public static DateTime StrToDate(string str)
	{
		DateTime ret = new DateTime(0);
		str = str.Trim();
		if (str.Length == 8)
		{
			int year = StrToInt(str.Substring(0, 4));
			int month = StrToInt(str.Substring(4, 2));
			int day = StrToInt(str.Substring(6, 2));

			ret = new DateTime(year, month, day);
		}
		return ret;
	}

	public static string SafeSql(string str)
	{
		return str.Replace("'", "");
	}

	public static bool IsFileExists(string name)
	{
		try
		{
			return File.Exists(name);
		}
		catch
		{
			return false;
		}
	}

	public static string GetDefaultDocumentIfExists(string dir)
	{
		string[] targets =
			{
				"default.aspx",
				"default.asp",
				"default.html",
				"default.htm",
				"index.html",
				"index.htm",
			};

		foreach (string s in targets)
		{
			string name = dir + s;

			if (IsFileExists(name))
			{
				return name;
			}
		}

		return null;
	}

	public static string ReadHtmlFile(string filename)
	{
		return File.ReadAllText(filename, Encoding.GetEncoding("shift_jis"));
	}

	public static string GetAlternativeTitleFromHtml(string src)
	{
		string tmp;
		string upper;
		int i;

		upper = src.ToLower();
		i = upper.IndexOf("</at>");
		if (i == -1)
		{
			return null;
		}

		tmp = src.Substring(0, i);

		i = tmp.IndexOf("<at>");
		if (i == -1)
		{
			return null;
		}

		string ret = tmp.Substring(i + 4);

		if (ret.Length == 0)
		{
			return null;
		}
		else
		{
			return ret;
		}
	}

	public static string GetTitleFromHtml(string src)
	{
		string tmp;
		string upper;
		int i;

		upper = src.ToLower();
		i = upper.IndexOf("</title>");
		if (i == -1)
		{
			return null;
		}

		tmp = src.Substring(0, i);

		i = tmp.IndexOf("<title>");
		if (i == -1)
		{
			return null;
		}

		return tmp.Substring(i + 7);
	}

	public static string GetTitleFromHtmlFile(string filename)
	{
		return GetTitleFromHtml(ReadHtmlFile(filename));
	}
	public static string GetAlternativeTitleFromHtmlFile(string filename)
	{
		return GetAlternativeTitleFromHtml(ReadHtmlFile(filename));
	}

	public static string GetUrlFileNameFromPath(string url)
	{
		string folder = GetUrlDirNameFromPath(url);

		return url.Substring(folder.Length);
	}

	public static string GetUrlDirNameFromPath(string url)
	{
		string ret = "";
		string[] strs = url.Split('/');
		int i;
		if (strs.Length >= 1)
		{
			for (i = 0; i < strs.Length - 1; i++)
			{
				ret += strs[i] + "/";
			}
		}
		return ret;
	}

	public static string Encode64(string str)
	{
		return Convert.ToBase64String(Encoding.UTF8.GetBytes(str)).Replace("/", "(").Replace("+", ")");
	}

	public static string Decode64(string str)
	{
		return Encoding.UTF8.GetString(Convert.FromBase64String(str.Replace(")", "+").Replace("(", "/")));
	}

	public static string RemoveDefaultHtml(string url)
	{
		string tmp = url.ToLower();
		if (tmp.EndsWith("/default.asp") || tmp.EndsWith("/default.aspx") || tmp.EndsWith("/default.htm") || tmp.EndsWith("/default.html"))
		{
			return GetUrlDirNameFromPath(url);
		}
		else
		{
			return url;
		}
	}

	public static string RemovePortFromHostHeader(string str)
	{
		try
		{
			string[] ret = str.Split(':');

			return ret[0];
		}
		catch
		{
			return str;
		}
	}

	public static string ToStr3(ulong v)
	{
		string tmp = LongToStr(v);
		int len, i;
		string tmp2 = "";

		len = tmp.Length;

		for (i = len - 1; i >= 0; i--)
		{
			tmp2 += tmp[i];
		}

		tmp = "";

		for (i = 0; i < len; i++)
		{
			if (i != 0 && (i % 3) == 0)
			{
				tmp += ",";
			}
			tmp += tmp2[i];
		}

		tmp2 = "";
		len = tmp.Length;

		for (i = len - 1; i >= 0; i--)
		{
			tmp2 += tmp[i];
		}

		return tmp2;
	}

	public static string DateTimeToStr(DateTime dt)
	{
		return DateTimeToStr(dt, false);
	}
	public static string DateTimeToStr(DateTime dt, bool toLocalTime)
	{
		if (toLocalTime)
		{
			dt = dt.ToLocalTime();
		}

		return dt.ToString("yyyy年M月d日(ddd) H時m分s秒");
	}

	public static byte[] IntToByte(uint value)
	{
		MemoryStream st = new MemoryStream();
		BinaryWriter w = new BinaryWriter(st);
		w.Write(value);
		st.Seek(0, SeekOrigin.Begin);
		return st.ToArray();
	}

	public static uint ByteToInt(byte[] b)
	{
		MemoryStream st = new MemoryStream();
		st.Write(b, 0, b.Length);
		st.Seek(0, SeekOrigin.Begin);
		BinaryReader r = new BinaryReader(st);
		return r.ReadUInt32();
	}

	public static byte[] ReverseByteArray(byte[] b)
	{
		int i, num, j;
		num = b.Length;
		byte[] ret = new byte[num];
		j = 0;

		for (i = num - 1; i >= 0; i--)
		{
			ret[j++] = b[i];
		}

		return ret;
	}

	public static uint ReverseEndian(uint value)
	{
		return ByteToInt(ReverseByteArray(IntToByte(value)));
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
		return (byte[])src.Clone();
	}
}
