using System;
using System.Text;
using System.Collections.Generic;
using System.IO;

public class Str
{
	static Encoding asciiEncoding = Encoding.ASCII;
	public static Encoding AsciiEncoding
	{
		get { return Str.asciiEncoding; }
	}

	static Encoding utf8Encoding = Encoding.UTF8;
	public static Encoding Utf8Encoding
	{
		get { return Str.utf8Encoding; }
	}

	static Encoding uniEncoding = Encoding.Unicode;
	public static Encoding UniEncoding
	{
		get { return Str.uniEncoding; }
	}

	public static string ByteToHex3(byte[] data)
	{
		if (data.Length == 0)
		{
			return "";
		}

		return BitConverter.ToString(data) + "-";
	}

	public static string ByteToHex(byte[] data)
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
		}

		return ret.ToString();
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

	public static string ByteToStr(byte[] data, Encoding enc)
	{
		try
		{
			return enc.GetString(data);
		}
		catch
		{
			return "";
		}
	}

	public static byte[] StrToByte(string str, Encoding enc)
	{
		try
		{
			return enc.GetBytes(str);
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
			if (Util.StrCmpi(a, b))
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
		return s1.CompareTo(s2);
	}
	public static bool StrCmp(string s1, string s2)
	{
		return StrCmpRetInt(s1, s2) == 0 ? true : false;
	}
	public static int StrCmpiRetInt(string s1, string s2)
	{
		s1 = s1.ToUpper();
		s2 = s2.ToUpper();
		return StrCmpRetInt(s1, s2);
	}
	public static bool StrCmpi(string s1, string s2)
	{
		return StrCmpiRetInt(s1, s2) == 0 ? true : false;
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

	public static bool IsNumber(string str)
	{
		str = str.Trim();

		foreach (char c in str)
		{
			if (c >= '0' && c <= '9')
			{
			}
			else
			{
				return false;
			}
		}

		return true;
	}

	public static string DateToString(DateTime dt)
	{
		if (dt.Ticks != 0)
		{
			return dt.ToString("yyyyMMdd HHmmss").Substring(2);
		}
		else
		{
			return "000000_000000";
		}
	}

	public static DateTime StringToDate(string str)
	{
		str = str.Replace("(JST)", "").Trim();

		try
		{
			return DateTime.Parse(str);
		}
		catch
		{
			return new DateTime(0);
		}
	}

	public static string ToSafeString(string str)
	{
		char[] chars =
				{
					';', '?', '=', '<', '>', ':', '@', '%', '$', '\\', '/', '|', '\"', '\r', '\n',
				};

		string ret = str;
		foreach (char c in chars)
		{
			ret = ret.Replace(c, '_');
		}

		string ret2 = "";

		foreach (char c in ret)
		{
			bool b = false;

			if (c >= 0x00 && c <= 0x1f)
			{
				b = true;
			}

			if (c >= 0x7f && c <= 0xff)
			{
				b = true;
			}

			if (b == false)
			{
				ret2 += c;
			}
			else
			{
				ret2 += "_";
			}
		}

		return ret2;
	}

	public static byte[] Base64Decode(string src)
	{
		try
		{
			return System.Convert.FromBase64String(src);
		}
		catch
		{
			return null;
		}
	}

	public static string DecodeMime(string src)
	{
		string[] s = src.Split('?');
		byte[] b;
		if (s[2] == "B")
		{
			b = System.Convert.FromBase64String(s[3]);
		}
		else
		{
			throw new Exception("Bad Encode.");
		}
		string ret = System.Text.Encoding.GetEncoding(s[1]).GetString(b);

		if (s.Length >= 4)
		{
			string tmp = s[s.Length - 1];

			if (tmp.StartsWith("="))
			{
				ret += tmp.Substring(1);
			}
		}

		return ret;
	}

	public static bool HasNullChar(string str)
	{
		if (str.IndexOf('\0') != -1)
		{
			return true;
		}

		return false;
	}

	public static bool IsMailHeaderStr(string str)
	{
		if (str == null)
		{
			return false;
		}
		if (HasNullChar(str))
		{
			return false;
		}

		string[] sep = { ": " };
		string[] tokens = str.Split(sep, StringSplitOptions.RemoveEmptyEntries);

		if (tokens.Length >= 2)
		{
			return true;
		}

		return false;
	}

	public static bool IsStrForBase64(string str)
	{
		string b64str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=";

		foreach (char c in str)
		{
			bool b = false;

			foreach (char c2 in b64str)
			{
				if (c == c2)
				{
					b = true;
					break;
				}
			}

			if (b == false)
			{
				return false;
			}
		}

		return true;
	}

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
			return Util.StrToUInt(strValue);
		}
	}

	public ulong Int64Value
	{
		get
		{
			return Util.StrToULong(strValue);
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
