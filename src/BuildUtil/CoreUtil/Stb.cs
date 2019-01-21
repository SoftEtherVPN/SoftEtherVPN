// CoreUtil


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
