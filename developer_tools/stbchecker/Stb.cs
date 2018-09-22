using System;
using System.Collections.Generic;
using System.IO;

public class StbTable
{
	List<string> tagList;
	public string[] TagList
	{
		get
		{
			return tagList.ToArray();
		}
	}

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

	public StbTable(string name, string str)
	{
		this.name = name;
		this.str = str;

		tagList = ParseTagList(str);
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

	public static StbTable ParseTableLine(string line, ref string prefix)
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

		return new StbTable(name2, str);
	}

	public static bool CompareTagList(string[] list1, string[] list2)
	{
		if (list1.Length != list2.Length)
		{
			return false;
		}

		int i;
		for (i = 0; i < list1.Length; i++)
		{
			if (list1[i] != list2[i])
			{
				return false;
			}
		}

		return true;
	}

	public static List<string> ParseTagList(string str)
	{
		List<string> list = new List<string>();
		int i, len;
		int mode = 0;
		string tmp = "";

		str += "_";

		len = str.Length;

		for (i = 0; i < len; i++)
		{
			char c = str[i];

			if (mode == 0)
			{
				switch (c)
				{
					case '%':
						if (str[i + 1] == '%')
						{
							i++;
							tmp += c;
						}
						else
						{
							mode = 1;
							tmp = "" + c;
						}
						break;

					default:
						tmp = "" + c;
						break;
				}
			}
			else
			{
				string tag;

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
					case 'n':
					case 'N':
					case 's':
					case 'S':
					case 'r':
					case ' ':
						tmp += c;
						tag = tmp;
						list.Add(tag);
						mode = 0;
						break;
					default:
						tmp += c;
						break;
				}
			}
		}

		return list;
	}
}

public class Stb
{
	Dictionary<string, StbTable> tableList;
	string name;
	public string Name
	{
		get { return name; }
	}

	public Stb(string fileName)
	{
		init(File.ReadAllBytes(fileName), fileName);
	}

	public Stb(string fileName, string name)
	{
		init(File.ReadAllBytes(fileName), name);
	}

	public Stb(byte[] data, string name)
	{
		init(data, name);
	}

	void init(byte[] data, string name)
	{
		if (data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
		{
			byte[] tmp = new byte[data.Length - 3];
			Array.Copy(data, 3, tmp, 0, data.Length - 3);
			data = tmp;
		}

		StringReader sr = new StringReader(Str.Utf8Encoding.GetString(data));
		tableList = new Dictionary<string, StbTable>();

		this.name = name;
		string prefix = "";

		while (true)
		{
			string tmp = sr.ReadLine();
			if (tmp == null)
			{
				break;
			}

			StbTable t = StbTable.ParseTableLine(tmp, ref prefix);
			if (t != null)
			{
				if (tableList.ContainsKey(t.Name.ToUpper()) == false)
				{
					tableList.Add(t.Name.ToUpper(), t);
				}
				else
				{
					ShowWarning(name, string.Format("Duplicated '{0}'", t.Name));
				}
			}
		}
	}

	protected static void ShowWarning(string name, string str)
	{
		Console.WriteLine("{0}: Warning: {1}", name, str);
	}

	protected static void ShowError(string name, string str)
	{
		Console.WriteLine("{0}: Error: {1}", name, str);
	}

	public static int Compare(string file1, string file2)
	{
		Stb stb1 = new Stb(file1, "File1");
		Stb stb2 = new Stb(file2, "File2");
		int num = 0;

		string file1_fn = Path.GetFileName(file1);
		string file2_fn = Path.GetFileName(file2);

		foreach (string name1 in stb1.tableList.Keys)
		{
			if (name1.Equals("DEFAULT_FONT_WIN7", StringComparison.InvariantCultureIgnoreCase) ||
				name1.Equals("DEFAULT_FONT_HIGHDPI", StringComparison.InvariantCultureIgnoreCase))
			{
				continue;
			}

			StbTable t1 = stb1.tableList[name1];

			if (stb2.tableList.ContainsKey(name1) == false)
			{
				ShowError(stb2.name, string.Format("Missing '{0}'", t1.Name));
				num++;
			}
			else
			{
				StbTable t2 = stb2.tableList[name1];

				if (StbTable.CompareTagList(t1.TagList, t2.TagList) == false)
				{
					ShowError(stb2.name, string.Format("Difference printf-style parameters '{0}'", t1.Name));
					num++;
				}
			}
		}

		Console.WriteLine("\nThere are {0} errors.\n\n{1}\n", num,
			(num == 0 ? "Good work! No problem!" : "You must correct them before sending us Pull Requests!"));

		return num;
	}
}
