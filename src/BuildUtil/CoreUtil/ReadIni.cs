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
using System.Security.Cryptography.X509Certificates;
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
	class IniCache
	{
		static Dictionary<string, IniCacheEntry> caches = new Dictionary<string, IniCacheEntry>();

		class IniCacheEntry
		{
			DateTime lastUpdate;
			public DateTime LastUpdate
			{
				get { return lastUpdate; }
			}

			Dictionary<string, string> datas;
			public Dictionary<string, string> Datas
			{
				get { return datas; }
			}

			public IniCacheEntry(DateTime lastUpdate, Dictionary<string, string> datas)
			{
				this.lastUpdate = lastUpdate;
				this.datas = datas;
			}
		}

		public static Dictionary<string, string> GetCache(string filename, DateTime lastUpdate)
		{
			lock (caches)
			{
				try
				{
					IniCacheEntry e = caches[filename];
					if (e.LastUpdate == lastUpdate || lastUpdate.Ticks == 0)
					{
						return e.Datas;
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
		}

		public static void AddCache(string filename, DateTime lastUpdate, Dictionary<string, string> datas)
		{
			lock (caches)
			{
				if (caches.ContainsKey(filename))
				{
					caches.Remove(filename);
				}

				caches.Add(filename, new IniCacheEntry(lastUpdate, datas));
			}
		}
	}

	public class ReadIni
	{
		Dictionary<string, string> datas;
		bool updated;

		public bool Updated
		{
			get
			{
				return updated;
			}
		}

		public StrData this[string key]
		{
			get
			{
				string s;
				try
				{
					s = datas[key.ToUpper()];
				}
				catch
				{
					s = null;
				}

				return new StrData(s);
			}
		}

		public string[] GetKeys()
		{
			List<string> ret = new List<string>();

			foreach (string s in datas.Keys)
			{
				ret.Add(s);
			}

			return ret.ToArray();
		}

		public ReadIni(string filename)
		{
			init(null, filename);
		}

		void init(byte[] data)
		{
			init(data, null);
		}
		void init(byte[] data, string filename)
		{
			updated = false;

			lock (typeof(ReadIni))
			{
				string[] lines;
				string srcstr;
				DateTime lastUpdate = new DateTime(0);

				if (filename != null)
				{
					lastUpdate = IO.GetLastWriteTimeUtc(filename);

					datas = IniCache.GetCache(filename, lastUpdate);
				}

				if (datas == null)
				{
					if (data == null)
					{
						try
						{
							data = Buf.ReadFromFile(filename).ByteData;
						}
						catch
						{
							data = new byte[0];
							datas = IniCache.GetCache(filename, new DateTime());
						}
					}

					if (datas == null)
					{
						datas = new Dictionary<string, string>();
						Encoding currentEncoding = Str.Utf8Encoding;
						srcstr = currentEncoding.GetString(data);

						lines = Str.GetLines(srcstr);

						foreach (string s in lines)
						{
							string line = s.Trim();

							if (Str.IsEmptyStr(line) == false)
							{
								if (line.StartsWith("#") == false &&
									line.StartsWith("//") == false &&
									line.StartsWith(";") == false)
								{
									string key, value;

									if (Str.GetKeyAndValue(line, out key, out value))
									{
										key = key.ToUpper();

										if (datas.ContainsKey(key) == false)
										{
											datas.Add(key, value);
										}
										else
										{
											int i;
											for (i = 1; ; i++)
											{
												string key2 = string.Format("{0}({1})", key, i).ToUpper();

												if (datas.ContainsKey(key2) == false)
												{
													datas.Add(key2, value);
													break;
												}
											}
										}
									}
								}
							}
						}

						if (filename != null)
						{
							IniCache.AddCache(filename, lastUpdate, datas);
						}

						updated = true;
					}
				}
			}
		}
	}
}

