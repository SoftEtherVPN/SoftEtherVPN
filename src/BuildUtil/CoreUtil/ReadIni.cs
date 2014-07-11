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


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
