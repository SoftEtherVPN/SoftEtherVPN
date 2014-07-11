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
	internal class HamCoreEntry : IComparable
	{
		public string FileName = "";
		public uint Size = 0;
		public uint SizeCompressed = 0;
		public uint Offset = 0;
		public byte[] Buffer = null;
		public long LastAccess = 0;

		public int CompareTo(object obj)
		{
			HamCoreEntry hc1, hc2;
			hc1 = this;
			hc2 = (HamCoreEntry)obj;

			return Str.StrCmpiRetInt(hc1.FileName, hc2.FileName);
		}
	}

	public class HamCoreBuilderFileEntry : IComparable<HamCoreBuilderFileEntry>
	{
		public string Name;
		public Buf RawData;
		public Buf CompressedData;
		public int Offset = 0;

		int IComparable<HamCoreBuilderFileEntry>.CompareTo(HamCoreBuilderFileEntry other)
		{
			return this.Name.CompareTo(other.Name);
		}
	}

	public class HamCoreBuilder
	{
		List<HamCoreBuilderFileEntry> fileList;
		public List<HamCoreBuilderFileEntry> FileList
		{
			get { return fileList; }
		}

		public bool IsFile(string name)
		{
			foreach (HamCoreBuilderFileEntry f in fileList)
			{
				if (f.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase))
				{
					return true;
				}
			}

			return false;
		}

		public bool DeleteFile(string name)
		{
			foreach (HamCoreBuilderFileEntry f in fileList)
			{
				if (f.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase))
				{
					fileList.Remove(f);
					return true;
				}
			}

			return false;
		}

		public HamCoreBuilder()
		{
			fileList = new List<HamCoreBuilderFileEntry>();
		}

		public void AddDir(string dirName)
		{
			dirName = IO.RemoteLastEnMark(dirName);

			DirEntry[] ee = IO.EnumDirEx(dirName);

			foreach (DirEntry e in ee)
			{
				if (e.IsFolder == false)
				{
					AddFile(e.FullPath, dirName);
				}
			}
		}

		public void AddFile(string fileName, string baseDirFileName)
		{
			string name = IO.GetRelativeFileName(fileName, baseDirFileName);

			AddFile(name, File.ReadAllBytes(fileName));
		}

		public void AddFile(string name, byte[] data)
		{
			if (IsFile(name))
			{
				throw new InvalidOperationException("fileName");
			}

			HamCoreBuilderFileEntry f = new HamCoreBuilderFileEntry();

			Console.Write("{0}: ", name);

			f.Name = name;
			f.RawData = new Buf(Util.CloneByteArray(data));
			Console.Write("{0} -> ", f.RawData.Size);
			f.CompressedData = new Buf(ZLib.Compress(f.RawData.ByteData));
			Console.WriteLine("{0}", f.CompressedData.Size);

			this.fileList.Add(f);
		}

		public void Build(string dstFileName)
		{
			Buf b = Build();

			IO.SaveFile(dstFileName, b.ByteData);
		}

		public Buf Build()
		{
			int z;
			Buf b;

			this.fileList.Sort();

			z = 0;

			z += HamCore.HamcoreHeaderSize;

			z += sizeof(int);

			foreach (HamCoreBuilderFileEntry f in this.fileList)
			{
				z += Str.ShiftJisEncoding.GetByteCount(f.Name) + sizeof(int);
				z += sizeof(int);
				z += sizeof(int);
				z += sizeof(int);
			}
			foreach (HamCoreBuilderFileEntry f in this.fileList)
			{
				f.Offset = z;
				z += (int)f.CompressedData.Size;
			}

			b = new Buf();
			b.Write(Str.ShiftJisEncoding.GetBytes(HamCore.HamcoreHeaderData));
			b.WriteInt((uint)this.fileList.Count);
			foreach (HamCoreBuilderFileEntry f in this.fileList)
			{
				b.WriteStr(f.Name, true);
				b.WriteInt(f.RawData.Size);
				b.WriteInt(f.CompressedData.Size);
				b.WriteInt((uint)f.Offset);
			}
			foreach (HamCoreBuilderFileEntry f in this.fileList)
			{
				b.Write(f.CompressedData.ByteData);
			}

			b.SeekToBegin();

			return b;
		}
	}

	public class HamCore
	{
		public const string HamcoreDirName = "@hamcore";
		public const string HamcoreHeaderData = "HamCore";
		public const int HamcoreHeaderSize = 7;
		public const long HamcoreCacheExpires = 5 * 60 * 1000;
		bool disableReadRawFile = false;
		public bool DisableReadRawFile
		{
			get { return disableReadRawFile; }
			set { disableReadRawFile = value; }
		}

		Dictionary<string, HamCoreEntry> list;

		IO hamcore_io;

		public HamCore(string filename)
		{
			init(filename);
		}

		public string[] GetFileNames()
		{
			List<string> ret = new List<string>();

			foreach (HamCoreEntry e in list.Values)
			{
				ret.Add(e.FileName);
			}

			return ret.ToArray();
		}

		void init(string filename)
		{
			filename = IO.InnerFilePath(filename);
			string filenameOnly = Path.GetFileName(filename);
			string filenameAlt = Path.Combine(Path.GetDirectoryName(filename), "_" + filenameOnly);

			try
			{
				IO.FileReplaceRename(filenameAlt, filename);
			}
			catch
			{
			}

			list = new Dictionary<string, HamCoreEntry>();

			try
			{
				hamcore_io = IO.FileOpen(filename);
			}
			catch
			{
				return;
			}

			try
			{
				byte[] header = hamcore_io.Read(HamcoreHeaderSize);
				byte[] header2 = Str.AsciiEncoding.GetBytes(HamcoreHeaderData);
				if (header == null || Util.CompareByte(header, header2) == false)
				{
					throw new SystemException();
				}

				uint num = 0;
				byte[] buf = hamcore_io.Read(Util.SizeOfInt32);
				num = Util.ByteToUInt(buf);
				uint i;
				for (i = 0; i < num; i++)
				{
					uint str_size;

					buf = hamcore_io.Read(Util.SizeOfInt32);
					str_size = Util.ByteToUInt(buf);
					if (str_size >= 1)
					{
						str_size--;
					}

					byte[] str_data = hamcore_io.Read((int)str_size);
					string tmp = Str.ShiftJisEncoding.GetString(str_data);

					HamCoreEntry c = new HamCoreEntry();
					c.FileName = tmp;

					buf = hamcore_io.Read(Util.SizeOfInt32);
					c.Size = Util.ByteToUInt(buf);

					buf = hamcore_io.Read(Util.SizeOfInt32);
					c.SizeCompressed = Util.ByteToUInt(buf);

					buf = hamcore_io.Read(Util.SizeOfInt32);
					c.Offset = Util.ByteToUInt(buf);

					list.Add(c.FileName.ToUpper(), c);
				}
			}
			catch
			{
				hamcore_io.Close();
			}
		}

		public Buf ReadHamcore(string name)
		{
			if (name[0] == '|')
			{
				name = name.Substring(1);
			}
			if (name[0] == '/' || name[0] == '\\')
			{
				name = name.Substring(1);
			}

			string filename = name;

			filename = filename.Replace("/", "\\");

			Buf b;

			if (this.disableReadRawFile == false)
			{
				try
				{
					b = Buf.ReadFromFile(HamcoreDirName + "\\" + filename);

					return b;
				}
				catch
				{
				}
			}

			lock (list)
			{
				HamCoreEntry c;
				string key = filename.ToUpper();

				b = null;

				if (list.ContainsKey(key))
				{
					c = list[key];

					if (c.Buffer != null)
					{
						b = new Buf(c.Buffer);
						b.SeekToBegin();
						c.LastAccess = Time.Tick64;
					}
					else
					{
						if (hamcore_io.Seek(SeekOrigin.Begin, (int)c.Offset))
						{
							byte[] data = hamcore_io.Read((int)c.SizeCompressed);

							int dstSize = (int)c.Size;
							byte[] buffer = ZLib.Uncompress(data, dstSize);

							c.Buffer = buffer;
							b = new Buf(buffer);
							b.SeekToBegin();
							c.LastAccess = Time.Tick64;
						}
					}
				}

				long now = Time.Tick64;
				foreach (HamCoreEntry cc in list.Values)
				{
					if (cc.Buffer != null)
					{
						if (((cc.LastAccess + HamcoreCacheExpires) < now) ||
							cc.FileName.StartsWith("Li", StringComparison.CurrentCultureIgnoreCase))
						{
							cc.Buffer = null;
						}
					}
				}
			}

			return b;
		}
	}

	public class DirEntry : IComparable<DirEntry>
	{
		internal bool folder;
		public bool IsFolder
		{
			get { return folder; }
		}
		internal string fileName;
		public string FileName
		{
			get { return fileName; }
		}
		internal string fullPath;
		public string FullPath
		{
			get { return fullPath; }
		}
		internal string relativePath;
		public string RelativePath
		{
			get { return relativePath; }
		}
		internal long fileSize;
		public long FileSize
		{
			get { return fileSize; }
		}
		internal DateTime createDate;
		public DateTime CreateDate
		{
			get { return createDate; }
		}
		internal DateTime updateDate;
		public DateTime UpdateDate
		{
			get { return updateDate; }
		}

		public int CompareTo(DirEntry other)
		{
			int i;
			i = Str.StrCmpiRetInt(this.fileName, other.fileName);
			if (i == 0)
			{
				i = Str.StrCmpRetInt(this.fileName, other.fileName);
			}

			return i;
		}

		public override string ToString()
		{
			return FileName;
		}
	};

	public class IO
	{
		public delegate bool CopyDirPreCopyDelegate(FileInfo srcFileInfo);
		public static void CopyDir(string srcDirName, string destDirName, CopyDirPreCopyDelegate preCopy, bool ignoreError, bool printStatus)
		{
			CopyDir(srcDirName, destDirName, preCopy, ignoreError, printStatus, false, false, false);
		}
		public static void CopyDir(string srcDirName, string destDirName, CopyDirPreCopyDelegate preCopy, bool ignoreError, bool printStatus,
			bool skipIfNoChange, bool deleteBom)
		{
			CopyDir(srcDirName, destDirName, preCopy, ignoreError, printStatus, skipIfNoChange, deleteBom, false);
		}
		public static void CopyDir(string srcDirName, string destDirName, CopyDirPreCopyDelegate preCopy, bool ignoreError, bool printStatus,
			bool skipIfNoChange, bool deleteBom, bool useTimeStampToCheckNoChange)
		{
			string[] files = Directory.GetFiles(srcDirName, "*", SearchOption.AllDirectories);

			foreach (string srcFile in files)
			{
				FileInfo info = new FileInfo(srcFile);

				string relativeFileName = IO.GetRelativeFileName(srcFile, srcDirName);
				string destFileName = Path.Combine(destDirName, relativeFileName);
				string destFileDirName = Path.GetDirectoryName(destFileName);

				if (preCopy != null)
				{
					if (preCopy(info) == false)
					{
						continue;
					}
				}

				try
				{
					if (Directory.Exists(destFileDirName) == false)
					{
						Directory.CreateDirectory(destFileDirName);
					}

					FileCopy(srcFile, destFileName, skipIfNoChange, deleteBom, useTimeStampToCheckNoChange);
				}
				catch
				{
					if (ignoreError == false)
					{
						throw;
					}
				}

				if (printStatus)
				{
					Con.WriteLine(relativeFileName);
				}
			}
		}

		public const string DefaultHamcoreFileName = "@hamcore.se2";

		static string hamcoreFileName = DefaultHamcoreFileName;
		public static string HamcoreFileName
		{
			get { return IO.hamcoreFileName; }
			set
			{
				lock (hamLockObj)
				{
					if (hamCore != null)
					{
						throw new ApplicationException();
					}

					IO.hamcoreFileName = value;
					tryToUseHamcore = false;
				}
			}
		}

		static bool tryToUseHamcore = true;
		static HamCore hamCore = null;
		static object hamLockObj = new object();
		public static HamCore HamCore
		{
			get
			{
				HamCore ret = null;

				lock (hamLockObj)
				{
					if (hamCore == null)
					{
						if (tryToUseHamcore)
						{
							if (hamCore == null)
							{
								try
								{
									ret = hamCore = new HamCore(hamcoreFileName);
								}
								catch
								{
									tryToUseHamcore = false;
								}
							}
						}
					}
				}

				return ret;
			}
		}

		string name;
		public string Name
		{
			get { return name; }
		}
		FileStream p;
		public FileStream InnerFileStream
		{
			get { return p; }
		}
		bool writeMode;
		public bool WriteMode
		{
			get { return writeMode; }
		}
		bool hamMode;
		public bool HamMode
		{
			get { return hamMode; }
		}
		Buf hamBuf;

		object lockObj;

		private IO()
		{
			name = "";
			p = null;
			writeMode = hamMode = false;
			lockObj = new object();
			hamBuf = null;
		}

		~IO()
		{
			Close();
		}

		public static void WriteAllTextWithEncoding(string fileName, string str, Encoding encoding)
		{
			WriteAllTextWithEncoding(fileName, str, encoding, false);
		}
		public static void WriteAllTextWithEncoding(string fileName, string str, Encoding encoding, bool appendBom)
		{
			fileName = InnerFilePath(fileName);

			byte[] data = encoding.GetBytes(str);
			byte[] bom = null;
			if (appendBom)
			{
				bom = Str.GetBOM(encoding);
			}

			data = Util.CombineByteArray(bom, data);

			File.WriteAllBytes(fileName, data);
		}

		public static string ReadAllTextWithAutoGetEncoding(string fileName)
		{
			fileName = InnerFilePath(fileName);

			byte[] data = File.ReadAllBytes(fileName);

			int bomSize;
			Encoding enc = Str.GetEncoding(data, out bomSize);
			if (enc == null)
			{
				enc = Encoding.Default;
			}

			data = Util.RemoveStartByteArray(data, bomSize);

			return enc.GetString(data);
		}

		public static IO CreateTempFileByExt(string ext)
		{
			return IO.FileCreate(CreateTempFileNameByExt(ext));
		}

		public static string CreateTempFileNameByExt(string ext)
		{
			if (Str.IsEmptyStr(ext))
			{
				ext = "tmp";
			}
			if (ext[0] == '.')
			{
				ext = ext.Substring(1);
			}

			while (true)
			{
				string newFilename;
				string fullPath;
				string randStr;

				randStr = Str.GenRandStr();
				newFilename = "__" + randStr + "." + ext;

				fullPath = CreateTempFileName(newFilename);

				if (IO.IsFileExists(fullPath) == false)
				{
					return fullPath;
				}
			}
		}

		public static IO CreateTempFile(string name)
		{
			return IO.FileCreate(CreateTempFileName(name));
		}

		public static string CreateTempFileName(string name)
		{
			return Path.Combine(Env.MyTempDir, name);
		}

		public static DirEntry[] EnumDirEx(string dirName)
		{
			List<DirEntry> list = new List<DirEntry>();

			enumDirEx(dirName, dirName, list);

			return list.ToArray();
		}
		static void enumDirEx(string dirName, string baseDirName, List<DirEntry> list)
		{
			string tmp = IO.InnerFilePath(dirName);

			string[] dirs = Directory.GetDirectories(tmp);
			foreach (string name in dirs)
			{
				string fullPath = name;
				DirectoryInfo info = new DirectoryInfo(fullPath);

				DirEntry e = new DirEntry();

				e.fileName = Path.GetFileName(name);
				e.fileSize = 0;
				e.createDate = info.CreationTimeUtc;
				e.folder = true;
				e.updateDate = info.LastWriteTimeUtc;
				e.fullPath = fullPath;
				e.relativePath = GetRelativeFileName(fullPath, baseDirName);

				list.Add(e);

				enumDirEx(fullPath, baseDirName, list);
			}

			string[] files = Directory.GetFiles(tmp);
			foreach (string name in files)
			{
				string fullPath = name;
				FileInfo info = new FileInfo(fullPath);

				DirEntry e = new DirEntry();

				e.fileName = Path.GetFileName(name);
				e.fileSize = info.Length;
				e.createDate = info.CreationTimeUtc;
				e.folder = false;
				e.updateDate = info.LastWriteTimeUtc;
				e.fullPath = fullPath;
				e.relativePath = GetRelativeFileName(fullPath, baseDirName);

				list.Add(e);
			}
		}

		public static DirEntry[] EnumDir(string dirName)
		{
			List<DirEntry> list = new List<DirEntry>();
			string tmp = IO.InnerFilePath(dirName);

			string[] dirs = Directory.GetDirectories(tmp);
			foreach (string name in dirs)
			{
				string fullPath = name;
				DirectoryInfo info = new DirectoryInfo(fullPath);

				DirEntry e = new DirEntry();

				e.fileName = Path.GetFileName(name);
				e.fileSize = 0;
				e.createDate = info.CreationTimeUtc;
				e.folder = true;
				e.updateDate = info.LastWriteTimeUtc;
				e.fullPath = fullPath;
				e.relativePath = GetRelativeFileName(fullPath, dirName);

				list.Add(e);
			}

			string[] files = Directory.GetFiles(tmp);
			foreach (string name in files)
			{
				string fullPath = name;
				FileInfo info = new FileInfo(fullPath);

				DirEntry e = new DirEntry();

				e.fileName = Path.GetFileName(name);
				e.fileSize = info.Length;
				e.createDate = info.CreationTimeUtc;
				e.folder = false;
				e.updateDate = info.LastWriteTimeUtc;
				e.fullPath = fullPath;
				e.relativePath = GetRelativeFileName(fullPath, dirName);

				list.Add(e);
			}

			list.Sort();

			return list.ToArray();
		}

		public static void FileReplaceRename(string oldName, string newName)
		{
			try
			{
				FileCopy(oldName, newName);
				FileDelete(oldName);
			}
			catch (Exception e)
			{
				throw e;
			}
		}

		public static void FileCopy(string oldName, string newName)
		{
			FileCopy(oldName, newName, false, false);
		}
		public static void FileCopy(string oldName, string newName, bool skipIfNoChange, bool deleteBom)
		{
			FileCopy(oldName, newName, skipIfNoChange, deleteBom, false);
		}
		public static void FileCopy(string oldName, string newName, bool skipIfNoChange, bool deleteBom, bool useTimeStampToCheckNoChange)
		{
			string tmp1 = InnerFilePath(oldName);
			string tmp2 = InnerFilePath(newName);

			if (useTimeStampToCheckNoChange && skipIfNoChange)
			{
				DateTime dt1, dt2;

				try
				{
					dt1 = Directory.GetLastWriteTimeUtc(tmp1);
					dt2 = Directory.GetLastWriteTimeUtc(tmp2);

					TimeSpan ts = dt2 - dt1;
					if (ts.TotalSeconds >= -5.0)
					{
						return;
					}
				}
				catch
				{
				}
			}

			if (skipIfNoChange || deleteBom)
			{
				byte[] srcData = File.ReadAllBytes(tmp1);
				byte[] destData = new byte[0];
				bool changed = true;
				int bomSize;

				Str.GetEncoding(srcData, out bomSize);
				if (bomSize >= 1)
				{
					srcData = Util.ExtractByteArray(srcData, bomSize, srcData.Length - bomSize);
				}

				if (skipIfNoChange)
				{
					try
					{
						FileStream fs = File.OpenRead(tmp2);
						long size = 0xffffffff;
						try
						{
							size = fs.Length;
						}
						finally
						{
							fs.Close();
						}

						if (size == srcData.Length || srcData.Length == 0)
						{
							destData = File.ReadAllBytes(tmp2);
						}
					}
					catch
					{
					}

					if (Util.CompareByte(srcData, destData))
					{
						changed = false;
					}
				}

				if (changed)
				{
					File.WriteAllBytes(tmp2, srcData);
					CopyFileTimestamp(tmp2, tmp1);
				}
			}
			else
			{
				File.Copy(tmp1, tmp2, true);
			}
		}

		public static void CopyFileTimestamp(string dstFileName, string srcFileName)
		{
			DateTime dt1 = File.GetCreationTimeUtc(srcFileName);
			DateTime dt2 = File.GetLastAccessTimeUtc(srcFileName);
			DateTime dt3 = File.GetLastWriteTimeUtc(srcFileName);

			File.SetCreationTimeUtc(dstFileName, dt1);
			File.SetLastAccessTimeUtc(dstFileName, dt2);
			File.SetLastWriteTimeUtc(dstFileName, dt3);
		}

		public static void SetFileTimestamp(string dstFileName, FileInfo fi)
		{
			File.SetCreationTimeUtc(dstFileName, fi.CreationTimeUtc);
			File.SetLastAccessTimeUtc(dstFileName, fi.LastAccessTimeUtc);
			File.SetLastWriteTimeUtc(dstFileName, fi.LastWriteTimeUtc);
		}

		static public byte[] ReadFile(string name)
		{
			IO io = FileOpen(name);
			try
			{
				int size = io.FileSize;
				byte[] ret = io.Read(size);
				return ret;
			}
			finally
			{
				io.Close();
			}
		}

		static public void SaveFile(string name, byte[] data)
		{
			SaveFile(name, data, 0, data.Length);
		}
		static public void SaveFile(string name, byte[] data, int offset, int size)
		{
			IO io = FileCreate(name);
			try
			{
				io.Write(data, offset, size);
			}
			finally
			{
				io.Close();
			}
		}

		static public string MakeSafeFileName(string src)
		{
			return src
				.Replace("..", "__")
				.Replace("/", "_")
				.Replace("\\", "_")
				.Replace("@", "_")
				.Replace("|", "_");
		}

		public static bool IsDirExists(string name)
		{
			string tmp = InnerFilePath(name);

			return Directory.Exists(tmp);
		}

		public static bool IsFileExists(string name)
		{
			string tmp = InnerFilePath(name);

			return File.Exists(tmp);
		}

		static void fileDeleteInner(string name)
		{
			string name2 = ConvertPath(name);

			File.Delete(name2);
		}
		public static void FileDelete(string name)
		{
			string tmp = InnerFilePath(name);

			fileDeleteInner(tmp);
		}

		public bool Seek(SeekOrigin mode, int offset)
		{
			lock (lockObj)
			{
				if (p != null)
				{
					try
					{
						p.Seek(offset, mode);

						return true;
					}
					catch
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
		}

		public long FileSize64
		{
			get
			{
				lock (lockObj)
				{
					if (p != null)
					{
						return p.Length;
					}
					else
					{
						if (hamMode)
						{
							return (long)hamBuf.Size;
						}
					}

					return 0;
				}
			}
		}
		public int FileSize
		{
			get
			{
				long size64 = this.FileSize64;

				if (size64 >= 2147483647)
				{
					size64 = 2147483647;
				}

				return (int)size64;
			}
		}
		public static int GetFileSize(string name)
		{
			IO io = IO.FileOpen(name, false);
			try
			{
				return io.FileSize;
			}
			finally
			{
				io.Close();
			}
		}

		public byte[] ReadAll()
		{
			this.Seek(SeekOrigin.Begin, 0);
			int size = this.FileSize;

			byte[] data = new byte[size];
			this.Read(data, 0, size);

			this.Seek(SeekOrigin.Begin, 0);

			return data;
		}

		public byte[] Read(int size)
		{
			byte[] buf = new byte[size];
			bool ret = Read(buf, size);
			if (ret == false)
			{
				return null;
			}
			return buf;
		}
		public bool Read(byte[] buf, int size)
		{
			return Read(buf, 0, size);
		}
		public bool Read(byte[] buf, int offset, int size)
		{
			if (size == 0)
			{
				return true;
			}

			lock (lockObj)
			{
				if (this.HamMode)
				{
					byte[] ret = hamBuf.Read((uint)size);

					if (ret.Length != size)
					{
						return false;
					}

					Util.CopyByte(buf, offset, ret, 0, size);

					return true;
				}

				if (p != null)
				{
					try
					{
						int ret = p.Read(buf, offset, size);
						if (ret == size)
						{
							return true;
						}
						else
						{
							return false;
						}
					}
					catch
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
		}

		public bool Write(byte[] buf)
		{
			return Write(buf, 0, buf.Length);
		}
		public bool Write(byte[] buf, int size)
		{
			return Write(buf, 0, size);
		}
		public bool Write(byte[] buf, int offset, int size)
		{
			if (writeMode == false)
			{
				return false;
			}
			if (size == 0)
			{
				return true;
			}

			lock (lockObj)
			{
				if (p != null)
				{
					try
					{
						p.Write(buf, offset, size);

						return true;
					}
					catch
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
		}

		public bool CloseAndDelete()
		{
			string name = this.Name;

			Close();

			try
			{
				FileDelete(name);
				return true;
			}
			catch
			{
				return false;
			}
		}

		public void Close()
		{
			Close(false);
		}
		public void Close(bool noFlush)
		{
			lock (this.lockObj)
			{
				if (this.hamMode == false)
				{
					if (this.p != null)
					{
						if (this.writeMode && noFlush == false)
						{
							Flush();
						}

						this.p.Close();
					}

					this.p = null;
				}
			}
		}

		public void Flush()
		{
			try
			{
				lock (this.lockObj)
				{
					if (this.p != null)
					{
						this.p.Flush();
					}
				}
			}
			catch
			{
			}
		}

		static IO fileCreateInner(string name)
		{
			IO o = new IO();

			string name2 = ConvertPath(name);

			lock (o.lockObj)
			{
				o.p = File.Open(name2, FileMode.Create, FileAccess.ReadWrite, FileShare.Read);
				o.name = name2;
				o.writeMode = true;
			}

			return o;
		}

		public static IO FileCreate(string name)
		{
			name = InnerFilePath(name);

			return fileCreateInner(name);
		}

		static IO fileOpenInner(string name, bool writeMode, bool readLock)
		{
			IO o = new IO();

			string name2 = ConvertPath(name);

			lock (o.lockObj)
			{
				o.p = File.Open(name2, FileMode.Open, (writeMode ? FileAccess.ReadWrite : FileAccess.Read),
					(readLock ? FileShare.None : FileShare.Read));

				o.name = name2;
				o.writeMode = writeMode;
			}

			return o;
		}

		public static IO FileOpen(string name)
		{
			return FileOpen(name, false);
		}
		public static IO FileOpen(string name, bool writeMode)
		{
			return FileOpen(name, writeMode, false);
		}
		public static IO FileOpen(string name, bool writeMode, bool readLock)
		{
			name = InnerFilePath(name);

			if (name[0] == '|')
			{
				HamCore hc = IO.HamCore;

				Buf b = hc.ReadHamcore(name);
				if (b == null)
				{
					throw new FileNotFoundException();
				}

				IO o = new IO();
				o.name = name.Substring(1);
				o.hamMode = true;
				o.hamBuf = b;

				return o;
			}
			else
			{
				return fileOpenInner(name, writeMode, readLock);
			}
		}

		public static IO FileCreateOrAppendOpen(string name)
		{
			if (IsFileExists(name))
			{
				IO io = FileOpen(name, true);
				io.Seek(SeekOrigin.End, 0);
				return io;
			}
			else
			{
				return FileCreate(name);
			}
		}

		public static string GetRelativeFileName(string fileName, string baseDirName)
		{
			baseDirName = RemoteLastEnMark(baseDirName).Trim() + "\\";
			fileName = fileName.Trim();

			if (fileName.Length <= baseDirName.Length)
			{
				throw new ArgumentException("fileName, baseDirName");
			}

			if (fileName.StartsWith(baseDirName, StringComparison.InvariantCultureIgnoreCase) == false)
			{
				throw new ArgumentException("fileName, baseDirName");
			}

			return fileName.Substring(baseDirName.Length);
		}

		public static string RemoteLastEnMark(string path)
		{
			if (path == null)
			{
				path = "";
			}
			if (path.EndsWith("\\"))
			{
				path = path.Substring(0, path.Length - 1);
			}
			return path;
		}

		public static void FileRename(string oldName, string newName)
		{
			string tmp1 = InnerFilePath(oldName);
			string tmp2 = InnerFilePath(newName);

			File.Move(tmp1, tmp2);
		}

		public static void DeleteFilesAndSubDirsInDir(string dirName)
		{
			dirName = InnerFilePath(dirName);

			if (Directory.Exists(dirName) == false)
			{
				Directory.CreateDirectory(dirName);
				return;
			}

			string[] files = Directory.GetFiles(dirName);
			string[] dirs = Directory.GetDirectories(dirName);

			foreach (string file in files)
			{
				File.SetAttributes(file, FileAttributes.Normal);
				File.Delete(file);
			}

			foreach (string dir in dirs)
			{
				Directory.Delete(dir, true);
			}
		}

		public static bool DeleteDir(string dirName)
		{
			return DeleteDir(dirName, false);
		}
		public static bool DeleteDir(string dirName, bool deleteSubDirs)
		{
			try
			{
				Directory.Delete(InnerFilePath(dirName), deleteSubDirs);
				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool MakeDir(string dirName)
		{
			try
			{
				Directory.CreateDirectory(InnerFilePath(dirName));
				return true;
			}
			catch
			{
				return false;
			}
		}
		public static bool MakeDirIfNotExists(string dirName)
		{
			string path = InnerFilePath(dirName);

			if (Directory.Exists(path) == false)
			{
				Directory.CreateDirectory(path);

				return true;
			}

			return false;
		}

		public static string NormalizePath(string src)
		{
			bool first_double_slash = false;
			bool first_single_slash = false;
			string win32_drive_char = "";
			int i;
			string tmp;

			tmp = ConvertPath(src).Trim();

			if (tmp.StartsWith(".\\") || tmp.StartsWith("..\\") || tmp.StartsWith(".") || tmp.StartsWith(".."))
			{
				if (tmp.StartsWith(".."))
				{
					tmp = Env.CurrentDir + "/../" + tmp.Substring(2);
				}
				else
				{
					tmp = Env.CurrentDir + "/" + tmp;
				}
			}

			if (tmp.StartsWith("~/") || tmp.StartsWith("~\\"))
			{
				tmp = Env.HomeDir + "/" + tmp.Substring(2);
			}

			if (tmp.StartsWith("//") || tmp.StartsWith("\\\\"))
			{
				first_double_slash = true;
			}
			else
			{
				if (tmp.StartsWith("/") || tmp.StartsWith("\\"))
				{
					first_single_slash = true;
				}
			}

			if (tmp.Length >= 2)
			{
				if (tmp[1] == ':')
				{
					win32_drive_char = "" + tmp[0];
					tmp = tmp.Substring(2);
				}
			}

			if (tmp == "/" || tmp == "\\")
			{
				tmp = "";
			}

			char[] splitChars = { '/', '\\' };
			string[] t = tmp.Split(splitChars, StringSplitOptions.RemoveEmptyEntries);

			Stack<string> sk = new Stack<string>();

			for (i = 0; i < t.Length; i++)
			{
				string s = t[i];

				if (Str.StrCmpi(s, "."))
				{
					continue;
				}
				else if (Str.StrCmpi(s, ".."))
				{
					if (sk.Count >= 1 && (first_double_slash == false || sk.Count >= 2))
					{
						sk.Pop();
					}
				}
				else
				{
					sk.Push(s);
				}
			}

			tmp = "";

			if (first_double_slash)
			{
				tmp += "//";
			}
			else if (first_single_slash)
			{
				tmp += "/";
			}

			if (Str.IsEmptyStr(win32_drive_char) == false)
			{
				tmp = win32_drive_char + ":/" + tmp;
			}

			string[] sks = sk.ToArray();
			Array.Reverse(sks);
			for (i = 0; i < sks.Length; i++)
			{
				tmp += sks[i];
				if (i != (sks.Length - 1))
				{
					tmp += "/";
				}
			}

			tmp = ConvertPath(tmp);

			return tmp;
		}

		public static string ConvertPath(string path)
		{
			return path.Replace('/', '\\');
		}

		public static string ConbinePath(string dirname, string filename)
		{
			return CombinePath(dirname, filename);
		}
		public static string CombinePath(string dirname, string filename)
		{
			bool is_full_path;
			string filename_ident = NormalizePath(filename);

			is_full_path = false;

			if (filename_ident.StartsWith("\\") || filename_ident.StartsWith("/"))
			{
				is_full_path = true;
			}

			filename = filename_ident;

			if (filename.Length >= 2)
			{
				char c = filename[0];
				if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'))
				{
					if (filename[1] == ':')
					{
						is_full_path = true;
					}
				}
			}

			string tmp;

			if (is_full_path == false)
			{
				tmp = dirname;
				if (tmp.EndsWith("/") == false && tmp.EndsWith("\\") == false)
				{
					tmp += "/";
				}

				tmp += filename;
			}
			else
			{
				tmp = filename;
			}

			return NormalizePath(tmp);
		}

		public static string InnerFilePath(string src)
		{
			if (src[0] != '@')
			{
				return NormalizePath(src);
			}
			else
			{
				return CombinePath(Env.ExeFileDir, src.Substring(1));
			}
		}

		public static DateTime GetCreationTimeUtc(string filename)
		{
			return File.GetCreationTimeUtc(InnerFilePath(filename));
		}
		public static DateTime GetCreationTimeLocal(string filename)
		{
			return File.GetCreationTime(InnerFilePath(filename));
		}

		public static DateTime GetLastWriteTimeUtc(string filename)
		{
			return File.GetLastWriteTimeUtc(InnerFilePath(filename));
		}
		public static DateTime GetLastWriteTimeLocal(string filename)
		{
			return File.GetLastWriteTime(InnerFilePath(filename));
		}

		public static DateTime GetLastAccessTimeUtc(string filename)
		{
			return File.GetLastAccessTimeUtc(InnerFilePath(filename));
		}
		public static DateTime GetLastAccessTimeLocal(string filename)
		{
			return File.GetLastAccessTime(InnerFilePath(filename));
		}

		public static byte[] ReadFileData(string filename)
		{
			FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			try
			{
				long size = fs.Length;
				int size2 = (int)Math.Min(size, int.MaxValue);
				byte[] ret = new byte[size2];
				fs.Read(ret, 0, size2);
				return ret;
			}
			finally
			{
				fs.Close();
			}
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
