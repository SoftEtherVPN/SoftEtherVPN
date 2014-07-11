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
using System.Runtime.InteropServices;

namespace CoreUtil
{
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct ZipDataHeader
	{
		public uint Signature;
		public ushort NeedVer;
		public ushort Option;
		public ushort CompType;
		public ushort FileTime;
		public ushort FileDate;
		public uint Crc32;
		public uint CompSize;
		public uint UncompSize;
		public ushort FileNameLen;
		public ushort ExtraLen;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct ZipDataFooter
	{
		public uint Signature;
		public uint Crc32;
		public uint CompSize;
		public uint UncompSize;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct ZipDirHeader
	{
		public uint Signature;
		public ushort MadeVer;
		public ushort NeedVer;
		public ushort Option;
		public ushort CompType;
		public ushort FileTime;
		public ushort FileDate;
		public uint Crc32;
		public uint CompSize;
		public uint UncompSize;
		public ushort FileNameLen;
		public ushort ExtraLen;
		public ushort CommentLen;
		public ushort DiskNum;
		public ushort InAttr;
		public uint OutAttr;
		public uint HeaderPos;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct ZipEndHeader
	{
		public uint Signature;
		public ushort DiskNum;
		public ushort StartDiskNum;
		public ushort DiskDirEntry;
		public ushort DirEntry;
		public uint DirSize;
		public uint StartPos;
		public ushort CommentLen;
	}

	public static class ZipUtil
	{
		static ZipUtil()
		{
			initCrc32();
		}

		static uint[] table;
		const int crcTableSize = 256;

		static void initCrc32()
		{
			table = new uint[crcTableSize];

			uint poly = 0xEDB88320;
			uint u, i, j;

			for (i = 0; i < 256; i++)
			{
				u = i;

				for (j = 0; j < 8; j++)
				{
					if ((u & 0x1) != 0)
					{
						u = (u >> 1) ^ poly;
					}
					else
					{
						u >>= 1;
					}
				}

				table[i] = u;
			}
		}

		public static uint Crc32(byte[] buf)
		{
			return Crc32(buf, 0, buf.Length);
		}
		public static uint Crc32(byte[] buf, int pos, int len)
		{
			return Crc32Finish(Crc32First(buf, pos, len));
		}
		public static uint Crc32First(byte[] buf, int pos, int len)
		{
			return Crc32Next(buf, pos, len, 0xffffffff);
		}
		public static uint Crc32Next(byte[] buf, int pos, int len, uint lastCrc32)
		{
			uint ret = lastCrc32;
			for (uint i = 0; i < len; i++)
			{
				ret = (ret >> 8) ^ table[buf[pos + i] ^ (ret & 0xff)];
			}
			return ret;
		}
		public static uint Crc32Finish(uint lastCrc32)
		{
			return ~lastCrc32;
		}
	}

	public class ZipPacker
	{
		public const uint Signature = 0x04034B50;
		public const uint SignatureEnd = 0x06054B50;
		public const ushort Version = 10;
		public const ushort VersionWithCompress = 20;
		public Encoding Encoding = Str.ShiftJisEncoding;

		class File
		{
			public string Name;
			public long Size;
			public DateTime DateTime;
			public FileAttributes Attributes;
			public long CurrentSize;
			public long CompressSize;
			public uint Crc32;
			public uint HeaderPos;
			public Encoding Encoding;
			public bool Compress;
			public CoreUtil.Internal.ZStream ZStream;

			public void WriteZipDataHeader(ref ZipDataHeader h, bool writeSizes)
			{
				h.Signature = Signature;
				h.NeedVer = Version;
				h.CompType = 0;
				h.FileTime = Util.DateTimeToDosTime(this.DateTime);
				h.FileDate = Util.DateTimeToDosDate(this.DateTime);
				h.Option = 8;

				if (writeSizes == false)
				{
					h.CompSize = h.UncompSize = 0;
					h.Crc32 = 0;

					if (this.Compress)
					{
						h.NeedVer = VersionWithCompress;
						h.CompType = 8;
					}
				}
				else
				{
					h.CompSize = h.UncompSize = (uint)this.Size;
					if (this.Compress)
					{
						h.CompSize = (uint)this.CompressSize;
                        h.CompType = 8;
                    }
					h.Crc32 = this.Crc32;
				}

				h.FileNameLen = (ushort)this.Encoding.GetByteCount(this.Name);
				h.ExtraLen = 0;
			}

			public void WriteZipDataFooter(ref ZipDataFooter h)
			{
				h.Signature = 0x08074B50;

				if (this.Compress == false)
				{
					h.CompSize = h.UncompSize = (uint)this.Size;
				}
				else
				{
					h.CompSize = (uint)this.CompressSize;
					h.UncompSize = (uint)this.Size;
				}
				h.Crc32 = this.Crc32;
			}
		}

		Fifo fifo;
		List<File> fileList;

		public Fifo GeneratedData
		{
			get
			{
				return this.fifo;
			}
		}

		public ZipPacker()
		{
			fifo = new Fifo();
			fileList = new List<File>();
		}

		File currentFile = null;

		public void AddFileSimple(string name, DateTime dt, FileAttributes attribute, byte[] data)
		{
			AddFileSimple(name, dt, attribute, data, false);
		}
		public void AddFileSimple(string name, DateTime dt, FileAttributes attribute, byte[] data, bool compress)
		{
			AddFileStart(name, data.Length, dt, attribute, compress);
			AddFileData(data, 0, data.Length);
		}

		public void AddFileStart(string name, long size, DateTime dt, FileAttributes attribute)
		{
			AddFileStart(name, size, dt, attribute, false);
		}
		public void AddFileStart(string name, long size, DateTime dt, FileAttributes attribute, bool compress)
		{
			if (currentFile != null)
			{
				throw new ApplicationException("currentFile != null");
			}

			name = name.Replace("/", "\\");

			File f = new File();

			f.Encoding = this.Encoding;
			f.Name = name;
			f.Size = size;
			f.DateTime = dt;
			f.Attributes = attribute;
			f.Compress = compress;

			this.fileList.Add(f);

			ZipDataHeader h = new ZipDataHeader();
			f.HeaderPos = (uint)fifo.TotalWriteSize;
			f.WriteZipDataHeader(ref h, false);
			fifo.Write(Util.StructToByte(h));
			fifo.Write(this.Encoding.GetBytes(f.Name));
			f.Crc32 = 0xffffffff;

			if (compress)
			{
				f.ZStream = new CoreUtil.Internal.ZStream();
				f.ZStream.deflateInit(-1, -15);
			}

			currentFile = f;
		}

		public long AddFileData(byte[] data, int pos, int len)
		{
			long totalSize = currentFile.CurrentSize + len;

			if (totalSize > currentFile.Size)
			{
				throw new ApplicationException("totalSize > currentFile.Size");
			}

			if (currentFile.Compress == false)
			{
				fifo.Write(data, pos, len);
			}
			else
			{
				CoreUtil.Internal.ZStream zs = currentFile.ZStream;

				byte[] srcData = Util.ExtractByteArray(data, pos, len);
				byte[] dstData = new byte[srcData.Length * 2 + 100];

				zs.next_in = srcData;
				zs.avail_in = srcData.Length;
				zs.next_in_index = 0;

				zs.next_out = dstData;
				zs.avail_out = dstData.Length;
				zs.next_out_index = 0;

				if (currentFile.Size == (currentFile.CurrentSize + len))
				{
					zs.deflate(CoreUtil.Internal.zlibConst.Z_FINISH);
				}
				else
				{
					zs.deflate(CoreUtil.Internal.zlibConst.Z_SYNC_FLUSH);
				}

				fifo.Write(dstData, 0, dstData.Length - zs.avail_out);

				currentFile.CompressSize += dstData.Length - zs.avail_out;

				Util.NoOP();
			}

			currentFile.CurrentSize += len;

			currentFile.Crc32 = ZipUtil.Crc32Next(data, pos, len, currentFile.Crc32);

			long ret = currentFile.Size - currentFile.CurrentSize;

			if (ret == 0)
			{
				currentFile.Crc32 = ~currentFile.Crc32;
				addFileFooter();

				currentFile = null;
			}

			return ret;
		}

		void addFileFooter()
		{
			ZipDataFooter f = new ZipDataFooter();
			currentFile.WriteZipDataFooter(ref f);
			fifo.Write(Util.StructToByte(f));
		}

		public void Finish()
		{
			long posStart = fifo.TotalWriteSize;
			foreach (File f in this.fileList)
			{
				ZipDirHeader d = new ZipDirHeader();
				d.Signature = 0x02014B50;// ZipPacker.Signature;
				d.MadeVer = Version;
				ZipDataHeader dh = new ZipDataHeader();
				f.WriteZipDataHeader(ref dh, true);
				if (f.Compress)
				{
					dh.CompType = 8;
					dh.CompSize = (uint)f.CompressSize;
					dh.NeedVer = ZipPacker.VersionWithCompress;
				}
				d.NeedVer = dh.NeedVer;
				d.Option = dh.Option;
				d.CompType = dh.CompType;
				d.FileTime = dh.FileTime;
				d.FileDate = dh.FileDate;
				d.Crc32 = dh.Crc32;
				d.CompSize = dh.CompSize;
				d.UncompSize = dh.UncompSize;
				d.FileNameLen = dh.FileNameLen;
				d.ExtraLen = dh.ExtraLen;
				d.CommentLen = 0;
				d.DiskNum = 0;
				d.InAttr = 0;
				d.OutAttr = (ushort)f.Attributes;
				d.HeaderPos = f.HeaderPos;

				fifo.Write(Util.StructToByte(d));
				fifo.Write(this.Encoding.GetBytes(f.Name));
			}
			long posEnd = fifo.TotalWriteSize;

			ZipEndHeader e = new ZipEndHeader();
			e.Signature = ZipPacker.SignatureEnd;
			e.DiskNum = e.StartDiskNum = 0;
			e.DiskDirEntry = e.DirEntry = (ushort)this.fileList.Count;
			e.DirSize = (uint)(posEnd - posStart);
			e.StartPos = (uint)posStart;
			e.CommentLen = 0;
			fifo.Write(Util.StructToByte(e));
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
