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
using System.IO.Compression;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using CoreUtil.Internal;

namespace CoreUtil
{
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct GZipHeader
	{
		public byte ID1, ID2, CM, FLG;
		public uint MTIME;
		public byte XFL, OS;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct GZipFooter
	{
		public uint CRC32;
		public uint ISIZE;
	}

	public static class GZipUtil
	{
		public static byte[] Decompress(byte[] gzip)
		{
			using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
			{
				const int size = 4096;
				byte[] buffer = new byte[size];
				using (MemoryStream memory = new MemoryStream())
				{
					int count = 0;
					do
					{
						count = stream.Read(buffer, 0, size);
						if (count > 0)
						{
							memory.Write(buffer, 0, count);
						}
					}
					while (count > 0);
					return memory.ToArray();
				}
			}
		}
	}

	public class GZipPacker
	{
		Fifo fifo;
		ZStream zs;
		long currentSize;
		uint crc32;
		bool finished;

		public bool Finished
		{
			get { return finished; }
		}

		public Fifo GeneratedData
		{
			get
			{
				return this.fifo;
			}
		}

		public GZipPacker()
		{
			fifo = new Fifo();

			zs = new ZStream();
			zs.deflateInit(-1, -15);

			this.currentSize = 0;
			this.crc32 = 0xffffffff;
			this.finished = false;

			GZipHeader h = new GZipHeader();
			h.ID1 = 0x1f;
			h.ID2 = 0x8b;
			h.FLG = 0;
			h.MTIME = Util.DateTimeToUnixTime(DateTime.Now.ToUniversalTime());
			h.XFL = 0;
			h.OS = 3;
			h.CM = 8;

			fifo.Write(Util.StructToByte(h));
		}

		public void Write(byte[] data, int pos, int len, bool finish)
		{
			byte[] srcData = Util.ExtractByteArray(data, pos, len);
			byte[] dstData = new byte[srcData.Length * 2 + 100];

			if (this.finished)
			{
				throw new ApplicationException("already finished");
			}

			zs.next_in = srcData;
			zs.avail_in = srcData.Length;
			zs.next_in_index = 0;

			zs.next_out = dstData;
			zs.avail_out = dstData.Length;
			zs.next_out_index = 0;

			if (finish)
			{
				zs.deflate(zlibConst.Z_FINISH);
			}
			else
			{
				zs.deflate(zlibConst.Z_SYNC_FLUSH);
			}

			fifo.Write(dstData, 0, dstData.Length - zs.avail_out);

			currentSize += len;

			this.crc32 = ZipUtil.Crc32Next(data, pos, len, this.crc32);

			if (finish)
			{
				this.finished = true;
				this.crc32 = ~this.crc32;

				GZipFooter f = new GZipFooter();
				f.CRC32 = this.crc32;
				f.ISIZE = (uint)(this.currentSize % 0x100000000);

				fifo.Write(Util.StructToByte(f));
			}
		}
	}
}
