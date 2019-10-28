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

namespace CoreUtil
{
	public class RC4 : ICloneable
	{
		uint x, y;
		uint[] state;

		public RC4(byte[] key)
		{
			state = new uint[256];

			uint i, t, u, ki, si;

			x = 0;
			y = 0;

			for (i = 0; i < 256; i++)
			{
				state[i] = i;
			}

			ki = si = 0;
			for (i = 0; i < 256; i++)
			{
				t = state[i];

				si = (si + key[ki] + t) & 0xff;
				u = state[si];
				state[si] = t;
				state[i] = u;
				if (++ki >= key.Length)
				{
					ki = 0;
				}
			}
		}

		private RC4()
		{
		}

		public object Clone()
		{
			RC4 rc4 = new RC4();

			rc4.x = this.x;
			rc4.y = this.y;
			rc4.state = (uint[])this.state.Clone();

			return rc4;
		}

		public byte[] Encrypt(byte[] src)
		{
			return Encrypt(src, src.Length);
		}
		public byte[] Encrypt(byte[] src, int len)
		{
			return Encrypt(src, 0, len);
		}
		public byte[] Encrypt(byte[] src, int offset, int len)
		{
			byte[] dst = new byte[len];

			uint x, y, sx, sy;
			x = this.x;
			y = this.y;

			int src_i = 0, dst_i = 0, end_src_i;

			for (end_src_i = src_i + len; src_i != end_src_i; src_i++, dst_i++)
			{
				x = (x + 1) & 0xff;
				sx = state[x];
				y = (sx + y) & 0xff;
				state[x] = sy = state[y];
				state[y] = sx;
				dst[dst_i] = (byte)(src[src_i + offset] ^ state[(sx + sy) & 0xff]);
			}

			this.x = x;
			this.y = y;

			return dst;
		}
		public void SkipDecrypt(int len)
		{
			SkipEncrypt(len);
		}
		public void SkipEncrypt(int len)
		{
			uint x, y, sx, sy;
			x = this.x;
			y = this.y;

			int src_i = 0, dst_i = 0, end_src_i;

			for (end_src_i = src_i + len; src_i != end_src_i; src_i++, dst_i++)
			{
				x = (x + 1) & 0xff;
				sx = state[x];
				y = (sx + y) & 0xff;
				state[x] = sy = state[y];
				state[y] = sx;
			}

			this.x = x;
			this.y = y;
		}

		public byte[] Decrypt(byte[] src)
		{
			return Decrypt(src, src.Length);
		}
		public byte[] Decrypt(byte[] src, int len)
		{
			return Decrypt(src, 0, len);
		}
		public byte[] Decrypt(byte[] src, int offset, int len)
		{
			return Encrypt(src, offset, len);
		}
	}
}
