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
using System.Runtime.InteropServices;

namespace CoreUtil
{
	public static class Bmp
	{
		public static Bitmap Load(string filename)
		{
			return Load(IO.ReadFile(filename));
		}
		public static Bitmap Load(byte[] data)
		{
			MemoryStream ms = new MemoryStream();
			ms.Write(data, 0, data.Length);
			ms.Seek(0, SeekOrigin.Begin);

			return new Bitmap(ms);
		}

		public static void SaveAsBitmap(Bitmap bmp, string filename)
		{
			IO.SaveFile(filename, SaveAsBitmap(bmp));
		}
		public static byte[] SaveAsBitmap(Bitmap bmp)
		{
			MemoryStream ms = new MemoryStream();

			bmp.Save(ms, ImageFormat.Bmp);

			return ms.ToArray();
		}

		public static void SaveAsJpeg(Bitmap bmp, string filename)
		{
			IO.SaveFile(filename, SaveAsJpeg(bmp));
		}
		public static byte[] SaveAsJpeg(Bitmap bmp)
		{
			return SaveAsJpeg(bmp, 100);
		}
		public static void SaveAsJpeg(Bitmap bmp, string filename, int quality)
		{
			IO.SaveFile(filename, SaveAsJpeg(bmp, quality));
		}
		public static byte[] SaveAsJpeg(Bitmap bmp, int quality)
		{
			EncoderParameters eps = new EncoderParameters(1);
			EncoderParameter ep = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, quality);
			eps.Param[0] = ep;

			ImageCodecInfo info = getEncoderInfo("image/jpeg");

			MemoryStream ms = new MemoryStream();
			bmp.Save(ms, info, eps);

			return ms.ToArray();
		}

		static ImageCodecInfo getEncoderInfo(string type)
		{
			ImageCodecInfo[] encs = ImageCodecInfo.GetImageEncoders();

			foreach (ImageCodecInfo enc in encs)
			{
				if (Str.StrCmpi(enc.MimeType, type))
				{
					return enc;
				}
			}

			return null;
		}

		public static Bitmap ResizeBitmap(Bitmap bmp, int width, int height)
		{
			Bitmap dst = new Bitmap(width, height, PixelFormat.Format24bppRgb);
			Graphics g = Graphics.FromImage(dst);
			g.SmoothingMode = SmoothingMode.HighQuality;
			g.InterpolationMode = InterpolationMode.HighQualityBicubic;

			Rectangle r = new Rectangle(0, 0, width, height);

			g.DrawImage(bmp, r);

			return dst;
		}
	}
}
