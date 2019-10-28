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
using System.Runtime.InteropServices;

namespace CoreUtil
{
	public enum PackerFileFormat
	{
		ZipRaw,
		ZipCompressed,
		Tar,
		TarGZip,
	}

	public delegate bool ProgressDelegate(string fileNameFullPath, string fileNameRelative, int currentFileNum, int totalFileNum);

	public static class Packer
	{
		public static byte[] PackDir(PackerFileFormat format, string rootDirPath, string appendPrefixDirName)
		{
			return PackDir(format, rootDirPath, appendPrefixDirName, null);
		}
		public static byte[] PackDir(PackerFileFormat format, string topDirPath, string appendPrefixDirName, ProgressDelegate proc)
		{
			string[] fileList = Directory.GetFiles(topDirPath, "*", SearchOption.AllDirectories);
			List<string> relativeFileList = new List<string>();

			foreach (string fileName in fileList)
			{
				string relativePath = IO.GetRelativeFileName(fileName, topDirPath);

				if (Str.IsEmptyStr(appendPrefixDirName) == false)
				{
					relativePath = IO.RemoteLastEnMark(appendPrefixDirName) + "\\" + relativePath;
				}

				relativeFileList.Add(relativePath);
			}

			return PackFiles(format, fileList, relativeFileList.ToArray(), proc);
		}

		public static byte[] PackFiles(PackerFileFormat format, string[] srcFileNameList, string[] relativeNameList)
		{
			return PackFiles(format, srcFileNameList, relativeNameList, null);
		}
		public static byte[] PackFiles(PackerFileFormat format, string[] srcFileNameList, string[] relativeNameList, ProgressDelegate proc)
		{
			if (srcFileNameList.Length != relativeNameList.Length)
			{
				throw new ApplicationException("srcFileNameList.Length != relativeNameList.Length");
			}

			int num = srcFileNameList.Length;
			int i;

			ZipPacker zip = new ZipPacker();
			TarPacker tar = new TarPacker();

			for (i = 0; i < num; i++)
			{
				if (proc != null)
				{
					bool ret = proc(srcFileNameList[i], relativeNameList[i], i, num);

					if (ret == false)
					{
						continue;
					}
				}

				byte[] srcData = File.ReadAllBytes(srcFileNameList[i]);
				DateTime date = File.GetLastWriteTime(srcFileNameList[i]);

				switch (format)
				{
					case PackerFileFormat.Tar:
					case PackerFileFormat.TarGZip:
						tar.AddFileSimple(relativeNameList[i], srcData, 0, srcData.Length, date);
						break;

					case PackerFileFormat.ZipRaw:
					case PackerFileFormat.ZipCompressed:
						zip.AddFileSimple(relativeNameList[i], date, FileAttributes.Normal, srcData, (format == PackerFileFormat.ZipCompressed));
						break;
				}
			}

			switch (format)
			{
				case PackerFileFormat.Tar:
					tar.Finish();
					return tar.GeneratedData.Read();

				case PackerFileFormat.TarGZip:
					tar.Finish();
					return tar.CompressToGZip();

				case PackerFileFormat.ZipCompressed:
				case PackerFileFormat.ZipRaw:
					zip.Finish();
					return zip.GeneratedData.Read();

				default:
					throw new ApplicationException("format");
			}
		}
	}
}
