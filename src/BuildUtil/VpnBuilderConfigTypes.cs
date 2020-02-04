// SoftEther VPN Source Code - Developer Edition Master Branch
// Build Utility


using System;
using System.Threading;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
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
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;

namespace BuildUtil
{
	// CPU data
	public class Cpu
	{
		public string Name;						// CPU name
		public string Title;					// CPU display name
		public CPUBits Bits;					// Bit length

		public Cpu(string name, string title, CPUBits bits)
		{
			this.Name = name;
			this.Title = title;
			this.Bits = bits;
		}
	}

	// OS data
	public class OS : ICloneable
	{
		public string Name;						// OS name
		public string Title;					// OS Display Name
		public string OSSimpleList;				// OS simple list
		public Cpu[] CpuList;					// CPU support list
		public bool IsWindows = false;			// Whether Windows
		public bool IsOnlyFiles = false;			// Whether only EXE file package

		public OS(string name, string title, string simpleList, Cpu[] cpuList)
		{
			this.Name = name;
			this.Title = title;
			this.OSSimpleList = simpleList;
			this.CpuList = cpuList;
		}

		public object Clone()
		{
			return this.MemberwiseClone();
		}
	}

	// Type of software
	public enum Software
	{
		vpnserver,
		vpnbridge,
		vpnclient,
		vpnserver_vpnbridge,
	}

	// Class to build the software
	public class BuildSoftware
	{
		public Software Software;				// Software
		public int VersionMajor;				// Version number (major)
		public int VersionMinor;				// Version number (minor)
		public int VersionBuild;				// Version number (build)
		public string BuildName;				// Build name
		public Cpu Cpu;							// CPU
		public OS Os;							// OS
		public DateTime BuildDate;				// Build date

		public BuildSoftware(Software software, int versionMajor, int versionMinor, int versionBuild, string buildName, Cpu cpu, OS os)
		{
			this.Software = software;
			this.VersionMajor = versionMajor;
			this.VersionMinor = versionMinor;
			this.VersionBuild = versionBuild;
			this.BuildName = buildName;
			this.Cpu = cpu;
			this.Os = os;
		}

		public void SetBuildNumberVersionName(int versionMajor, int versionMinor, int versionBuild, string buildName, DateTime date)
		{
			this.VersionMajor = versionMajor;
			this.VersionMinor = versionMinor;
			this.VersionBuild = versionBuild;
			this.BuildName = buildName;
			this.BuildDate = date;
		}

		public BuildSoftware(string filename)
		{
			filename = Path.GetFileName(filename);

			if (filename.StartsWith(Paths.Prefix, StringComparison.InvariantCultureIgnoreCase))
			{
				filename = filename.Substring(Paths.Prefix.Length);
			}

			if (filename.EndsWith(".tar.gz", StringComparison.InvariantCultureIgnoreCase))
			{
				filename = Str.ReplaceStr(filename, ".tar.gz", "");
			}
			else
			{
				filename = Path.GetFileNameWithoutExtension(filename);
			}
			char[] sps = {'-'};

			string[] tokens = filename.Split(sps, StringSplitOptions.RemoveEmptyEntries);
			if (tokens.Length != 8)
			{
				throw new ApplicationException(filename);
			}

			if (tokens[1].StartsWith("v", StringComparison.InvariantCultureIgnoreCase) == false)
			{
				throw new ApplicationException(filename);
			}

			this.Software = (Software)Enum.Parse(typeof(Software), tokens[0], true);

			string[] vs = tokens[1].Substring(1).Split('.');
			this.VersionMajor = int.Parse(vs[0]);
			this.VersionMinor = int.Parse(vs[1]);
			this.VersionBuild = int.Parse(tokens[2]);
			this.BuildName = tokens[3];

			string[] ds = tokens[4].Split('.');
			this.BuildDate = new DateTime(int.Parse(ds[0]), int.Parse(ds[1]), int.Parse(ds[2]));
			this.Os = OSList.FindByName(tokens[5]);
			this.Cpu = CpuList.FindByName(tokens[6]);
		}

		// Generate a string of file name equivalent
		public virtual string FileNameBaseString
		{
			get
			{
				return string.Format("{0}-v{6}-{1}-{2}-{8:D4}.{9:D2}.{10:D2}-{4}-{3}-{7}",
					Paths.Prefix + this.Software.ToString(),
					this.VersionBuild,
					this.BuildName,
					this.Cpu.Name,
					this.Os.Name,
					0,
					BuildHelper.VersionIntToString(this.VersionMajor, this.VersionMinor),
					CPUBitsUtil.CPUBitsToString(this.Cpu.Bits),
					BuildDate.Year, BuildDate.Month, BuildDate.Day).ToLower();
			}
		}

		// Generate an identifier
		public virtual string IDString
		{
			get
			{
				return string.Format("{0}-{2}-{3}-{4}",
					Paths.Prefix + this.Software.ToString(),
					0,
					this.Os.Name,
					this.Cpu.Name,
					CPUBitsUtil.CPUBitsToString(this.Cpu.Bits));
			}
		}

		// Generate a title string
		public virtual string TitleString
		{
			get
			{
				return string.Format("{0} (Ver {2}, Build {1}, {3}) for {5}", BuildHelper.GetSoftwareTitle(this.Software),
					this.VersionBuild, BuildHelper.VersionIntToString(this.VersionMajor, this.VersionMinor), this.Cpu.Title, 0, this.Os.Title);
			}
		}

		// Generate extension
		public virtual string OutputFileExt
		{
			get
			{
				if (this.Os.IsWindows)
				{
					return ".exe";
				}
				else
				{
					return ".tar.gz";
				}
			}
		}

		// Generate the output file name
		public virtual string OutputFileName
		{
			get
			{
				return this.FileNameBaseString + this.OutputFileExt;
			}
		}

		// Run the build
		public virtual void Build()
		{
			throw new NotSupportedException();
		}
	}
}
