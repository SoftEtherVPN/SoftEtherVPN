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
	// Build Win32 software
	public class BuildSoftwareWin32 : BuildSoftware
	{
		public BuildSoftwareWin32(Software software, int versionMajor, int versionMinor, int versionBuild, string buildName, Cpu cpu, OS os)
			: base(software, versionMajor, versionMinor, versionBuild, buildName, cpu, os)
		{
		}

		// Run the build
		public override void Build()
		{
			Semaphore sem = new Semaphore(BuildConfig.NumMultipleCompileTasks, BuildConfig.NumMultipleCompileTasks, "vpn_build_cross");
			Con.WriteLine("Waiting for Semaphore...");
			sem.WaitOne();
			Con.WriteLine("Done.");
			try
			{
				// Run the build
				buildInstaller();
			}
			finally
			{
				sem.Release();
			}
		}

		// Build the installer
		void buildInstaller()
		{
			string outFileName = Path.Combine(Paths.ReleaseDir, this.OutputFileName);

			string vpnsetup_exe = Path.Combine(Paths.BinDirName, "vpnsetup.exe");

			try
			{
				File.Delete(outFileName);
			}
			catch
			{
			}

			Win32BuildUtil.ExecCommand(vpnsetup_exe, string.Format("/SFXMODE:{1} /SFXOUT:\"{0}\"",
				outFileName, Software.ToString()));

			CodeSign.SignFile(outFileName, outFileName, "VPN Software", false);
		}
	}
}

