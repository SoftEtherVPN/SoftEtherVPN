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
	// Build settings
	public static class BuildConfig
	{
		public static readonly int NumMultipleCompileTasks = 1;
	}

	// Software List
	public static class BuildSoftwareList
	{
		// List creation date and time
		public static DateTime ListCreatedDateTime = DateTime.Now;

		// ========== Windows ==========
		// Server and Bridge
		public static readonly BuildSoftware vpnserver_win32_x86x64_ja =
			new BuildSoftwareWin32(Software.vpnserver_vpnbridge, 0, 0, 0, "", CpuList.intel, OSList.Windows);

		// Client
		public static readonly BuildSoftware vpnclient_win32_x86x64_ja =
			new BuildSoftwareWin32(Software.vpnclient, 0, 0, 0, "", CpuList.intel, OSList.Windows);

		// ========== Linux ==========
		// Server
		public static readonly BuildSoftware vpnserver_linux_x86_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x86, OSList.Linux,
				"linux-x86-32bit", true, "linux-x86-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_linux_x64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x64, OSList.Linux,
				"linux-x86-64bit", true, "linux-x86-64bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_linux_arm_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.arm, OSList.Linux,
				"linux-arm-32bit", false, "linux-arm-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_linux_armeabi_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.armeabi, OSList.Linux,
				"linux-armeabi-32bit", false, "linux-armeabi-32bit-4.3.2", true,
				null);
		public static readonly BuildSoftware vpnserver_linux_mipsel_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.mipsel, OSList.Linux,
				"linux-mipsel-32bit", false, "linux-mipsel-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_linux_ppc_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.ppc32, OSList.Linux,
				"linux-ppc-32bit", false, "linux-ppc-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_linux_sh4_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.sh4, OSList.Linux,
				"linux-sh4-32bit", false, "linux-sh4-32bit-3.4.6", false,
				null);

		// Client
		public static readonly BuildSoftware vpnclient_linux_x86_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.x86, OSList.Linux,
				"linux-x86-32bit", true, "linux-x86-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnclient_linux_x64_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.x64, OSList.Linux,
				"linux-x86-64bit", true, "linux-x86-64bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnclient_linux_arm_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.arm, OSList.Linux,
				"linux-arm-32bit", false, "linux-arm-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnclient_linux_armeabi_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.armeabi, OSList.Linux,
				"linux-armeabi-32bit", false, "linux-armeabi-32bit-4.3.2", true,
				null);
		public static readonly BuildSoftware vpnclient_linux_mipsel_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.mipsel, OSList.Linux,
				"linux-mipsel-32bit", false, "linux-mipsel-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnclient_linux_ppc_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.ppc32, OSList.Linux,
				"linux-ppc-32bit", false, "linux-ppc-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnclient_linux_sh4_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.sh4, OSList.Linux,
				"linux-sh4-32bit", false, "linux-sh4-32bit-3.4.6", false,
				null);

		// Bridge
		public static readonly BuildSoftware vpnbridge_linux_x86_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x86, OSList.Linux,
				"linux-x86-32bit", true, "linux-x86-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_linux_x64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x64, OSList.Linux,
				"linux-x86-64bit", true, "linux-x86-64bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_linux_arm_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.arm, OSList.Linux,
				"linux-arm-32bit", false, "linux-arm-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_linux_armeabi_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.armeabi, OSList.Linux,
				"linux-armeabi-32bit", false, "linux-armeabi-32bit-4.3.2", true,
				null);
		public static readonly BuildSoftware vpnbridge_linux_mipsel_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.mipsel, OSList.Linux,
				"linux-mipsel-32bit", false, "linux-mipsel-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_linux_ppc_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.ppc32, OSList.Linux,
				"linux-ppc-32bit", false, "linux-ppc-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_linux_sh4_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.sh4, OSList.Linux,
				"linux-sh4-32bit", false, "linux-sh4-32bit-3.4.6", false,
				null);


		// ========== FreeBSD ==========
		// Server
		public static readonly BuildSoftware vpnserver_bsd_x86_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x86, OSList.FreeBSD,
				"freebsd-x86-32bit", true, "freebsd-x86-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnserver_bsd_x64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x64, OSList.FreeBSD,
				"freebsd-x86-64bit", true, "freebsd-x86-64bit-3.4.6", false,
				null);

		// Bridge
		public static readonly BuildSoftware vpnbridge_bsd_x86_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x86, OSList.FreeBSD,
				"freebsd-x86-32bit", true, "freebsd-x86-32bit-3.4.6", false,
				null);
		public static readonly BuildSoftware vpnbridge_bsd_x64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x64, OSList.FreeBSD,
				"freebsd-x86-64bit", true, "freebsd-x86-64bit-3.4.6", false,
				null);


		// ========== Mac OS X ==========
		// Server
		public static readonly BuildSoftware vpnserver_macos_ppc32_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.ppc32, OSList.MacOS,
				"macos-ppc-32bit", true, "macos-ppc-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnserver_macos_ppc64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.ppc64, OSList.MacOS,
				"macos-ppc-64bit", true, "macos-ppc-64bit-4.0.4", true,
				null);
		public static readonly BuildSoftware vpnserver_macos_x86_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x86, OSList.MacOS,
				"macos-x86-32bit", true, "macos-x86-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnserver_macos_x64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x64, OSList.MacOS,
				"macos-x86-64bit", true, "macos-x86-64bit-4.0.4", true,
				null);

		// Client
		public static readonly BuildSoftware vpnclient_macos_ppc32_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.ppc32, OSList.MacOS,
				"macos-ppc-32bit", true, "macos-ppc-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnclient_macos_ppc64_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.ppc64, OSList.MacOS,
				"macos-ppc-64bit", true, "macos-ppc-64bit-4.0.4", true,
				null);
		public static readonly BuildSoftware vpnclient_macos_x86_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.x86, OSList.MacOS,
				"macos-x86-32bit", true, "macos-x86-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnclient_macos_x64_ja =
			new BuildSoftwareUnix(Software.vpnclient, 0, 0, 0, "", CpuList.x64, OSList.MacOS,
				"macos-x86-64bit", true, "macos-x86-64bit-4.0.4", true,
				null);

		// Bridge
		public static readonly BuildSoftware vpnbridge_macos_ppc32_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.ppc32, OSList.MacOS,
				"macos-ppc-32bit", true, "macos-ppc-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnbridge_macos_ppc64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.ppc64, OSList.MacOS,
				"macos-ppc-64bit", true, "macos-ppc-64bit-4.0.4", true,
				null);
		public static readonly BuildSoftware vpnbridge_macos_x86_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x86, OSList.MacOS,
				"macos-x86-32bit", true, "macos-x86-32bit-4.0.4", true,
				"-isysroot /cygdrive/s/CommomDev/xc/common/apple_xcode/xcode_2.4/Developer/SDKs/MacOSX10.4u.sdk");
		public static readonly BuildSoftware vpnbridge_macos_x64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x64, OSList.MacOS,
				"macos-x86-64bit", true, "macos-x86-64bit-4.0.4", true,
				null);

		// ========== Solaris ==========
		// Server
		public static readonly BuildSoftware vpnserver_solaris_sparc32_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.sparc32, OSList.Solaris,
				"solaris-sparc-32bit", true, "solaris-sparc-32bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnserver_solaris_sparc64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.sparc64, OSList.Solaris,
				"solaris-sparc-64bit", true, "solaris-sparc-64bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnserver_solaris_x86_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x86, OSList.Solaris,
				"solaris-x86-32bit", true, "solaris-x86-32bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnserver_solaris_x64_ja =
			new BuildSoftwareUnix(Software.vpnserver, 0, 0, 0, "", CpuList.x64, OSList.Solaris,
				"solaris-x86-64bit", true, "solaris-x86-64bit-3.4.6", true,
				null);

		// Bridge
		public static readonly BuildSoftware vpnbridge_solaris_sparc32_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.sparc32, OSList.Solaris,
				"solaris-sparc-32bit", true, "solaris-sparc-32bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnbridge_solaris_sparc64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.sparc64, OSList.Solaris,
				"solaris-sparc-64bit", true, "solaris-sparc-64bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnbridge_solaris_x86_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x86, OSList.Solaris,
				"solaris-x86-32bit", true, "solaris-x86-32bit-3.4.6", true,
				null);
		public static readonly BuildSoftware vpnbridge_solaris_x64_ja =
			new BuildSoftwareUnix(Software.vpnbridge, 0, 0, 0, "", CpuList.x64, OSList.Solaris,
				"solaris-x86-64bit", true, "solaris-x86-64bit-3.4.6", true,
				null);

		static BuildSoftwareList()
		{
			foreach (BuildSoftware soft in List)
			{
				BuildSoftwareUnix s = soft as BuildSoftwareUnix;
				if (s != null)
				{
					// Make different settings for each OS
					if (soft.Os == OSList.Linux)
					{
						s.GccMacros.Add("UNIX_LINUX");
					}
					else if (soft.Os == OSList.FreeBSD)
					{
						s.GccMacros.Add("UNIX_BSD");
						s.GccMacros.Add("BRIDGE_BPF");
						s.GccMacros.Add("NO_VLAN");
					}
					else if (soft.Os == OSList.MacOS)
					{
						s.GccMacros.Add("UNIX_MACOS");
						s.GccMacros.Add("BRIDGE_PCAP");
						//s.GccMacros.Add("NO_VLAN");
					}
					else if (soft.Os == OSList.Solaris)
					{
						s.GccMacros.Add("UNIX_SOLARIS");
						s.GccMacros.Add("NO_VLAN");
					}
					if (s.Cpu.Bits == CPUBits.Bits64)
					{
						s.GccMacros.Add("CPU_64");
					}
					s.GccMacros.Add("CPU_" + s.Cpu.Name.ToUpperInvariant());
				}
			}
		}

		public static BuildSoftware[] List
		{
			get
			{
				List<BuildSoftware> o = new List<BuildSoftware>();
				foreach (FieldInfo fi in typeof(BuildSoftwareList).GetFields(BindingFlags.Static | BindingFlags.Public))
					if (fi.FieldType == typeof(BuildSoftware))
						o.Add((BuildSoftware)fi.GetValue(null));
				return o.ToArray();
			}
		}

		public static BuildSoftware Find(Software soft, OS os, Cpu cpu)
		{
			foreach (BuildSoftware s in List)
			{
				if (s.Software == soft && s.Os == os && s.Cpu == cpu)
				{
					return s;
				}
			}
			return null;
		}
	}

	// OS List
	public static class OSList
	{
		// Windows
		public static readonly OS Windows = new OS("windows", "Windows",
			"Windows 98 / 98 SE / ME / NT 4.0 SP6a / 2000 SP4 / XP SP2, SP3 / Vista SP1, SP2 / 7 SP1 / 8 / 8.1 / 10 / Server 2003 SP2 / Server 2008 SP1, SP2 / Hyper-V Server 2008 / Server 2008 R2 SP1 / Hyper-V Server 2008 R2 / Server 2012 / Hyper-V Server 2012 / Server 2012 R2 / Hyper-V Server 2012 R2 / Server 2016",
			new Cpu[]
			{
				CpuList.intel,
			});

		// Linux
		public static readonly OS Linux = new OS("linux", "Linux",
			"Linux Kernel 2.4 / 2.6 / 3.x / 4.x",
			new Cpu[]
			{
				CpuList.x86,
				CpuList.x64,
				CpuList.mipsel,
				CpuList.ppc32,
				CpuList.ppc64,
				CpuList.sh4,
				CpuList.arm,
				CpuList.armeabi,
			});

		// FreeBSD
		public static readonly OS FreeBSD = new OS("freebsd", "FreeBSD",
			"FreeBSD 5 / 6 / 7 / 8 / 9 / 10",
			new Cpu[]
			{
				CpuList.x86,
				CpuList.x64,
			});

		// OpenBSD
		public static readonly OS OpenBSD = new OS("openbsd", "OpenBSD",
			"OpenBSD 5 / 6 / 7 / 8 / 9 / 10",
			new Cpu[]
			{
				CpuList.x86,
				CpuList.x64,
			});

		// Solaris
		public static readonly OS Solaris = new OS("solaris", "Solaris",
			"Solaris 8 / 9 / 10 / 11",
			new Cpu[]
			{
				CpuList.x86,
				CpuList.x64,
				CpuList.sparc32,
				CpuList.sparc64,
			});

		// Mac OS X
		public static readonly OS MacOS = new OS("macos", "Mac OS X",
			"Mac OS X 10.4 Tiger / 10.5 Leopard / 10.6 Snow Leopard / 10.7 Lion / 10.8 Mountain Lion / 10.9 Mavericks",
			new Cpu[]
			{
				CpuList.x86,
				CpuList.x64,
				CpuList.ppc32,
				CpuList.ppc64,
			});

		static OSList()
		{
			OSList.Windows.IsWindows = true;
		}

		public static OS[] List
		{
			get
			{
				List<OS> o = new List<OS>();
				foreach (FieldInfo fi in typeof(OSList).GetFields(BindingFlags.Static | BindingFlags.Public))
					if (fi.FieldType == typeof(OS))
						o.Add((OS)fi.GetValue(null));
				return o.ToArray();
			}
		}

		public static OS FindByName(string name)
		{
			foreach (OS os in List)
			{
				if (os.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase))
				{
					return os;
				}
			}

			throw new ApplicationException(name);
		}
	}

	// CPU List
	public static class CpuList
	{
		public static readonly Cpu x86 = new Cpu("x86", "Intel x86", CPUBits.Bits32);
		public static readonly Cpu x64 = new Cpu("x64", "Intel x64 / AMD64", CPUBits.Bits64);
		public static readonly Cpu intel = new Cpu("x86_x64", "Intel", CPUBits.Both);
		public static readonly Cpu arm = new Cpu("arm", "ARM legacy ABI", CPUBits.Bits32);
		public static readonly Cpu armeabi = new Cpu("arm_eabi", "ARM EABI", CPUBits.Bits32);
		public static readonly Cpu mipsel = new Cpu("mips_el", "MIPS Little-Endian", CPUBits.Bits32);
		public static readonly Cpu ppc32 = new Cpu("powerpc", "PowerPC", CPUBits.Bits32);
		public static readonly Cpu ppc64 = new Cpu("powerpc64", "PowerPC G5", CPUBits.Bits64);
		public static readonly Cpu sh4 = new Cpu("sh4", "SH-4", CPUBits.Bits32);
		public static readonly Cpu sparc32 = new Cpu("sparc", "SPARC", CPUBits.Bits32);
		public static readonly Cpu sparc64 = new Cpu("sparc64", "SPARC", CPUBits.Bits64);

		public static Cpu[] List
		{
			get
			{
				List<Cpu> o = new List<Cpu>();
				foreach (FieldInfo fi in typeof(CpuList).GetFields(BindingFlags.Static | BindingFlags.Public))
					if (fi.FieldType == typeof(Cpu))
						o.Add((Cpu)fi.GetValue(null));
				return o.ToArray();
			}
		}

		public static Cpu FindByName(string name)
		{
			foreach (Cpu c in List)
			{
				if (c.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase))
				{
					return c;
				}
			}

			throw new ApplicationException(name);
		}
	}
}

