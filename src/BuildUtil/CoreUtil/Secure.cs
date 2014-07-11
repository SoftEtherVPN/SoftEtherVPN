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
using System.Runtime.InteropServices;

namespace CoreUtil
{
	public class CommonSign
	{
		byte[] keyData;
		static uint init_dummy = CryptoConfigHelper.Init();

		public CommonSign(byte[] key)
		{
			init(key);
		}
		public CommonSign(Buf buf)
		{
			init(buf.ByteData);
		}
		public CommonSign(string filename)
		{
			init(Buf.ReadFromFile(filename).ByteData);
		}
		void init(byte[] key)
		{
			keyData = (byte[])key.Clone();
		}

		public byte[] Sign(byte[] data)
		{
			Buf b = new Buf(data);
			b.SeekToEnd();
			b.Write(keyData);

			return Secure.HashSHA1(b.ByteData);
		}
		public bool Verify(byte[] data, byte[] sign)
		{
			byte[] sign2 = Sign(data);

			return Util.CompareByte(sign, sign2);
		}
	}

	public class Rsa
	{
		byte[] data;
		Cert cert;
		static uint init_dummy = CryptoConfigHelper.Init();
		static object lockObj = new object();

		public Rsa(byte[] data)
		{
			init(data);
		}
		public Rsa(string filename)
		{
			Buf b = Buf.ReadFromFile(filename);
			init(b.ByteData);
		}
		public Rsa(Buf b)
		{
			init(b.ByteData);
		}
		void init(byte[] data)
		{
			this.data = (byte[])data.Clone();
			this.cert = null;

			Cert.deleteOldTempFiles();
		}

		public Rsa(Cert cert)
		{
			init(cert);
		}
		void init(Cert cert)
		{
			this.cert = (Cert)cert.Clone();
			this.data = null;

			Cert.deleteOldTempFiles();
		}

		public byte[] SignData(byte[] data)
		{
			lock (lockObj)
			{
				byte[] ret;
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					ret = rsa.SignData(data);
				}
				return ret;
			}
		}

		public byte[] SignHash(byte[] hash)
		{
			lock (lockObj)
			{
				byte[] ret;
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					ret = rsa.SignHash(hash);
				}
				return ret;
			}
		}

		public bool VerifyData(byte[] data, byte[] sign)
		{
			lock (lockObj)
			{
				bool ret;
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					ret = rsa.VerifyData(data, sign);
				}
				return ret;
			}
		}

		public bool VerifyHash(byte[] hash, byte[] sign)
		{
			lock (lockObj)
			{
				bool ret;
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					ret = rsa.VerifyHash(hash, sign);
				}
				return ret;
			}
		}

		public byte[] Encrypt(byte[] data)
		{
			lock (lockObj)
			{
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					return rsa.Encrypt(data);
				}
			}
		}

		public byte[] Decrypt(byte[] data)
		{
			lock (lockObj)
			{
				using (RsaInner rsa = new RsaInner(this.data, this.cert))
				{
					return rsa.Decrypt(data);
				}
			}
		}

		public int KeySizeBit
		{
			get
			{
				lock (lockObj)
				{
					using (RsaInner rsa = new RsaInner(this.data, this.cert))
					{
						return rsa.KeySizeBit;
					}
				}
			}
		}
	}

	class RsaInner : IDisposable
	{
		static string sha1rsa = CryptoConfig.MapNameToOID("SHA1");
		RSACryptoServiceProvider rsa;
		static object lockObj = new Object();
		static LocalDataStoreSlot slot = Thread.AllocateDataSlot();
		static LocalDataStoreSlot slot2 = Thread.AllocateDataSlot();
		static uint init_dummy = CryptoConfigHelper.Init();

		public static void Lock()
		{
		}

		public static void Unlock()
		{
		}

		public RsaInner(byte[] data, Cert cert)
		{
			if (data != null)
			{
				init(data);
			}
			else
			{
				init(cert);
			}
		}
		public RsaInner(byte[] data)
		{
			init(data);
		}
		public RsaInner(string filename)
		{
			Buf b = Buf.ReadFromFile(filename);
			init(b.ByteData);
		}
		public RsaInner(Buf b)
		{
			init(b.ByteData);
		}
		void init(byte[] data)
		{
			Lock();
			rsa = readRsaPrivate(data);
		}

		public RsaInner(Cert cert)
		{
			init(cert);
		}
		void init(Cert cert)
		{
			Lock();
			string text1 = cert.X509Cert.GetKeyAlgorithm();
			byte[] buffer1 = cert.X509Cert.GetKeyAlgorithmParameters();
			byte[] buffer2 = cert.X509Cert.GetPublicKey();
			Oid oid1 = new Oid("1.2.840.113549.1.1.1", "RSA");

			rsa = (RSACryptoServiceProvider)(new PublicKey(oid1, new AsnEncodedData(oid1, buffer1), new AsnEncodedData(oid1, buffer2))).Key;
		}

		public byte[] SignData(byte[] data)
		{
			byte[] hash = Secure.HashSHA1(data);
			return SignHash(hash);
		}

		public byte[] SignHash(byte[] hash)
		{
			byte[] ret = null;
			ret = rsa.SignHash(hash, sha1rsa);

			return ret;
		}

		public bool VerifyData(byte[] data, byte[] sign)
		{
			byte[] hash = Secure.HashSHA1(data);
			return VerifyHash(hash, sign);
		}

		public bool VerifyHash(byte[] hash, byte[] sign)
		{
			return rsa.VerifyHash(hash, sha1rsa, sign);
		}

		public byte[] Encrypt(byte[] data)
		{
			return rsa.Encrypt(data, false);
		}

		public byte[] Decrypt(byte[] data)
		{
			return rsa.Decrypt(data, false);
		}

		static RSACryptoServiceProvider readRsaPrivate(byte[] data)
		{
			// From http://forums.l-space-design.com/blogs/day_of_the_developer/archive/2006/06/08/216.aspx
			string t = Str.AsciiEncoding.GetString(data);
			if (!t.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
			{
				throw new ArgumentException("Not an RSA Private Key");
			}
			t = t.Substring("-----BEGIN RSA PRIVATE KEY-----".Length);
			t = t.Substring(0, t.IndexOf("----"));
			t = t.Replace("\r", "").Replace("\n", "");
			byte[] byteArray = System.Convert.FromBase64String(t);
			System.IO.MemoryStream s = new MemoryStream(byteArray);
			BinaryReader binr = new BinaryReader(s, Str.AsciiEncoding);
			byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;
			// --------- Set up stream to decode the asn.1 encoded RSA private key ------
			byte bt = 0;
			ushort twobytes = 0;
			int elems = 0;
			RSAParameters result = new RSAParameters();
			try
			{
				twobytes = binr.ReadUInt16();
				if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
					binr.ReadByte(); //advance 1 byte
				else if (twobytes == 0x8230)
					binr.ReadInt16(); //advance 2 bytes
				else
					return null;
				twobytes = binr.ReadUInt16();
				if (twobytes != 0x0102) //version number
					return null;
				bt = binr.ReadByte();
				if (bt != 0x00)
					return null;
				//------ all private key components are Integer sequences ----
				elems = getIntegerSize(binr);
				MODULUS = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				E = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				D = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				P = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				Q = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				DP = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				DQ = binr.ReadBytes(elems);
				elems = getIntegerSize(binr);
				IQ = binr.ReadBytes(elems);
				result.Modulus = MODULUS;
				result.Exponent = E;
				result.D = D;
				result.P = P;
				result.Q = Q;
				result.DP = DP;
				result.DQ = DQ;
				result.InverseQ = IQ;
			}
			catch (Exception)
			{
				return null;
			}
			finally
			{
				binr.Close();
			}
			CspParameters cp = new CspParameters();
			cp.Flags = CspProviderFlags.UseMachineKeyStore;
			RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(cp);
			RSA.PersistKeyInCsp = false;
			RSA.ImportParameters(result);
			return RSA;
		}

		static int getIntegerSize(BinaryReader binr)
		{
			byte bt = 0;
			byte lowbyte = 0x00;
			byte highbyte = 0x00;
			int count = 0;
			bt = binr.ReadByte();
			if (bt != 0x02) //expect integer
				return 0;
			bt = binr.ReadByte();
			if (bt == 0x81)
				count = binr.ReadByte(); // data size in next byte
			else
				if (bt == 0x82)
				{
					highbyte = binr.ReadByte(); // data size in next 2 bytes
					lowbyte = binr.ReadByte();
					byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
					count = BitConverter.ToInt32(modint, 0);
				}
				else
				{
					count = bt; // we already have the data size
				}
			while (binr.PeekChar() == 0x00)
			{ //remove high order zeros in data
				binr.ReadByte();
				count -= 1;
			}
			return count;
		}

		public void Dispose()
		{
			rsa.Clear();
			rsa = null;
			Unlock();
		}

		public int KeySizeBit
		{
			get
			{
				return rsa.KeySize;
			}
		}
	}

	public class Cert
	{
		X509Certificate2 x509;
		static TimeSpan deleteOldCertSpan = new TimeSpan(0, 0, 30);
		static object lockObj = new Object();
		static RSACryptoServiceProvider rsaDummy = null;
		static uint init_dummy = CryptoConfigHelper.Init();

		public int KeySizeBit
		{
			get
			{
				Rsa r = new Rsa(this);

				return r.KeySizeBit;
			}
		}

		public X509Certificate2 X509Cert
		{
			get { return x509; }
		}

		public Rsa RsaPublicKey
		{
			get
			{
				return new Rsa(this);
			}
		}

		public Cert(byte[] data)
		{
			init(data);
		}
		public Cert(string filename)
		{
			init(IO.ReadFile(filename));
		}
		public Cert(Buf buf)
		{
			init(buf.ByteData);
		}
		void init(byte[] data)
		{
			deleteOldTempFiles();
			x509 = new X509Certificate2(data);

			if (rsaDummy == null)
			{
				rsaDummy = (RSACryptoServiceProvider)(new X509Certificate2(data).PublicKey.Key);
			}
		}

		public byte[] Hash
		{
			get
			{
				return x509.GetCertHash();
			}
		}

		public byte[] PublicKey
		{
			get
			{
				return x509.GetPublicKey();
			}
		}

		public byte[] ByteData
		{
			get
			{
				return x509.Export(X509ContentType.Cert);
			}
		}
		public Buf ToBuf()
		{
			return new Buf(ByteData);
		}
		public void ToFile(string filename)
		{
			ToBuf().WriteToFile(filename);
		}

		public Cert Clone()
		{
			return new Cert(this.ByteData);
		}

		static DateTime lastDeletedDateTime = new DateTime();
		static readonly TimeSpan deleteTimeSpan = new TimeSpan(0, 1, 0);
		internal static void deleteOldTempFiles()
		{
			lock (lockObj)
			{
				DateTime now = Time.NowDateTime;

				if (lastDeletedDateTime.Ticks == 0 ||
					now >= (lastDeletedDateTime + deleteTimeSpan))
				{
					lastDeletedDateTime = now;

					string tempDir = Path.GetTempPath();
					string[] files = Directory.GetFiles(tempDir);

					if (files != null)
					{
						foreach (string name in files)
						{
							try
							{
								if (Str.StrCmpi(Path.GetExtension(name), ".tmp") && Path.GetFileName(name).StartsWith("tmp", StringComparison.CurrentCultureIgnoreCase))
								{
									DateTime dt = File.GetLastWriteTimeUtc(name);
									if ((DateTime.UtcNow - dt) >= deleteOldCertSpan)
									{
										FileInfo info = new FileInfo(name);

										if (info.Length == 0)
										{
											try
											{
												File.Delete(name);
											}
											catch
											{
											}
										}
									}
								}
							}
							catch
							{
							}
						}
					}
				}
			}
		}
	}

	public class Secure
	{
		static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
		static MD5 md5 = new MD5CryptoServiceProvider();
		static uint init_dummy = CryptoConfigHelper.Init();
		public const uint SHA1Size = 20;
		public const uint MD5Size = 16;
		static object rand_lock = new object();

		public static byte[] Rand(uint size)
		{
			lock (rand_lock)
			{
				byte[] ret = new byte[size];
				rng.GetBytes(ret);
				return ret;
			}
		}
		public static uint Rand32()
		{
			return BitConverter.ToUInt32(Rand(4), 0);
		}
		public static ulong Rand64()
		{
			return BitConverter.ToUInt64(Rand(8), 0);
		}
		public static ushort Rand16()
		{
			return BitConverter.ToUInt16(Rand(2), 0);
		}
		public static int Rand32i()
		{
			return BitConverter.ToInt32(Rand(4), 0);
		}
		public static long Rand64i()
		{
			return BitConverter.ToInt64(Rand(8), 0);
		}
		public static short Rand16i()
		{
			return BitConverter.ToInt16(Rand(2), 0);
		}
		public static int Rand31i()
		{
			while (true)
			{
				int i = Rand32i();
				if (i >= 0)
				{
					return i;
				}
			}
		}
		public static long Rand63i()
		{
			while (true)
			{
				long i = Rand64i();
				if (i >= 0)
				{
					return i;
				}
			}
		}
		public static short Rand15i()
		{
			while (true)
			{
				short i = Rand16i();
				if (i >= 0)
				{
					return i;
				}
			}
		}
		public static byte Rand8()
		{
			return Rand(1)[0];
		}
		public static bool Rand1()
		{
			return (Rand32() % 2) == 0;
		}

		// MD5
		public static byte[] HashMD5(byte[] data)
		{
			byte[] ret;

			RsaInner.Lock();
			try
			{
				ret = md5.ComputeHash(data);
			}
			finally
			{
				RsaInner.Unlock();
			}

			return ret;
		}

		// SHA1
		public static byte[] HashSHA1(byte[] data)
		{
			SHA1 sha1 = new SHA1Managed();

			return sha1.ComputeHash(data);
		}

		// SHA256
		public static byte[] HashSHA256(byte[] data)
		{
			SHA256 sha256 = new SHA256Managed();

			return sha256.ComputeHash(data);
		}

		public static byte[] PkcsPadding(byte[] srcData, int destSize)
		{
			int srcSize = srcData.Length;

			if ((srcSize + 11) > destSize)
			{
				throw new OverflowException();
			}

			int randSize = destSize - srcSize - 3;
			byte[] rand = Secure.Rand((uint)randSize);

			Buf b = new Buf();
			b.WriteByte(0x00);
			b.WriteByte(0x02);
			b.Write(rand);
			b.WriteByte(0x00);
			b.Write(srcData);

			return b.ByteData;
		}
	}

	public class CryptoConfigHelper
	{
		static object objLock = new Object();
		static bool flag = false;

		public static uint Init()
		{
			try
			{
				lock (objLock)
				{
					if (flag == false)
					{
						flag = true;
						Type t = typeof(CryptoConfig);
						Hashtable ht = (Hashtable)t.InvokeMember("DefaultOidHT", System.Reflection.BindingFlags.GetProperty | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static,
							null, null, null);
						List<string> values = new List<string>();

						foreach (string key in ht.Keys)
						{
							string value = (string)ht[key];

							values.Add(value);
						}

						foreach (string s in values)
						{
							ht.Add(s, s);
						}
					}
				}
			}
			catch
			{
			}

			return 0;
		}
	}

	public static class ExeSignChecker
	{
		public static bool IsKernelModeSignedFile(string fileName)
		{
			return IsKernelModeSignedFile(File.ReadAllBytes(fileName));
		}

		public static bool IsKernelModeSignedFile(byte[] data)
		{
			string str = Str.AsciiEncoding.GetString(data);

			if (str.IndexOf("Microsoft Code Verification Root") != -1 &&
				str.IndexOf("http://crl.microsoft.com/pki/crl/products/MicrosoftCodeVerifRoot.crl") != -1)
			{
				return true;
			}

			return false;
		}

		enum SignChecker_MemoryAllocator { HGlobal, CoTaskMem };
		enum SignChecker_UiChoice { All = 1, NoUI, NoBad, NoGood };
		enum SignChecker_StateAction { Ignore = 0, Verify, Close, AutoCache, AutoCacheFlush };
		enum SignChecker_UnionChoice { File = 1, Catalog, Blob, Signer, Cert };
		enum SignChecker_RevocationCheckFlags { None = 0, WholeChain };
		enum SignChecker_TrustProviderFlags
		{
			UseIE4Trust = 1,
			NoIE4Chain = 2,
			NoPolicyUsage = 4,
			RevocationCheckNone = 16,
			RevocationCheckEndCert = 32,
			RevocationCheckChain = 64,
			RecovationCheckChainExcludeRoot = 128,
			Safer = 256,
			HashOnly = 512,
			UseDefaultOSVerCheck = 1024,
			LifetimeSigning = 2048
		};
		enum SignChecker_UIContext { Execute = 0, Install };

		[DllImport("Wintrust.dll", PreserveSig = true, SetLastError = false)]
		static extern uint WinVerifyTrust(IntPtr hWnd, IntPtr pgActionID, IntPtr pWinTrustData);

		sealed class SignCheckerUnmanagedPointer : IDisposable
		{
			private IntPtr m_ptr;
			private SignChecker_MemoryAllocator m_meth;
			public SignCheckerUnmanagedPointer(IntPtr ptr, SignChecker_MemoryAllocator method)
			{
				m_meth = method;
				m_ptr = ptr;
			}

			~SignCheckerUnmanagedPointer()
			{
				Dispose(false);
			}

			void Dispose(bool disposing)
			{
				if (m_ptr != IntPtr.Zero)
				{
					if (m_meth == SignChecker_MemoryAllocator.HGlobal)
					{
						Marshal.FreeHGlobal(m_ptr);
					}
					else if (m_meth == SignChecker_MemoryAllocator.CoTaskMem)
					{
						Marshal.FreeCoTaskMem(m_ptr);
					}
					m_ptr = IntPtr.Zero;
				}

				if (disposing)
				{
					GC.SuppressFinalize(this);
				}
			}

			public void Dispose()
			{
				Dispose(true);
			}

			public static implicit operator IntPtr(SignCheckerUnmanagedPointer ptr)
			{
				return ptr.m_ptr;
			}
		}

		struct WINTRUST_FILE_INFO : IDisposable
		{
			public WINTRUST_FILE_INFO(string fileName, Guid subject)
			{
				cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
				pcwszFilePath = fileName;

				if (subject != Guid.Empty)
				{
					tmp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
					Marshal.StructureToPtr(subject, tmp, false);
				}
				else
				{
					tmp = IntPtr.Zero;
				}
				hFile = IntPtr.Zero;
			}
			public uint cbStruct;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string pcwszFilePath;
			public IntPtr hFile;
			public IntPtr tmp;

			public void Dispose()
			{
				Dispose(true);
			}

			private void Dispose(bool disposing)
			{
				if (tmp != IntPtr.Zero)
				{
					Marshal.DestroyStructure(this.tmp, typeof(Guid));
					Marshal.FreeHGlobal(this.tmp);
				}
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		struct WINTRUST_DATA : IDisposable
		{
			public WINTRUST_DATA(WINTRUST_FILE_INFO fileInfo)
			{
				this.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
				pInfoStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
				Marshal.StructureToPtr(fileInfo, pInfoStruct, false);
				dwUnionChoice = SignChecker_UnionChoice.File;
				pPolicyCallbackData = IntPtr.Zero;
				pSIPCallbackData = IntPtr.Zero;
				dwUIChoice = SignChecker_UiChoice.NoUI;
				fdwRevocationChecks = SignChecker_RevocationCheckFlags.WholeChain;
				dwStateAction = SignChecker_StateAction.Ignore;
				hWVTStateData = IntPtr.Zero;
				pwszURLReference = IntPtr.Zero;
				dwProvFlags = SignChecker_TrustProviderFlags.RevocationCheckChain;

				dwUIContext = SignChecker_UIContext.Execute;
			}

			public uint cbStruct;
			public IntPtr pPolicyCallbackData;
			public IntPtr pSIPCallbackData;
			public SignChecker_UiChoice dwUIChoice;
			public SignChecker_RevocationCheckFlags fdwRevocationChecks;
			public SignChecker_UnionChoice dwUnionChoice;
			public IntPtr pInfoStruct;
			public SignChecker_StateAction dwStateAction;
			public IntPtr hWVTStateData;
			private IntPtr pwszURLReference;
			public SignChecker_TrustProviderFlags dwProvFlags;
			public SignChecker_UIContext dwUIContext;

			public void Dispose()
			{
				Dispose(true);
			}

			private void Dispose(bool disposing)
			{
				if (dwUnionChoice == SignChecker_UnionChoice.File)
				{
					WINTRUST_FILE_INFO info = new WINTRUST_FILE_INFO();
					Marshal.PtrToStructure(pInfoStruct, info);
					info.Dispose();
					Marshal.DestroyStructure(pInfoStruct, typeof(WINTRUST_FILE_INFO));
				}

				Marshal.FreeHGlobal(pInfoStruct);
			}
		}

		public static bool CheckFileDigitalSignature(string fileName)
		{
			Guid wintrust_action_generic_verify_v2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
			WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(fileName, Guid.Empty);
			WINTRUST_DATA data = new WINTRUST_DATA(fileInfo);

			uint ret = 0;

			using (SignCheckerUnmanagedPointer guidPtr = new SignCheckerUnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid))), SignChecker_MemoryAllocator.HGlobal))
			using (SignCheckerUnmanagedPointer wvtDataPtr = new SignCheckerUnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA))), SignChecker_MemoryAllocator.HGlobal))
			{
				IntPtr pGuid = guidPtr;
				IntPtr pData = wvtDataPtr;

				Marshal.StructureToPtr(wintrust_action_generic_verify_v2, pGuid, false);
				Marshal.StructureToPtr(data, pData, false);

				ret = WinVerifyTrust(IntPtr.Zero, pGuid, pData);
			}

			if (ret != 0)
			{
				return false;
			}

			return true;
		}
	}
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
