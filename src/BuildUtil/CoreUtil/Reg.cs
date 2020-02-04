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
using Microsoft.Win32;

namespace CoreUtil
{
	public class AppReg
	{
		string appSubKey;
		public string AppSubKey
		{
			get { return appSubKey; }
		}
		RegRoot rootKey;
		public RegRoot RootKey
		{
			get { return rootKey; }
		}

		public AppReg(RegRoot root, string subkey)
		{
			subkey = subkey.TrimEnd('\\');
			this.rootKey = root;
			this.appSubKey = subkey;
		}

		public AppReg GetSubReg(string subKeyName)
		{
			return new AppReg(rootKey, appSubKey + "\\" + subKeyName);
		}

		public bool WriteStr(string name, string value)
		{
			return Reg.WriteStr(rootKey, appSubKey, name, value);
		}

		public bool WriteInt(string name, int value)
		{
			return Reg.WriteInt(rootKey, appSubKey, name, value);
		}

		public bool WriteStrList(string name, string[] values)
		{
			return Reg.WriteStrList(rootKey, appSubKey, name, values);
		}

		public bool WriteByte(string name, byte[] data)
		{
			return Reg.WriteByte(rootKey, appSubKey, name, data);
		}

		public bool DeleteValue(string name)
		{
			return Reg.DeleteValue(rootKey, appSubKey, name);
		}

		public string ReadStr(string name)
		{
			return Reg.ReadStr(rootKey, appSubKey, name);
		}

		public int ReadInt(string name)
		{
			return Reg.ReadInt(rootKey, appSubKey, name);
		}

		public string[] ReadStrList(string name)
		{
			return Reg.ReadStrList(rootKey, appSubKey, name);
		}

		public byte[] ReadByte(string name)
		{
			return Reg.ReadByte(rootKey, appSubKey, name);
		}
	}

	public enum RegRoot
	{
		LocalMachine = 0,
		CurrentUser = 1,
		Users = 2,
	}

	public static class Reg
	{
		static RegistryKey rootKey(RegRoot r)
		{
			switch (r)
			{
				case RegRoot.LocalMachine:
					return Registry.LocalMachine;

				case RegRoot.CurrentUser:
					return Registry.CurrentUser;

				case RegRoot.Users:
					return Registry.Users;
			}

			throw new ArgumentException();
		}

		public static string[] EnumValue(RegRoot root, string keyname)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return new string[0];
				}

				try
				{
					return key.GetValueNames();
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return new string[0];
			}
		}

		public static string[] EnumKey(RegRoot root, string keyname)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return new string[0];
				}

				try
				{
					return key.GetSubKeyNames();
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return new string[0];
			}
		}

		public static bool WriteByte(RegRoot root, string keyname, string valuename, byte[] data)
		{
			return WriteValue(root, keyname, valuename, data);
		}

		public static byte[] ReadByte(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return new byte[0];
			}

			try
			{
				return (byte[])o;
			}
			catch
			{
				return new byte[0];
			}
		}

		public static bool WriteInt(RegRoot root, string keyname, string valuename, int value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static int ReadInt(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return 0;
			}

			try
			{
				return (int)o;
			}
			catch
			{
				return 0;
			}
		}

		public static bool WriteStrList(RegRoot root, string keyname, string valuename, string[] value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static string[] ReadStrList(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return new string[0];
			}

			try
			{
				return (string[])o;
			}
			catch
			{
				return new string[0];
			}
		}

		public static bool WriteStr(RegRoot root, string keyname, string valuename, string value)
		{
			return WriteValue(root, keyname, valuename, value);
		}

		public static string ReadStr(RegRoot root, string keyname, string valuename)
		{
			object o = ReadValue(root, keyname, valuename);
			if (o == null)
			{
				return "";
			}

			try
			{
				return (string)o;
			}
			catch
			{
				return "";
			}
		}

		public static bool WriteValue(RegRoot root, string keyname, string valuename, object o)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname, true);

				if (key == null)
				{
					key = rootKey(root).CreateSubKey(keyname);

					if (key == null)
					{
						return false;
					}
				}

				try
				{
					key.SetValue(valuename, o);

					return true;
				}
				catch
				{
					return false;
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return false;
			}
		}

		public static object ReadValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				if (key == null)
				{
					return null;
				}

				try
				{
					return key.GetValue(valuename);
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return null;
			}
		}

		public static bool IsValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname);

				try
				{
					object o = key.GetValue(valuename);

					if (o == null)
					{
						return false;
					}
				}
				finally
				{
					key.Close();
				}

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool DeleteValue(RegRoot root, string keyname, string valuename)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(keyname, true);

				if (key == null)
				{
					return false;
				}

				try
				{
					key.DeleteValue(valuename);

					return true;
				}
				finally
				{
					key.Close();
				}
			}
			catch
			{
				return false;
			}
		}

		public static bool DeleteKey(RegRoot root, string keyname)
		{
			return DeleteKey(root, keyname, false);
		}
		public static bool DeleteKey(RegRoot root, string keyname, bool deleteAll)
		{
			try
			{
				if (deleteAll == false)
				{
					rootKey(root).DeleteSubKey(keyname);
				}
				else
				{
					rootKey(root).DeleteSubKeyTree(keyname);
				}

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool NewKey(RegRoot root, string keyname)
		{
			if (IsKey(root, keyname))
			{
				return true;
			}

			try
			{
				RegistryKey key = rootKey(root).CreateSubKey(keyname);

				if (key == null)
				{
					return false;
				}

				key.Close();

				return true;
			}
			catch
			{
				return false;
			}
		}

		public static bool IsKey(RegRoot root, string name)
		{
			try
			{
				RegistryKey key = rootKey(root).OpenSubKey(name);

				if (key == null)
				{
					return false;
				}

				key.Close();

				return true;
			}
			catch
			{
				return false;
			}
		}
	}
}
