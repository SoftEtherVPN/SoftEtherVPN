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

namespace CoreUtil
{
	class TimeHelper
	{
		internal Stopwatch Sw;
		internal long Freq;
		internal DateTime FirstDateTime;

		public TimeHelper()
		{
			FirstDateTime = DateTime.Now;
			Sw = new Stopwatch();
			Sw.Start();
			Freq = Stopwatch.Frequency;
		}

		public DateTime GetDateTime()
		{
			return FirstDateTime + this.Sw.Elapsed;
		}
	}

	public static class Time
	{
		static TimeHelper h = new TimeHelper();
		static TimeSpan baseTimeSpan = new TimeSpan(0, 0, 1);

		static public TimeSpan NowTimeSpan
		{
			get
			{
				return h.Sw.Elapsed.Add(baseTimeSpan);
			}
		}

		static public long NowLong100Usecs
		{
			get
			{
				return NowTimeSpan.Ticks;
			}
		}

		static public long NowLongMillisecs
		{
			get
			{
				return NowLong100Usecs / 10000;
			}
		}

		static public long Tick64
		{
			get
			{
				return NowLongMillisecs;
			}
		}

		static public double NowDouble
		{
			get
			{
				return (double)NowLong100Usecs / (double)10000000.0;
			}
		}

		static public DateTime NowDateTime
		{
			get
			{
				return h.GetDateTime();
			}
		}
	}
}
