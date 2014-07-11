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
using System.Net.Mail;
using System.Net.Mime;
using CoreUtil;

#pragma warning disable 0618

namespace CoreUtil
{
	class WorkerQueuePrivate
	{
		object lockObj = new object();

		List<ThreadObj> thread_list;
		ThreadProc thread_proc;
		int num_worker_threads;
		Queue<object> taskQueue = new Queue<object>();
		Exception raised_exception = null;

		void worker_thread(object param)
		{
			while (true)
			{
				object task = null;

				lock (lockObj)
				{
					if (taskQueue.Count == 0)
					{
						return;
					}
					task = taskQueue.Dequeue();
				}

				try
				{
					this.thread_proc(task);
				}
				catch (Exception ex)
				{
					if (raised_exception == null)
					{
						raised_exception = ex;
					}

					Console.WriteLine(ex.Message);
				}
			}
		}

		public WorkerQueuePrivate(ThreadProc thread_proc, int num_worker_threads, object[] tasks)
		{
			thread_list = new List<ThreadObj>();
			int i;

			this.thread_proc = thread_proc;
			this.num_worker_threads = num_worker_threads;

			foreach (object task in tasks)
			{
				taskQueue.Enqueue(task);
			}

			raised_exception = null;

			for (i = 0; i < num_worker_threads; i++)
			{
				ThreadObj t = new ThreadObj(worker_thread);

				thread_list.Add(t);
			}

			foreach (ThreadObj t in thread_list)
			{
				t.WaitForEnd();
			}

			if (raised_exception != null)
			{
				throw raised_exception;
			}
		}
	}

	public static class Tick64
	{
		static object lock_obj = new object();
		static uint last_value = 0;
		static bool is_first = true;
		static uint num_round = 0;

		public static long Value
		{
			get
			{
				unchecked
				{
					lock (lock_obj)
					{
						uint current_value = (uint)(System.Environment.TickCount + 3864700935);

						if (is_first)
						{
							last_value = current_value;
							is_first = false;
						}

						if (last_value > current_value)
						{
							num_round++;
						}

						last_value = current_value;

						ulong ret = 4294967296UL * (ulong)num_round + current_value;

						return (long)ret;
					}
				}
			}
		}

		public static uint ValueUInt32
		{
			get
			{
				unchecked
				{
					return (uint)((ulong)Value);
				}
			}
		}
	}

	public class Event
	{
		EventWaitHandle h;
		public const int Infinite = Timeout.Infinite;

		public Event()
		{
			init(false);
		}

		public Event(bool manualReset)
		{
			init(manualReset);
		}

		void init(bool manualReset)
		{
			h = new EventWaitHandle(false, (manualReset ? EventResetMode.ManualReset : EventResetMode.AutoReset));
		}

		public void Set()
		{
			h.Set();
		}

		public bool Wait()
		{
			return Wait(Infinite);
		}
		public bool Wait(int millisecs)
		{
			return h.WaitOne(millisecs, false);
		}

		static EventWaitHandle[] toArray(Event[] events)
		{
			List<EventWaitHandle> list = new List<EventWaitHandle>();

			foreach (Event e in events)
			{
				list.Add(e.h);
			}

			return list.ToArray();
		}

		public static bool WaitAll(Event[] events)
		{
			return WaitAll(events, Infinite);
		}
		public static bool WaitAll(Event[] events, int millisecs)
		{
			if (events.Length <= 64)
			{
				return waitAllInner(events, millisecs);
			}
			else
			{
				return waitAllMulti(events, millisecs);
			}
		}

		static bool waitAllMulti(Event[] events, int millisecs)
		{
			int numBlocks = (events.Length + 63) / 64;
			List<Event>[] list = new List<Event>[numBlocks];
			int i;
			for (i = 0; i < numBlocks; i++)
			{
				list[i] = new List<Event>();
			}
			for (i = 0; i < events.Length; i++)
			{
				list[i / 64].Add(events[i]);
			}

			double start = Time.NowDouble;
			double giveup = start + (double)millisecs / 1000.0;
			foreach (List<Event> o in list)
			{
				double now = Time.NowDouble;
				if (now <= giveup || millisecs < 0)
				{
					int waitmsecs;
					if (millisecs >= 0)
					{
						waitmsecs = (int)((giveup - now) * 1000.0);
					}
					else
					{
						waitmsecs = Timeout.Infinite;
					}

					bool ret = waitAllInner(o.ToArray(), waitmsecs);
					if (ret == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}

			return true;
		}

		static bool waitAllInner(Event[] events, int millisecs)
		{
			if (events.Length == 1)
			{
				return events[0].Wait(millisecs);
			}
			return EventWaitHandle.WaitAll(toArray(events), millisecs, false);
		}

		public static bool WaitAny(Event[] events)
		{
			return WaitAny(events, Infinite);
		}
		public static bool WaitAny(Event[] events, int millisecs)
		{
			if (events.Length == 1)
			{
				return events[0].Wait(millisecs);
			}
			return ((WaitHandle.WaitTimeout == EventWaitHandle.WaitAny(toArray(events), millisecs, false)) ? false : true);
		}

		public IntPtr Handle
		{
			get
			{
				return h.Handle;
			}
		}
	}

	public class ThreadData
	{
		static LocalDataStoreSlot slot = Thread.AllocateDataSlot();

		public readonly SortedDictionary<string, object> DataList = new SortedDictionary<string, object>();

		public static ThreadData CurrentThreadData
		{
			get
			{
				return GetCurrentThreadData();
			}
		}

		public static ThreadData GetCurrentThreadData()
		{
			ThreadData t;

			try
			{
				t = (ThreadData)Thread.GetData(slot);
			}
			catch
			{
				t = null;
			}

			if (t == null)
			{
				t = new ThreadData();

				Thread.SetData(slot, t);
			}

			return t;
		}
	}

	public delegate void ThreadProc(object userObject);

	public class ThreadObj
	{
		static int defaultStackSize = 100000;

		static LocalDataStoreSlot currentObjSlot = Thread.AllocateDataSlot();

		public const int Infinite = Timeout.Infinite;

		ThreadProc proc;
		Thread thread;
		EventWaitHandle waitInit;
		EventWaitHandle waitEnd;
		EventWaitHandle waitInitForUser;
		public Thread Thread
		{
			get { return thread; }
		}
		object userObject;

		public ThreadObj(ThreadProc threadProc)
		{
			init(threadProc, null, 0);
		}

		public ThreadObj(ThreadProc threadProc, int stacksize)
		{
			init(threadProc, null, stacksize);
		}

		public ThreadObj(ThreadProc threadProc, object userObject)
		{
			init(threadProc, userObject, 0);
		}

		public ThreadObj(ThreadProc threadProc, object userObject, int stacksize)
		{
			init(threadProc, userObject, stacksize);
		}

		void init(ThreadProc threadProc, object userObject, int stacksize)
		{
			if (stacksize == 0)
			{
				stacksize = defaultStackSize;
			}

			this.proc = threadProc;
			this.userObject = userObject;
			waitInit = new EventWaitHandle(false, EventResetMode.AutoReset);
			waitEnd = new EventWaitHandle(false, EventResetMode.ManualReset);
			waitInitForUser = new EventWaitHandle(false, EventResetMode.ManualReset);
			this.thread = new Thread(new ParameterizedThreadStart(commonThreadProc), stacksize);
			this.thread.Start(this);
			waitInit.WaitOne();
		}

		public static int DefaultStackSize
		{
			get
			{
				return defaultStackSize;
			}

			set
			{
				defaultStackSize = value;
			}
		}

		void commonThreadProc(object obj)
		{
			Thread.SetData(currentObjSlot, this);

			waitInit.Set();

			try
			{
				this.proc(this.userObject);
			}
			finally
			{
				waitEnd.Set();
			}
		}

		public static ThreadObj GetCurrentThreadObj()
		{
			return (ThreadObj)Thread.GetData(currentObjSlot);
		}

		public static void NoticeInited()
		{
			GetCurrentThreadObj().waitInitForUser.Set();
		}

		public void WaitForInit()
		{
			waitInitForUser.WaitOne();
		}

		public void WaitForEnd(int timeout)
		{
			waitEnd.WaitOne(timeout, false);
		}
		public void WaitForEnd()
		{
			waitEnd.WaitOne();
		}

		public static void Sleep(int millisec)
		{
			if (millisec == 0x7fffffff)
			{
				millisec = ThreadObj.Infinite;
			}

			Thread.Sleep(millisec);
		}

		public static void Yield()
		{
			Thread.Sleep(0);
		}

		public static void ProcessWorkQueue(ThreadProc thread_proc, int num_worker_threads, object[] tasks)
		{
			WorkerQueuePrivate q = new WorkerQueuePrivate(thread_proc, num_worker_threads, tasks);
		}
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
