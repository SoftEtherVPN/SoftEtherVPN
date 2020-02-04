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
