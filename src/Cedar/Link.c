// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
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


// Link.c
// Inter-HUB Link

#include "CedarPch.h"

// Link server thread
void LinkServerSessionThread(THREAD *t, void *param)
{
	LINK *k = (LINK *)param;
	CONNECTION *c;
	SESSION *s;
	POLICY *policy;
	wchar_t name[MAX_SIZE];
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	// Create a server connection
	c = NewServerConnection(k->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_LINK_SERVER;

	// Create a policy
	policy = ZeroMalloc(sizeof(POLICY));
	Copy(policy, k->Policy, sizeof(POLICY));

	// Create a server session
	s = NewServerSession(k->Cedar, c, k->Hub, LINK_USER_NAME, policy);
	s->LinkModeServer = true;
	s->Link = k;
	c->Session = s;
	ReleaseConnection(c);

	// User name
	s->Username = CopyStr(LINK_USER_NAME_PRINT);

	k->ServerSession = s;
	AddRef(k->ServerSession->ref);

	// Notify the initialization completion
	NoticeThreadInit(t);

	UniStrCpy(name, sizeof(name), k->Option->AccountName);
	HLog(s->Hub, "LH_LINK_START", name, s->Name);

	// Main function of session
	SessionMain(s);

	HLog(s->Hub, "LH_LINK_STOP", name);

	ReleaseSession(s);
}

// Initialize the packet adapter
bool LinkPaInit(SESSION *s)
{
	LINK *k;
	THREAD *t;
	// Validate arguments
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	if (k->Halting || (*k->StopAllLinkFlag))
	{
		return false;
	}

	// Create a transmission packet queue
	k->SendPacketQueue = NewQueue();

	// Creat a link server thread
	t = NewThread(LinkServerSessionThread, (void *)k);
	WaitThreadInit(t);

	k->LastServerConnectionReceivedBlocksNum = 0;
	k->CurrentSendPacketQueueSize = 0;

	ReleaseThread(t);

	return true;
}

// Get the cancel object
CANCEL *LinkPaGetCancel(SESSION *s)
{
	LINK *k;
	// Validate arguments
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	return NULL;
}

// Get the next packet
UINT LinkPaGetNextPacket(SESSION *s, void **data)
{
	LINK *k;
	UINT ret = 0;
	// Validate arguments
	if (s == NULL || data == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	if (k->Halting || (*k->StopAllLinkFlag))
	{
		return INFINITE;
	}
	// Examine whether there are packets in the queue
	LockQueue(k->SendPacketQueue);
	{
		BLOCK *block = GetNext(k->SendPacketQueue);

		if (block != NULL)
		{
			// There was a packet
			*data = block->Buf;
			ret = block->Size;

			k->CurrentSendPacketQueueSize -= block->Size;

			// Discard the memory for the structure
			Free(block);
		}
	}
	UnlockQueue(k->SendPacketQueue);

	return ret;
}

// Write the received packet
bool LinkPaPutPacket(SESSION *s, void *data, UINT size)
{
	LINK *k;
	BLOCK *block = NULL;
	SESSION *server_session;
	CONNECTION *server_connection;
	bool ret = true;
	bool halting = false;
	// Validate arguments
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	halting = (k->Halting || (*k->StopAllLinkFlag));

	server_session = k->ServerSession;
	server_connection = server_session->Connection;

	k->Flag1++;
	if ((k->Flag1 % 32) == 0)
	{
		// Ommit for performance
		UINT current_num;
		int diff;

		current_num = GetQueueNum(server_connection->ReceivedBlocks);

		diff = (int)current_num - (int)k->LastServerConnectionReceivedBlocksNum;

		k->LastServerConnectionReceivedBlocksNum = current_num;

		CedarAddQueueBudget(k->Cedar, diff);
	}

	// Since the packet arrives from the HUB of the link destination,
	// deliver it to the ReceivedBlocks of the server session
	if (data != NULL)
	{
		if (halting == false)
		{
			block = NewBlock(data, size, 0);
		}

		if (k->LockFlag == false)
		{
			UINT current_num;
			int diff;

			k->LockFlag = true;
			LockQueue(server_connection->ReceivedBlocks);

			current_num = GetQueueNum(server_connection->ReceivedBlocks);

			diff = (int)current_num - (int)k->LastServerConnectionReceivedBlocksNum;

			k->LastServerConnectionReceivedBlocksNum = current_num;

			CedarAddQueueBudget(k->Cedar, diff);
		}

		if (halting == false)
		{
			if (CedarGetFifoBudgetBalance(k->Cedar) == 0)
			{
				FreeBlock(block);
			}
			else
			{
				InsertReveicedBlockToQueue(server_connection, block, true);
			}
		}
	}
	else
	{
		UINT current_num;
		int diff;

		current_num = GetQueueNum(server_connection->ReceivedBlocks);

		diff = (int)current_num - (int)k->LastServerConnectionReceivedBlocksNum;

		k->LastServerConnectionReceivedBlocksNum = current_num;

		CedarAddQueueBudget(k->Cedar, diff);

		if (k->LockFlag)
		{
			k->LockFlag = false;
			UnlockQueue(server_connection->ReceivedBlocks);
		}

		// Issue the Cancel, since finished store all packets when the data == NULL
		Cancel(server_session->Cancel1);

		if (k->Hub != NULL && k->Hub->Option != NULL && k->Hub->Option->YieldAfterStorePacket)
		{
			YieldCpu();
		}
	}

	if (halting)
	{
		ret = false;
	}

	return ret;
}

// Release the packet adapter
void LinkPaFree(SESSION *s)
{
	LINK *k;
	// Validate arguments
	if (s == NULL || (k = (LINK *)s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	CedarAddQueueBudget(k->Cedar, -((int)k->LastServerConnectionReceivedBlocksNum));
	k->LastServerConnectionReceivedBlocksNum = 0;

	// Stop the server session
	StopSession(k->ServerSession);
	ReleaseSession(k->ServerSession);

	// Release the transmission packet queue
	LockQueue(k->SendPacketQueue);
	{
		BLOCK *block;
		while (block = GetNext(k->SendPacketQueue))
		{
			FreeBlock(block);
		}
	}
	UnlockQueue(k->SendPacketQueue);

	ReleaseQueue(k->SendPacketQueue);

	k->CurrentSendPacketQueueSize = 0;
}

// Packet adapter
PACKET_ADAPTER *LinkGetPacketAdapter()
{
	return NewPacketAdapter(LinkPaInit, LinkPaGetCancel, LinkPaGetNextPacket,
		LinkPaPutPacket, LinkPaFree);
}

// Release all links
void ReleaseAllLink(HUB *h)
{
	LINK **kk;
	UINT num, i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		num = LIST_NUM(h->LinkList);
		kk = ToArray(h->LinkList);
		DeleteAll(h->LinkList);
	}
	UnlockList(h->LinkList);

	for (i = 0;i < num;i++)
	{
		LINK *k = kk[i];

		ReleaseLink(k);
	}

	Free(kk);
}

// Release the link
void ReleaseLink(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	if (Release(k->ref) == 0)
	{
		CleanupLink(k);
	}
}

// Clean-up the link
void CleanupLink(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	DeleteLock(k->lock);
	if (k->ClientSession)
	{
		ReleaseSession(k->ClientSession);
	}
	Free(k->Option);
	CiFreeClientAuth(k->Auth);
	Free(k->Policy);

	if (k->ServerCert != NULL)
	{
		FreeX(k->ServerCert);
	}

	Free(k);
}

// Make the link on-line
void SetLinkOnline(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	if (k->NoOnline)
	{
		return;
	}

	if (k->Offline == false)
	{
		return;
	}

	k->Offline = false;
	StartLink(k);
}

// Make the link off-line
void SetLinkOffline(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	if (k->Offline)
	{
		return;
	}

	StopLink(k);
	k->Offline = true;
}

// Delete the link
void DelLink(HUB *hub, LINK *k)
{
	// Validate arguments
	if (hub == NULL || k == NULL)
	{
		return;
	}

	LockList(hub->LinkList);
	{
		if (Delete(hub->LinkList, k))
		{
			ReleaseLink(k);
		}
	}
	UnlockList(hub->LinkList);
}

// Start all links
void StartAllLink(HUB *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = (LINK *)LIST_DATA(h->LinkList, i);

			if (k->Offline == false)
			{
				StartLink(k);
			}
		}
	}
	UnlockList(h->LinkList);
}

// Stop all links
void StopAllLink(HUB *h)
{
	LINK **link_list;
	UINT num_link;
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	h->StopAllLinkFlag = true;

	LockList(h->LinkList);
	{
		link_list = ToArray(h->LinkList);
		num_link = LIST_NUM(h->LinkList);
		for (i = 0;i < num_link;i++)
		{
			AddRef(link_list[i]->ref);
		}
	}
	UnlockList(h->LinkList);

	for (i = 0;i < num_link;i++)
	{
		StopLink(link_list[i]);
		ReleaseLink(link_list[i]);
	}

	Free(link_list);

	h->StopAllLinkFlag = false;
}

// Start the link
void StartLink(LINK *k)
{
	PACKET_ADAPTER *pa;
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	LockLink(k);
	{
		if (k->Started || k->Halting)
		{
			UnlockLink(k);
			return;
		}
		k->Started = true;

		Inc(k->Cedar->CurrentActiveLinks);
	}
	UnlockLink(k);

	// Connect the client session
	pa = LinkGetPacketAdapter();
	pa->Param = (void *)k;
	LockLink(k);
	{
		k->ClientSession = NewClientSession(k->Cedar, k->Option, k->Auth, pa);
	}
	UnlockLink(k);
}

// Stop the link
void StopLink(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	LockLink(k);
	{
		if (k->Started == false)
		{
			UnlockLink(k);
			return;
		}
		k->Started = false;
		k->Halting = true;

		Dec(k->Cedar->CurrentActiveLinks);
	}
	UnlockLink(k);

	if (k->ClientSession != NULL)
	{
		// Disconnect the client session
		StopSession(k->ClientSession);

		LockLink(k);
		{
			ReleaseSession(k->ClientSession);
			k->ClientSession = NULL;
		}
		UnlockLink(k);
	}

	LockLink(k);
	{
		k->Halting = false;
	}
	UnlockLink(k);
}

// Lock the link
void LockLink(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	Lock(k->lock);
}

// Unlock the link
void UnlockLink(LINK *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	Unlock(k->lock);
}

// Normalize the policy for the link
void NormalizeLinkPolicy(POLICY *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->Access = true;
	p->NoBridge = p->NoRouting = p->MonitorPort = false;
	p->MaxConnection = 32;
	p->TimeOut = 20;
	p->FixPassword = false;
}

// Create a Link
LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy)
{
	CLIENT_OPTION *o;
	LINK *k;
	CLIENT_AUTH *a;
	// Validate arguments
	if (cedar == NULL || hub == NULL || option == NULL || auth == NULL || policy == NULL)
	{
		return NULL;
	}
	if (hub->Halt)
	{
		return NULL;
	}

	if (LIST_NUM(hub->LinkList) >= MAX_HUB_LINKS)
	{
		return NULL;
	}

	if (UniIsEmptyStr(option->AccountName))
	{
		return NULL;
	}

	// Limitation of authentication method
	if (auth->AuthType != CLIENT_AUTHTYPE_ANONYMOUS && auth->AuthType != CLIENT_AUTHTYPE_PASSWORD &&
		auth->AuthType != CLIENT_AUTHTYPE_PLAIN_PASSWORD && auth->AuthType != CLIENT_AUTHTYPE_CERT)
	{
		// Authentication method other than anonymous authentication, password authentication, plain password, certificate authentication cannot be used
		return NULL;
	}

	// Copy of the client options (for modification)
	o = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(o, option, sizeof(CLIENT_OPTION));
	StrCpy(o->DeviceName, sizeof(o->DeviceName), LINK_DEVICE_NAME);

	o->RequireBridgeRoutingMode = true;	// Request the bridge mode
	o->RequireMonitorMode = false;	// Not to require the monitor mode

	o->NumRetry = INFINITE;			// Retry the connection infinitely
	o->RetryInterval = 10;			// Retry interval is 10 seconds
	o->NoRoutingTracking = true;	// Stop the routing tracking

	// Copy the authentication data
	a = CopyClientAuth(auth);
	a->SecureSignProc = NULL;
	a->CheckCertProc = NULL;

	// Link object
	k = ZeroMalloc(sizeof(LINK));

	k->StopAllLinkFlag = &hub->StopAllLinkFlag;

	k->lock = NewLock();
	k->ref = NewRef();

	k->Cedar = cedar;
	k->Option = o;
	k->Auth = a;
	k->Hub = hub;

	// Copy the policy
	k->Policy = ZeroMalloc(sizeof(POLICY));
	Copy(k->Policy, policy, sizeof(POLICY));

	// Normalize the policy
	NormalizeLinkPolicy(k->Policy);

	// Register in the link list of the HUB
	LockList(hub->LinkList);
	{
		Add(hub->LinkList, k);
		AddRef(k->ref);
	}
	UnlockList(hub->LinkList);

	return k;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
