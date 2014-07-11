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


// NativeStack.c
// Native IP stack

#include "CedarPch.h"

// Stack main thread
void NsMainThread(THREAD *thread, void *param)
{
	NATIVE_STACK *a = (NATIVE_STACK *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		SOCKSET set;
		bool err = false;
		bool flush_tube;
		LIST *recv_packets;
		bool state_changed = false;

		InitSockSet(&set);
		AddSockSet(&set, a->Sock1);

		if (a->Halt)
		{
			break;
		}

		// Pass to the IPC by receiving from the bridge
LABEL_RESTART:
		state_changed = false;
		flush_tube = false;
		while (true)
		{
			void *data;
			UINT size;

			size = EthGetPacket(a->Eth, &data);

			if (size == INFINITE)
			{
				// Device error
				err = true;
				break;
			}
			else if (size == 0)
			{
				// Can not get any more
				break;
			}
			else
			{
				// Pass the IPC socket
				TubeSendEx(a->Sock1->SendTube, data, size, NULL, true);
				Free(data);
				flush_tube = true;
				state_changed = true;
			}
		}

		if (flush_tube)
		{
			TubeFlush(a->Sock1->SendTube);
		}

		// Pass to the bridge by receiving from IPC
		recv_packets = NULL;
		while (true)
		{
			TUBEDATA *d = TubeRecvAsync(a->Sock1->RecvTube);

			if (d == NULL)
			{
				break;
			}

			if (recv_packets == NULL)
			{
				recv_packets = NewListFast(NULL);
			}

			Add(recv_packets, d);

			state_changed = true;
		}
		if (recv_packets != NULL)
		{
			UINT i;
			UINT num = LIST_NUM(recv_packets);
			void **data_array;
			UINT *size_array;

			data_array = Malloc(sizeof(void *) * num);
			size_array = Malloc(sizeof(UINT) * num);

			for (i = 0;i < num;i++)
			{
				TUBEDATA *d = LIST_DATA(recv_packets, i);

				data_array[i] = d->Data;
				size_array[i] = d->DataSize;
			}

			EthPutPackets(a->Eth, num, data_array, size_array);

			for (i = 0;i < num;i++)
			{
				TUBEDATA *d = LIST_DATA(recv_packets, i);

				// Because the data buffer has been already released, not to release twice
				d->Data = NULL;

				FreeTubeData(d);
			}

			Free(data_array);
			Free(size_array);

			ReleaseList(recv_packets);
		}

		if (IsTubeConnected(a->Sock1->SendTube) == false || IsTubeConnected(a->Sock1->RecvTube) == false)
		{
			err = true;
		}

		if (err)
		{
			// An error has occured
			Debug("Native Stack: Error !\n");
			a->Halt = true;
			continue;
		}

		if (state_changed)
		{
			goto LABEL_RESTART;
		}

		Select(&set, 1234, a->Cancel, NULL);
	}

	Disconnect(a->Sock1);
	Disconnect(a->Sock2);
}

// Release the stack
void FreeNativeStack(NATIVE_STACK *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->Ipc != NULL && IsZero(&a->CurrentDhcpOptionList, sizeof(a->CurrentDhcpOptionList)) == false)
	{
		IP dhcp_server;

		UINTToIP(&dhcp_server, a->CurrentDhcpOptionList.ServerAddress);

		IPCDhcpFreeIP(a->Ipc, &dhcp_server);
		SleepThread(200);
	}

	a->Halt = true;
	Cancel(a->Cancel);
	Disconnect(a->Sock1);
	Disconnect(a->Sock2);

	WaitThread(a->MainThread, INFINITE);

	ReleaseThread(a->MainThread);

	CloseEth(a->Eth);
	FreeIPC(a->Ipc);

	ReleaseCancel(a->Cancel);

	ReleaseSock(a->Sock1);
	ReleaseSock(a->Sock2);

	ReleaseCedar(a->Cedar);

	Free(a);
}

// Create a new stack
NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed)
{
	ETH *eth;
	NATIVE_STACK *a;
	IP localhost;
	char tmp[64];
	bool release_cedar = false;
	// Validate arguments
	if (device_name == NULL || mac_address_seed == NULL)
	{
		return NULL;
	}

	if (cedar == NULL)
	{
		cedar = NewCedar(NULL, NULL);
		release_cedar = true;
	}

	GetLocalHostIP4(&localhost);

	// Open the Eth device
	eth = OpenEth(device_name, false, false, NULL);
	if (eth == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(NATIVE_STACK));

	NewSocketPair(&a->Sock1, &a->Sock2, &localhost, 1, &localhost, 1);

	a->Cedar = cedar;
	AddRef(a->Cedar->ref);

	NsGenMacAddress(a->MacAddress, mac_address_seed, device_name);

	BinToStr(tmp, sizeof(tmp), a->MacAddress, sizeof(a->MacAddress));
	Debug("NewNativeStack: MAC Address = %s\n", tmp);

	a->Ipc = NewIPCBySock(cedar, a->Sock2, a->MacAddress);

	StrCpy(a->DeviceName, sizeof(a->DeviceName), device_name);

	a->Eth = eth;
	a->Cancel = EthGetCancel(eth);

	a->MainThread = NewThread(NsMainThread, a);

	if (release_cedar)
	{
		ReleaseCedar(cedar);
	}

	return a;
}

// Identify whether the specified MAC address is for the Native Stack which operate on the same host
bool NsIsMacAddressOnLocalhost(UCHAR *mac)
{
	UCHAR tmp[2];
	// Validate arguments
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] != NS_MAC_ADDRESS_BYTE_1)
	{
		return false;
	}

	NsGenMacAddressSignatureForMachine(tmp, mac);

	if (Cmp(mac + 4, tmp, 2) == 0)
	{
		return true;
	}

	return false;
}

// Determine the last two bytes of the MAC address
void NsGenMacAddressSignatureForMachine(UCHAR *dst_last_2, UCHAR *src_mac_addr_4)
{
	char machine_name[MAX_SIZE];
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (dst_last_2 == NULL || src_mac_addr_4 == NULL)
	{
		return;
	}

	GetMachineHostName(machine_name, sizeof(machine_name));

	Trim(machine_name);
	StrUpper(machine_name);

	b = NewBuf();
	WriteBuf(b, src_mac_addr_4, 4);
	WriteBufStr(b, machine_name);

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(dst_last_2, hash, 2);
}

// Generate the MAC address
void NsGenMacAddress(void *dest, char *mac_address_seed, char *device_name)
{
	char tmp[MAX_SIZE];
	UCHAR mac[6];
	UCHAR hash[SHA1_SIZE];

	Zero(tmp, sizeof(tmp));

	StrCat(tmp, sizeof(tmp), mac_address_seed);
	StrCat(tmp, sizeof(tmp), "@");
	StrCat(tmp, sizeof(tmp), device_name);

	Trim(tmp);

	StrLower(tmp);

	HashSha1(hash, tmp, StrLen(tmp));

	mac[0] = NS_MAC_ADDRESS_BYTE_1;
	mac[1] = hash[1];
	mac[2] = hash[2];
	mac[3] = hash[3];
	mac[4] = hash[4];
	mac[5] = hash[5];

	NsGenMacAddressSignatureForMachine(mac + 4, mac);

	Copy(dest, mac, 6);
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
