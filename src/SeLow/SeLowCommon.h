// SoftEther VPN Source Code
// SeLow - SoftEther Lightweight Network Protocol
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


// SeLowCommon.h
// Common Header for Kernel Mode / User Mode

//// Version number
// Change this number every time functions are added or modified on the driver.
// As long as this number does not change, installation of SeLow during the update
// installation of the VPN Server / VPN Client / VPN Bridge is skipped.
#define	SL_VER						45

// Constants
#define	SL_MAX_PACKET_SIZE			1600
#define	SL_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	SL_MIN_PACKET_SIZE			14
#define	SL_PACKET_HEADER_SIZE		14
#define	SL_MAX_FRAME_SIZE			(SL_MAX_PACKET_SIZE - SL_MIN_PACKET_SIZE)

#define	SL_PROTOCOL_NAME			"SeLow"
#define	SL_EVENT_NAME_SIZE			128

#define	SL_ENUM_COMPLETE_GIVEUP_TICK	(15 * 1000)

// IOCTL
#define	SL_IOCTL_GET_EVENT_NAME		CTL_CODE(0x8000, 1, METHOD_NEITHER, FILE_ANY_ACCESS)

// IOCTL data structure
typedef struct SL_IOCTL_EVENT_NAME
{
	char EventNameWin32[SL_EVENT_NAME_SIZE];		// Event name
} SL_IOCTL_EVENT_NAME;

// Device ID
#define	SL_BASIC_DEVICE_NAME			"\\Device\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_FILENAME_WIN32	"\\\\.\\SELOW_BASIC_DEVICE"
#define	SL_ADAPTER_ID_PREFIX			"SELOW_A_"
#define	SL_ADAPTER_ID_PREFIX_W			L"SELOW_A_"
#define	SL_ADAPTER_DEVICE_NAME			"\\Device\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_FILENAME_WIN32	"\\\\.\\%s"

// Event name
#define	SL_EVENT_NAME					"\\BaseNamedObjects\\SELOW_EVENT_%u_%u"
#define	SL_EVENT_NAME_WIN32				"Global\\SELOW_EVENT_%u_%u"

// Registry key
#define	SL_REG_KEY_NAME					"SYSTEM\\CurrentControlSet\\services\\SeLow"
#define	SL_REG_VER_VALUE				"SlVersion"
#define	SL_REG_VER_VALUE_WIN10			"SlVersion_Win10"

// Adapter data
#define	SL_ADAPTER_ID_LEN				64
typedef struct SL_ADAPTER_INFO
{
	wchar_t AdapterId[SL_ADAPTER_ID_LEN];	// Adapter ID
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding1[2];
	UINT MtuSize;						// MTU size
	char FriendlyName[256];				// Display name
	UINT SupportsVLanHw;				// Supports VLAN by HW
	UCHAR Reserved[256 - sizeof(UINT)];	// Reserved area
} SL_ADAPTER_INFO;

#define	SL_MAX_ADAPTER_INFO_LIST_ENTRY	256
#define	SL_SIGNATURE					0xDEADBEEF

typedef struct SL_ADAPTER_INFO_LIST
{
	UINT Signature;													// Signature
	UINT SeLowVersion;												// Version of SeLow
	UINT EnumCompleted;												// Enumeration completion flag
	UINT NumAdapters;												// The total number of adapter
	SL_ADAPTER_INFO Adapters[SL_MAX_ADAPTER_INFO_LIST_ENTRY];		// Array of adapter
} SL_ADAPTER_INFO_LIST;


// Packet data exchange related
#define	SL_MAX_PACKET_EXCHANGE		256			// Number of packets that can be exchanged at a time
#define	SL_MAX_PACKET_QUEUED		4096		// Maximum number of packets that can be queued
#define	SL_EX_SIZEOF_NUM_PACKET	4			// Packet count data (UINT)
#define	SL_EX_SIZEOF_LENGTH_PACKET	4			// Length data of the packet data (UINT)
#define	SL_EX_SIZEOF_LEFT_FLAG		4			// Flag to indicate that the packet is left
#define	SL_EX_SIZEOF_ONE_PACKET	1600		// Data area occupied by a packet data
#define	SL_EXCHANGE_BUFFER_SIZE	(SL_EX_SIZEOF_NUM_PACKET + SL_EX_SIZEOF_LEFT_FLAG +	\
	(SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET) * (SL_MAX_PACKET_EXCHANGE + 1))
#define	SL_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	SL_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	SL_EX_SIZEOF_LENGTH_PACKET +	\
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_LEFT_FLAG(buf)			SL_SIZE_OF_PACKET(buf, SL_MAX_PACKET_EXCHANGE)



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
