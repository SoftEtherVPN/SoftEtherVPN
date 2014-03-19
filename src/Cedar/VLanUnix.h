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
// USE ONLY IN JAPAN. DO NOT USE IT IN OTHER COUNTRIES. IMPORTING THIS
// SOFTWARE INTO OTHER COUNTRIES IS AT YOUR OWN RISK. SOME COUNTRIES
// PROHIBIT ENCRYPTED COMMUNICATIONS. USING THIS SOFTWARE IN OTHER
// COUNTRIES MIGHT BE RESTRICTED.
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


// VLanUnix.h
// Header of VLanUnix.c

#ifndef	VLANUNIX_H
#define	VLANUNIX_H

// Constant
#define	TAP_READ_BUF_SIZE			1600

#ifndef	NO_VLAN

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halt flag
	char *InstanceName;			// Instance name
	int fd;						// File
};

// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
VLAN *NewTap(char *name, char *mac_address);
void FreeVLan(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

#else	// NO_VLAN

#define	VLanGetPacketAdapter	NullGetPacketAdapter

#endif	// NO_VLAN

struct UNIX_VLAN_LIST
{
	char Name[MAX_SIZE];		// Device name
	int fd;						// fd
};

int UnixCreateTapDevice(char *name, UCHAR *mac_address);
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address);
void UnixCloseTapDevice(int fd);
void UnixVLanInit();
void UnixVLanFree();
bool UnixVLanCreate(char *name, UCHAR *mac_address);
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address);
TOKEN_LIST *UnixVLanEnum();
void UnixVLanDelete(char *name);
int UnixVLanGet(char *name);
int UnixCompareVLan(void *p1, void *p2);

#endif	// VLANUNIX_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
