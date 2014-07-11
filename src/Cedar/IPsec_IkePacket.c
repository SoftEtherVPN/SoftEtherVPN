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


// IPsec_IkePacket.c
// IKE (ISAKMP) packet processing

#include "CedarPch.h"

// Convert the string to a password
BUF *IkeStrToPassword(char *str)
{
	BUF *b;
	// Validate arguments
	if (str == NULL)
	{
		return NewBuf();
	}

	if (StartWith(str, "0x") == false)
	{
		// Accept the string as is
		b = NewBuf();
		WriteBuf(b, str, StrLen(str));
	}
	else
	{
		// Interpret as a hexadecimal value
		b = StrToBin(str + 2);
	}

	return b;
}

// Phase 1: Convert the encryption algorithm name to key size
UINT IkePhase1CryptIdToKeySize(UCHAR id)
{
	switch (id)
	{
	case IKE_P1_CRYPTO_3DES_CBC:
		return DES3_KEY_SIZE;

	case IKE_P1_CRYPTO_DES_CBC:
		return DES_KEY_SIZE;
	}

	return 0;
}

// Phase 2: Convert the encryption algorithm name to key size
UINT IkePhase2CryptIdToKeySize(UCHAR id)
{
	switch (id)
	{
	case IKE_TRANSFORM_ID_P2_ESP_3DES:
		return DES3_KEY_SIZE;

	case IKE_TRANSFORM_ID_P2_ESP_DES:
		return DES_KEY_SIZE;
	}

	return 0;
}

// Convert a string to an algorithm name
UCHAR IkeStrToPhase1CryptId(char *name)
{
	if (StartWith(name, "3DES") || StartWith("3DES", name))
	{
		return IKE_P1_CRYPTO_3DES_CBC;
	}
	else if (StartWith(name, "DES") || StartWith("DES", name))
	{
		return IKE_P1_CRYPTO_DES_CBC;
	}
	else
	{
		return 0;
	}
}
UCHAR IkeStrToPhase1HashId(char *name)
{
	if (StartWith(name, "SHA-1") || StartWith("SHA-1", name))
	{
		return IKE_P1_HASH_SHA1;
	}

	return 0;
}
UCHAR IkeStrToPhase2CryptId(char *name)
{
	if (StartWith(name, "3DES") || StartWith("3DES", name))
	{
		return IKE_TRANSFORM_ID_P2_ESP_3DES;
	}
	else if (StartWith(name, "DES") || StartWith("DES", name))
	{
		return IKE_TRANSFORM_ID_P2_ESP_DES;
	}
	else
	{
		return 0;
	}
}
UCHAR IkeStrToPhase2HashId(char *name)
{
	if (StartWith(name, "SHA-1") || StartWith("SHA-1", name))
	{
		return IKE_P2_HMAC_SHA1_96;
	}

	return 0;
}

// Build a data payload
BUF *IkeBuildDataPayload(IKE_PACKET_DATA_PAYLOAD *t)
{
	BUF *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, t->Data->Buf, t->Data->Size);

	return b;
}

// Build a SA payload
BUF *IkeBuildSaPayload(IKE_PACKET_SA_PAYLOAD *t)
{
	IKE_SA_HEADER h;
	BUF *ret;
	BUF *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.Situation = Endian32(IKE_SA_SITUATION_IDENTITY);

	ret = NewBuf();

	WriteBuf(ret, &h, sizeof(h));

	b = IkeBuildPayloadList(t->PayloadList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Build a proposal payload
BUF *IkeBuildProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t)
{
	IKE_PROPOSAL_HEADER h;
	BUF *ret, *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.Number = t->Number;
	h.NumTransforms = LIST_NUM(t->PayloadList);
	h.ProtocolId = t->ProtocolId;
	h.SpiSize = t->Spi->Size;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->Spi);

	b = IkeBuildPayloadList(t->PayloadList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Build the transform value list
BUF *IkeBuildTransformValueList(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(o, i);
		BUF *tmp = IkeBuildTransformValue(v);

		WriteBufBuf(b, tmp);

		FreeBuf(tmp);
	}

	return b;
}

// Build a transform value
BUF *IkeBuildTransformValue(IKE_PACKET_TRANSFORM_VALUE *v)
{
	BUF *b;
	UCHAR af_bit, type;
	USHORT size_or_value;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	type = v->Type;

	if (v->Value >= 65536)
	{
		// 32 bit
		af_bit = 0;
		size_or_value = Endian16(sizeof(UINT));
	}
	else
	{
		// 16 bit
		af_bit = 0x80;
		size_or_value = Endian16((USHORT)v->Value);
	}

	b = NewBuf();
	WriteBuf(b, &af_bit, sizeof(af_bit));
	WriteBuf(b, &type, sizeof(type));
	WriteBuf(b, &size_or_value, sizeof(size_or_value));

	if (af_bit == 0)
	{
		UINT value = Endian32(v->Value);
		WriteBuf(b, &value, sizeof(UINT));
	}

	return b;
}

// Build a transform payload
BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t)
{
	IKE_TRANSFORM_HEADER h;
	BUF *ret, *b;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.Number = t->Number;
	h.TransformId = t->TransformId;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	b = IkeBuildTransformValueList(t->ValueList);
	WriteBufBuf(ret, b);

	FreeBuf(b);

	return ret;
}

// Get the value from the transform payload
UINT IkeGetTransformValue(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type, UINT index)
{
	UINT i;
	UINT num;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(t->ValueList);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(t->ValueList, i);

		if (v->Type == type)
		{
			if (num == index)
			{
				return v->Value;
			}

			num++;
		}
	}

	return 0;
}

// Get the number of values from the transform payload
UINT IkeGetTransformValueNum(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type)
{
	UINT i;
	UINT num;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(t->ValueList);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(t->ValueList, i);

		if (v->Type == type)
		{
			num++;
		}
	}

	return num;
}

// Build the ID payload
BUF *IkeBuildIdPayload(IKE_PACKET_ID_PAYLOAD *t)
{
	IKE_ID_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.IdType = t->Type;
	h.Port = Endian16(t->Port);
	h.ProtocolId = t->ProtocolId;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	WriteBufBuf(ret, t->IdData);

	return ret;
}

// Build a certificate payload
BUF *IkeBuildCertPayload(IKE_PACKET_CERT_PAYLOAD *t)
{
	IKE_CERT_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.CertType = t->CertType;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->CertData);

	return ret;
}

// Build a certificate request payload
BUF *IkeBuildCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t)
{
	IKE_CERT_REQUEST_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.CertType = t->CertType;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, t->Data);

	return ret;
}

// Build a notification payload
BUF *IkeBuildNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t)
{
	IKE_NOTICE_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.MessageType = Endian16(t->MessageType);
	h.ProtocolId = t->ProtocolId;
	h.SpiSize = t->Spi->Size;

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBuf(ret, t->Spi->Buf, t->Spi->Size);

	if (t->MessageData != NULL)
	{
		WriteBuf(ret, t->MessageData->Buf, t->MessageData->Size);
	}

	return ret;
}

// Build a NAT-OA payload
BUF *IkeBuildNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t)
{
	IKE_NAT_OA_HEADER h;
	BUF *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	if (IsIP6(&t->IpAddress))
	{
		h.IdType = IKE_ID_IPV6_ADDR;
	}
	else
	{
		h.IdType = IKE_ID_IPV4_ADDR;
	}

	ret = NewBuf();

	WriteBuf(ret, &h, sizeof(h));

	if (IsIP6(&t->IpAddress))
	{
		WriteBuf(ret, t->IpAddress.ipv6_addr, 16);
	}
	else
	{
		WriteBuf(ret, t->IpAddress.addr, 4);
	}

	return ret;
}

// Build a deletion payload
BUF *IkeBuildDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t)
{
	IKE_DELETE_HEADER h;
	BUF *ret;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.DoI = Endian32(IKE_SA_DOI_IPSEC);
	h.NumSpis = Endian16(LIST_NUM(t->SpiList));
	h.ProtocolId = t->ProtocolId;

	if (LIST_NUM(t->SpiList) >= 1)
	{
		BUF *b = LIST_DATA(t->SpiList, 0);

		h.SpiSize = b->Size;
	}

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));

	for (i = 0;i < LIST_NUM(t->SpiList);i++)
	{
		BUF *b = LIST_DATA(t->SpiList, i);

		WriteBuf(ret, b->Buf, b->Size);
	}

	return ret;
}

// Build a bit array from the payload
BUF *IkeBuildPayload(IKE_PACKET_PAYLOAD *p)
{
	BUF *b = NULL;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		b = IkeBuildSaPayload(&p->Payload.Sa);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		b = IkeBuildProposalPayload(&p->Payload.Proposal);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Transform payload
		b = IkeBuildTransformPayload(&p->Payload.Transform);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		b = IkeBuildIdPayload(&p->Payload.Id);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
		b = IkeBuildCertPayload(&p->Payload.Cert);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
		b = IkeBuildCertRequestPayload(&p->Payload.CertRequest);
		break;

	case IKE_PAYLOAD_NOTICE:			// Notification Payload
		b = IkeBuildNoticePayload(&p->Payload.Notice);
		break;

	case IKE_PAYLOAD_DELETE:			// Deletion payload
		b = IkeBuildDeletePayload(&p->Payload.Delete);
		break;

	case IKE_PAYLOAD_NAT_OA:			// NAT-OA payload
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		b = IkeBuildNatOaPayload(&p->Payload.NatOa);
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	default:
		b = IkeBuildDataPayload(&p->Payload.GeneralData);
		break;
	}

	if (b != NULL)
	{
		if (p->BitArray != NULL)
		{
			FreeBuf(p->BitArray);
		}
		p->BitArray = CloneBuf(b);
	}

	return b;
}

// Get the payload type of the first item
UCHAR IkeGetFirstPayloadType(LIST *o)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (o == NULL)
	{
		return IKE_PAYLOAD_NONE;
	}

	if (LIST_NUM(o) == 0)
	{
		return IKE_PAYLOAD_NONE;
	}

	p = (IKE_PACKET_PAYLOAD *)LIST_DATA(o, 0);

	return p->PayloadType;
}

// Build a bit array from the payload list
BUF *IkeBuildPayloadList(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);
		IKE_PACKET_PAYLOAD *next = NULL;
		IKE_COMMON_HEADER h;
		BUF *tmp;

		if (i < (LIST_NUM(o) - 1))
		{
			next = LIST_DATA(o, i + 1);
		}

		Zero(&h, sizeof(h));
		if (next != NULL)
		{
			h.NextPayload = next->PayloadType;
		}
		else
		{
			h.NextPayload = IKE_PAYLOAD_NONE;
		}

		tmp = IkeBuildPayload(p);
		if (tmp != NULL)
		{
			h.PayloadSize = Endian16(tmp->Size + (USHORT)sizeof(h));

			WriteBuf(b, &h, sizeof(h));
			WriteBuf(b, tmp->Buf, tmp->Size);

			FreeBuf(tmp);
		}
	}

	SeekBuf(b, 0, 0);

	return b;
}

// Get the specified payload
IKE_PACKET_PAYLOAD *IkeGetPayload(LIST *o, UINT payload_type, UINT index)
{
	UINT i, num;
	IKE_PACKET_PAYLOAD *ret = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		if (p->PayloadType == payload_type)
		{
			if (num == index)
			{
				ret = p;
				break;
			}

			num++;
		}
	}

	return ret;
}

// Get the number of the payload of the specified type
UINT IkeGetPayloadNum(LIST *o, UINT payload_type)
{
	UINT i, num;
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		if (p->PayloadType == payload_type)
		{
			num++;
		}
	}

	return num;
}

// Create a deletion payload
IKE_PACKET_PAYLOAD *IkeNewDeletePayload(UCHAR protocol_id, LIST *spi_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (spi_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_DELETE);
	p->Payload.Delete.ProtocolId = protocol_id;
	p->Payload.Delete.SpiList = spi_list;

	return p;
}

// Create a Notification payload
IKE_PACKET_PAYLOAD *IkeNewNoticePayload(UCHAR protocol_id, USHORT message_type,
										void *spi, UINT spi_size,
										void *message, UINT message_size)
{
	IKE_PACKET_PAYLOAD *p;
	if (spi == NULL && spi_size != 0)
	{
		return NULL;
	}
	if (message == NULL && message_size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_NOTICE);
	p->Payload.Notice.MessageType = message_type;
	p->Payload.Notice.MessageData = MemToBuf(message, message_size);
	p->Payload.Notice.Spi = MemToBuf(spi, spi_size);
	p->Payload.Notice.ProtocolId = protocol_id;

	return p;
}

// Create a Invalid Cookie Payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidCookiePayload(UINT64 init_cookie, UINT64 resp_cookie)
{
	IKE_PACKET_PAYLOAD *ret;
	BUF *b = NewBuf();

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IKE, IKE_NOTICE_ERROR_INVALID_COOKIE, b->Buf, b->Size,
		b->Buf, b->Size);

	FreeBuf(b);

	return ret;
}

// Create an Invalid Exchange Type Payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidExchangeTypePayload(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type)
{
	IKE_PACKET_PAYLOAD *ret;
	BUF *b = NewBuf();

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IKE, IKE_NOTICE_ERROR_INVALID_EXCHANGE_TYPE, b->Buf, b->Size,
		&exchange_type, 1);

	FreeBuf(b);

	return ret;
}

// Create an Invalid SPI payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidSpiPayload(UINT spi)
{
	IKE_PACKET_PAYLOAD *ret;
	spi = Endian32(spi);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IPSEC_ESP, IKE_NOTICE_ERROR_INVALID_SPI, &spi, sizeof(UINT),
		&spi, sizeof(UINT));

	return ret;
}

// Create a No Proposal Chosen payload
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorNoProposalChosenPayload(bool quick_mode, UINT64 init_cookie, UINT64 resp_cookie)
{
	BUF *b = NewBuf();
	IKE_PACKET_PAYLOAD *ret;

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload((quick_mode ? IKE_PROTOCOL_ID_IPSEC_ESP : IKE_PROTOCOL_ID_IKE),
		IKE_NOTICE_ERROR_NO_PROPOSAL_CHOSEN, b->Buf, b->Size,
		NULL, 0);

	FreeBuf(b);

	return ret;
}

// Create a DPD payload
IKE_PACKET_PAYLOAD *IkeNewNoticeDpdPayload(bool ack, UINT64 init_cookie, UINT64 resp_cookie, UINT seq_no)
{
	IKE_PACKET_PAYLOAD *ret;
	BUF *b = NewBuf();

	seq_no = Endian32(seq_no);

	WriteBufInt64(b, init_cookie);
	WriteBufInt64(b, resp_cookie);

	ret = IkeNewNoticePayload(IKE_PROTOCOL_ID_IKE, (ack ? IKE_NOTICE_DPD_RESPONSE : IKE_NOTICE_DPD_REQUEST),
		b->Buf, b->Size,
		&seq_no, sizeof(UINT));

	FreeBuf(b);

	return ret;
}

// Create a Certificate Request Payload
IKE_PACKET_PAYLOAD *IkeNewCertRequestPayload(UCHAR cert_type, void *data, UINT size)
{
	IKE_PACKET_PAYLOAD *p;
	if (data == NULL && size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_CERT_REQUEST);
	p->Payload.CertRequest.CertType = cert_type;
	p->Payload.CertRequest.Data = MemToBuf(data, size);

	return p;
}

// Create a Certificate payload
IKE_PACKET_PAYLOAD *IkeNewCertPayload(UCHAR cert_type, void *cert_data, UINT cert_size)
{
	IKE_PACKET_PAYLOAD *p;
	if (cert_data == NULL && cert_size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_CERT);
	p->Payload.Cert.CertType = cert_type;
	p->Payload.Cert.CertData = MemToBuf(cert_data, cert_size);

	return p;
}

// Create an ID payload
IKE_PACKET_PAYLOAD *IkeNewIdPayload(UCHAR id_type, UCHAR protocol_id, USHORT port, void *id_data, UINT id_size)
{
	IKE_PACKET_PAYLOAD *p;
	if (id_data == NULL && id_size != 0)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_ID);
	p->Payload.Id.IdData = MemToBuf(id_data, id_size);
	p->Payload.Id.Port = port;
	p->Payload.Id.ProtocolId = protocol_id;
	p->Payload.Id.Type = id_type;

	return p;
}

// Create a transform payload
IKE_PACKET_PAYLOAD *IkeNewTransformPayload(UCHAR number, UCHAR transform_id, LIST *value_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (value_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_TRANSFORM);
	p->Payload.Transform.Number = number;
	p->Payload.Transform.TransformId = transform_id;
	p->Payload.Transform.ValueList = value_list;

	return p;
}

// Create a proposal payload
IKE_PACKET_PAYLOAD *IkeNewProposalPayload(UCHAR number, UCHAR protocol_id, void *spi, UINT spi_size, LIST *payload_list)
{
	IKE_PACKET_PAYLOAD *p;
	if (payload_list == NULL || (spi == NULL && spi_size != 0))
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_PROPOSAL);
	p->Payload.Proposal.Number = number;
	p->Payload.Proposal.ProtocolId = protocol_id;
	p->Payload.Proposal.Spi = MemToBuf(spi, spi_size);
	p->Payload.Proposal.PayloadList = payload_list;

	return p;
}

// Create an SA payload
IKE_PACKET_PAYLOAD *IkeNewSaPayload(LIST *payload_list)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (payload_list == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(IKE_PAYLOAD_SA);
	p->Payload.Sa.PayloadList = payload_list;

	return p;
}

// Create a NAT-OA payload
IKE_PACKET_PAYLOAD *IkeNewNatOaPayload(UCHAR payload_type, IP *ip)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(payload_type);
	Copy(&p->Payload.NatOa.IpAddress, ip, sizeof(IP));
	p->PayloadType = payload_type;

	return p;
}

// Create a data payload
IKE_PACKET_PAYLOAD *IkeNewDataPayload(UCHAR payload_type, void *data, UINT size)
{
	IKE_PACKET_PAYLOAD *p;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	p = IkeNewPayload(payload_type);
	p->Payload.GeneralData.Data = MemToBuf(data, size);

	return p;
}

// Create a new payload
IKE_PACKET_PAYLOAD *IkeNewPayload(UINT payload_type)
{
	IKE_PACKET_PAYLOAD *p;

	p = ZeroMalloc(sizeof(IKE_PACKET_PAYLOAD));

	p->PayloadType = payload_type;

	return p;
}

// Analyse the IKE payload body
IKE_PACKET_PAYLOAD *IkeParsePayload(UINT payload_type, BUF *b)
{
	IKE_PACKET_PAYLOAD *p = NULL;
	bool ok = true;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(IKE_PACKET_PAYLOAD));
	p->PayloadType = payload_type;

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		ok = IkeParseSaPayload(&p->Payload.Sa, b);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		ok = IkeParseProposalPayload(&p->Payload.Proposal, b);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Proposal payload
		ok = IkeParseTransformPayload(&p->Payload.Transform, b);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		ok = IkeParseIdPayload(&p->Payload.Id, b);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
		ok = IkeParseCertPayload(&p->Payload.Cert, b);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
		ok = IkeParseCertRequestPayload(&p->Payload.CertRequest, b);
		break;

	case IKE_PAYLOAD_NOTICE:				// Notification Payload
		ok = IkeParseNoticePayload(&p->Payload.Notice, b);
		break;

	case IKE_PAYLOAD_DELETE:				// Deletion payload
		ok = IkeParseDeletePayload(&p->Payload.Delete, b);
		break;

	case IKE_PAYLOAD_NAT_OA:
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		ok = IkeParseNatOaPayload(&p->Payload.NatOa, b);
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	default:
		ok = IkeParseDataPayload(&p->Payload.GeneralData, b);
		break;
	}

	if (ok == false)
	{
		Free(p);
		p = NULL;
	}
	else
	{
		p->BitArray = CloneBuf(b);
	}

	return p;
}

// Parse the SA payload
bool IkeParseSaPayload(IKE_PACKET_SA_PAYLOAD *t, BUF *b)
{
	IKE_SA_HEADER *h;
	UCHAR *buf;
	UINT size;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (b->Size < sizeof(IKE_SA_HEADER))
	{
		return false;
	}

	h = (IKE_SA_HEADER *)b->Buf;
	buf = (UCHAR *)b->Buf;
	buf += sizeof(IKE_SA_HEADER);
	size = b->Size - sizeof(IKE_SA_HEADER);

	if (Endian32(h->DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h->DoI));
		return false;
	}

	if (Endian32(h->Situation) != IKE_SA_SITUATION_IDENTITY)
	{
		Debug("ISAKMP: Invalid Situation Value: 0x%x\n", Endian32(h->Situation));
		return false;
	}

	t->PayloadList = IkeParsePayloadList(buf, size, IKE_PAYLOAD_PROPOSAL);

	return true;
}

// Release the SA payload
void IkeFreeSaPayload(IKE_PACKET_SA_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->PayloadList != NULL)
	{
		IkeFreePayloadList(t->PayloadList);
		t->PayloadList = NULL;
	}
}

// Parse the proposal payload
bool IkeParseProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t, BUF *b)
{
	IKE_PROPOSAL_HEADER *h;
	UCHAR *buf;
	UINT size;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (b->Size < sizeof(IKE_PROPOSAL_HEADER))
	{
		return false;
	}

	h = (IKE_PROPOSAL_HEADER *)b->Buf;

	t->Number = h->Number;
	t->ProtocolId = h->ProtocolId;

	buf = (UCHAR *)b->Buf;
	buf += sizeof(IKE_PROPOSAL_HEADER);
	size = b->Size - sizeof(IKE_PROPOSAL_HEADER);

	if (size < (UINT)h->SpiSize)
	{
		return false;
	}

	t->Spi = MemToBuf(buf, h->SpiSize);

	buf += h->SpiSize;
	size -= h->SpiSize;

	t->PayloadList = IkeParsePayloadList(buf, size, IKE_PAYLOAD_TRANSFORM);

	return true;
}

// Release the proposal payload
void IkeFreeProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->Spi != NULL)
	{
		FreeBuf(t->Spi);
		t->Spi = NULL;
	}

	if (t->PayloadList != NULL)
	{
		IkeFreePayloadList(t->PayloadList);
		t->PayloadList = NULL;
	}
}

// Parse the transform payload
bool IkeParseTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t, BUF *b)
{
	IKE_TRANSFORM_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->Number = h.Number;
	t->TransformId = h.TransformId;
	t->ValueList = IkeParseTransformValueList(b);

	return true;
}

// Create a new transform value
IKE_PACKET_TRANSFORM_VALUE *IkeNewTransformValue(UCHAR type, UINT value)
{
	IKE_PACKET_TRANSFORM_VALUE *v = ZeroMalloc(sizeof(IKE_PACKET_TRANSFORM_VALUE));

	v->Type = type;
	v->Value = value;

	return v;
}

// Parse the transform value list
LIST *IkeParseTransformValueList(BUF *b)
{
	LIST *o;
	bool ok = true;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	while (b->Current < b->Size)
	{
		UCHAR af_bit, type;
		USHORT size;
		UINT value = 0;
		IKE_PACKET_TRANSFORM_VALUE *v;

		if (ReadBuf(b, &af_bit, sizeof(af_bit)) != sizeof(af_bit))
		{
			ok = false;
			break;
		}

		if (ReadBuf(b, &type, sizeof(type)) != sizeof(type))
		{
			ok = false;
			break;
		}

		if (ReadBuf(b, &size, sizeof(size)) != sizeof(size))
		{
			ok = false;
		}

		size = Endian16(size);

		if (af_bit == 0)
		{
			UCHAR *tmp = Malloc(size);

			if (ReadBuf(b, tmp, size) != size)
			{
				ok = false;
				Free(tmp);
				break;
			}

			switch (size)
			{
			case sizeof(UINT):
				value = READ_UINT(tmp);
				break;

			case sizeof(USHORT):
				value = READ_USHORT(tmp);
				break;

			case sizeof(UCHAR):
				value = *((UCHAR *)tmp);
				break;
			}

			Free(tmp);
		}
		else
		{
			value = (UINT)size;
		}

		v = ZeroMalloc(sizeof(IKE_PACKET_TRANSFORM_VALUE));
		v->Type = type;
		v->Value = value;

		Add(o, v);
	}

	if (ok == false)
	{
		IkeFreeTransformValueList(o);
		o = NULL;
	}

	return o;
}

// Release the transform value list
void IkeFreeTransformValueList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_TRANSFORM_VALUE *v = LIST_DATA(o, i);

		Free(v);
	}

	ReleaseList(o);
}

// Release the transform payload
void IkeFreeTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->ValueList != NULL)
	{
		IkeFreeTransformValueList(t->ValueList);
		t->ValueList = NULL;
	}
}

// Parse the ID payload
bool IkeParseIdPayload(IKE_PACKET_ID_PAYLOAD *t, BUF *b)
{
	IKE_ID_HEADER h;
	IP ip;
	IP subnet;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->Type = h.IdType;
	t->ProtocolId = h.ProtocolId;
	t->Port = Endian16(h.Port);
	t->IdData = ReadRemainBuf(b);
	if (t->IdData == NULL)
	{
		return false;
	}

	Zero(&ip, sizeof(ip));
	Zero(&subnet, sizeof(subnet));

	// Convert to string
	Zero(t->StrData, sizeof(t->StrData));
	switch (t->Type)
	{
	case IKE_ID_FQDN:
	case IKE_ID_USER_FQDN:
	case IKE_ID_KEY_ID:
		Copy(t->StrData, t->IdData->Buf, MIN(t->IdData->Size, sizeof(t->StrData) - 1));
		break;

	case IKE_ID_IPV4_ADDR:
		if (t->IdData->Size == 4)
		{
			Copy(ip.addr, t->IdData->Buf, 4);

			IPToStr(t->StrData, sizeof(t->StrData), &ip);
		}
		break;

	case IKE_ID_IPV6_ADDR:
		if (t->IdData->Size == 16)
		{
			SetIP6(&ip, t->IdData->Buf);

			IPToStr(t->StrData, sizeof(t->StrData), &ip);
		}
		break;

	case IKE_ID_IPV4_ADDR_SUBNET:
		if (t->IdData->Size == 8)
		{
			char ipstr[MAX_SIZE];
			char subnetstr[MAX_SIZE];
			Copy(ip.addr, t->IdData->Buf, 4);
			Copy(subnet.addr, ((UCHAR *)t->IdData->Buf) + 4, 4);

			IPToStr(ipstr, sizeof(ipstr), &ip);
			MaskToStr(subnetstr, sizeof(subnetstr), &subnet);

			Format(t->StrData, sizeof(t->StrData), "%s/%s", ipstr, subnetstr);
		}
		break;

	case IKE_ID_IPV6_ADDR_SUBNET:
		if (t->IdData->Size == 32)
		{
			char ipstr[MAX_SIZE];
			char subnetstr[MAX_SIZE];
			SetIP6(&ip, t->IdData->Buf);
			SetIP6(&subnet, ((UCHAR *)t->IdData->Buf) + 16);

			IPToStr(ipstr, sizeof(ipstr), &ip);
			MaskToStr(subnetstr, sizeof(subnetstr), &subnet);

			Format(t->StrData, sizeof(t->StrData), "%s/%s", ipstr, subnetstr);
		}
		break;
	}

	return true;
}

// Release the ID payload
void IkeFreeIdPayload(IKE_PACKET_ID_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->IdData != NULL)
	{
		FreeBuf(t->IdData);
		t->IdData = NULL;
	}
}

// Parse the certificate payload
bool IkeParseCertPayload(IKE_PACKET_CERT_PAYLOAD *t, BUF *b)
{
	IKE_CERT_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->CertType = h.CertType;
	t->CertData = ReadRemainBuf(b);
	if (t->CertData == NULL)
	{
		return false;
	}

	return true;
}

// Release the certificate payload
void IkeFreeCertPayload(IKE_PACKET_CERT_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->CertData != NULL)
	{
		FreeBuf(t->CertData);
		t->CertData = NULL;
	}
}

// Parse the certificate request payload
bool IkeParseCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t, BUF *b)
{
	IKE_CERT_REQUEST_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	t->CertType = h.CertType;
	t->Data = ReadRemainBuf(b);
	if (t->Data == NULL)
	{
		return false;
	}

	return true;
}

// Release the certificate request payload
void IkeFreeCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->Data != NULL)
	{
		FreeBuf(t->Data);
		t->Data = NULL;
	}
}

// Parse the notification payload
bool IkeParseNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t, BUF *b)
{
	IKE_NOTICE_HEADER h;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (Endian32(h.DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h.DoI));
		return false;
	}

	t->MessageType = Endian16(h.MessageType);
	t->ProtocolId = h.ProtocolId;
	t->Spi = ReadBufFromBuf(b, h.SpiSize);
	if (t->Spi == NULL)
	{
		return false;
	}
	t->MessageData = ReadRemainBuf(b);

	return true;
}

// Release the notification payload
void IkeFreeNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->MessageData != NULL)
	{
		FreeBuf(t->MessageData);
		t->MessageData = NULL;
	}

	if (t->Spi != NULL)
	{
		FreeBuf(t->Spi);
		t->Spi = NULL;
	}
}

// Parse the NAT-OA payload
bool IkeParseNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t, BUF *b)
{
	IKE_NAT_OA_HEADER h;
	UCHAR ip4[4];
	UCHAR ip6[16];
	IP ip;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	Zero(&ip, sizeof(ip));

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (h.IdType != IKE_ID_IPV4_ADDR && h.IdType != IKE_ID_IPV6_ADDR)
	{
		return false;
	}

	switch (h.IdType)
	{
	case IKE_ID_IPV4_ADDR:	// IPv4
		if (ReadBuf(b, ip4, sizeof(ip4)) != sizeof(ip4))
		{
			return false;
		}

		SetIP(&ip, ip4[0], ip4[1], ip4[2], ip4[3]);

		break;

	case IKE_ID_IPV6_ADDR:	// IPv6
		if (ReadBuf(b, ip6, sizeof(ip6)) != sizeof(ip6))
		{
			return false;
		}

		SetIP6(&ip, ip6);

		break;

	default:
		return false;
	}

	Copy(&t->IpAddress, &ip, sizeof(IP));

	return true;
}

// Parse the deletion payload
bool IkeParseDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t, BUF *b)
{
	IKE_DELETE_HEADER h;
	UINT num_spi;
	UINT spi_size;
	UINT i;
	bool ok = true;
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &h, sizeof(h)) != sizeof(h))
	{
		return false;
	}

	if (Endian32(h.DoI) != IKE_SA_DOI_IPSEC)
	{
		Debug("ISAKMP: Invalid DoI Value: 0x%x\n", Endian32(h.DoI));
		return false;
	}

	t->ProtocolId = h.ProtocolId;
	t->SpiList = NewListFast(NULL);
	num_spi = Endian16(h.NumSpis);
	spi_size = h.SpiSize;

	for (i = 0;i < num_spi;i++)
	{
		BUF *spi = ReadBufFromBuf(b, spi_size);

		if (spi == NULL)
		{
			ok = false;
			break;
		}

		Add(t->SpiList, spi);
	}

	if (ok == false)
	{
		IkeFreeDeletePayload(t);
		return false;
	}

	return true;
}

// Release the deletion payload
void IkeFreeDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->SpiList != NULL)
	{
		for (i = 0;i < LIST_NUM(t->SpiList);i++)
		{
			BUF *spi = LIST_DATA(t->SpiList, i);

			FreeBuf(spi);
		}

		ReleaseList(t->SpiList);

		t->SpiList = NULL;
	}
}

// Check whether the hash matches
bool IkeCompareHash(IKE_PACKET_PAYLOAD *hash_payload, void *hash_data, UINT hash_size)
{
	//char tmp1[MAX_SIZE], tmp2[MAX_SIZE];
	// Validate arguments
	if (hash_payload == NULL || hash_data == NULL || hash_size == 0)
	{
		return false;
	}

	if (hash_payload->PayloadType != IKE_PAYLOAD_HASH)
	{
		return false;
	}

	if (hash_payload->Payload.Hash.Data == NULL)
	{
		return false;
	}

	if (hash_payload->Payload.Hash.Data->Size != hash_size)
	{
		return false;
	}

	//BinToStrEx(tmp1, sizeof(tmp1), hash_payload->Payload.Hash.Data->Buf, hash_size);
	//BinToStrEx(tmp2, sizeof(tmp2), hash_data, hash_size);

	//Debug("IkeCompareHash\n  1: %s\n  2: %s\n", tmp1, tmp2);

	if (Cmp(hash_payload->Payload.Hash.Data->Buf, hash_data, hash_size) != 0)
	{
		return false;
	}

	return true;
}

// Parse the data payload
bool IkeParseDataPayload(IKE_PACKET_DATA_PAYLOAD *t, BUF *b)
{
	// Validate arguments
	if (t == NULL || b == NULL)
	{
		return false;
	}

	t->Data = MemToBuf(b->Buf, b->Size);

	return true;
}

// Release the data payload
void IkeFreeDataPayload(IKE_PACKET_DATA_PAYLOAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeBuf(t->Data);
}

// Release the IKE payload body
void IkeFreePayload(IKE_PACKET_PAYLOAD *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	switch (p->PayloadType)
	{
	case IKE_PAYLOAD_SA:					// SA payload
		IkeFreeSaPayload(&p->Payload.Sa);
		break;

	case IKE_PAYLOAD_PROPOSAL:			// Proposal payload
		IkeFreeProposalPayload(&p->Payload.Proposal);
		break;

	case IKE_PAYLOAD_TRANSFORM:			// Proposal payload
		IkeFreeTransformPayload(&p->Payload.Transform);
		break;

	case IKE_PAYLOAD_ID:					// ID payload
		IkeFreeIdPayload(&p->Payload.Id);
		break;

	case IKE_PAYLOAD_CERT:				// Certificate payload
		IkeFreeCertPayload(&p->Payload.Cert);
		break;

	case IKE_PAYLOAD_CERT_REQUEST:		// Certificate request payload
		IkeFreeCertRequestPayload(&p->Payload.CertRequest);
		break;

	case IKE_PAYLOAD_NOTICE:				// Notification Payload
		IkeFreeNoticePayload(&p->Payload.Notice);
		break;

	case IKE_PAYLOAD_DELETE:				// Deletion payload
		IkeFreeDeletePayload(&p->Payload.Delete);
		break;

	case IKE_PAYLOAD_NAT_OA:				// NAT-OD payload
	case IKE_PAYLOAD_NAT_OA_DRAFT:
	case IKE_PAYLOAD_NAT_OA_DRAFT_2:
		// Do Nothing
		break;

	case IKE_PAYLOAD_KEY_EXCHANGE:		// Key exchange payload
	case IKE_PAYLOAD_HASH:				// Hash payload
	case IKE_PAYLOAD_SIGN:				// Signature payload
	case IKE_PAYLOAD_RAND:				// Random number payload
	case IKE_PAYLOAD_VENDOR_ID:			// Vendor ID payload
	case IKE_PAYLOAD_NAT_D:				// NAT-D payload
	case IKE_PAYLOAD_NAT_D_DRAFT:		// NAT-D payload (draft)
	default:
		IkeFreeDataPayload(&p->Payload.GeneralData);
		break;
	}

	if (p->BitArray != NULL)
	{
		FreeBuf(p->BitArray);
	}

	Free(p);
}

// Analyse the IKE payload list
LIST *IkeParsePayloadList(void *data, UINT size, UCHAR first_payload)
{
	return IkeParsePayloadListEx(data, size, first_payload, NULL);
}
LIST *IkeParsePayloadListEx(void *data, UINT size, UCHAR first_payload, UINT *total_read_size)
{
	LIST *o;
	BUF *b;
	UCHAR payload_type = first_payload;
	UINT total = 0;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);
	b = MemToBuf(data, size);

	while (payload_type != IKE_PAYLOAD_NONE)
	{
		// Read the common header
		IKE_COMMON_HEADER header;
		USHORT payload_size;
		BUF *payload_data;
		IKE_PACKET_PAYLOAD *pay;

		if (ReadBuf(b, &header, sizeof(header)) != sizeof(header))
		{
			Debug("ISAKMP: Broken Packet (Invalid Payload Size)\n");

LABEL_ERROR:
			// Header reading failure
			IkeFreePayloadList(o);
			o = NULL;

			break;
		}

		total += sizeof(header);

		// Get the payload size
		payload_size = Endian16(header.PayloadSize);

		if (payload_size < sizeof(header))
		{
			Debug("ISAKMP: Broken Packet (Invalid Payload Size)\n");
			goto LABEL_ERROR;
		}

		payload_size -= sizeof(header);

		// Read the payload data
		payload_data = ReadBufFromBuf(b, payload_size);
		if (payload_data == NULL)
		{
			// Data read failure
			Debug("ISAKMP: Broken Packet (Invalid Payload Data)\n");
			goto LABEL_ERROR;
		}

		total += payload_size;

		// Analyse the payload body
		if (IKE_IS_SUPPORTED_PAYLOAD_TYPE(payload_type))
		{
			// Supported payload type
			pay = IkeParsePayload(payload_type, payload_data);

			if (pay == NULL)
			{
				FreeBuf(payload_data);
				Debug("ISAKMP: Broken Packet (Payload Data Parse Failed)\n");
				goto LABEL_ERROR;
			}

			Add(o, pay);
		}
		else
		{
			// Unsupported payload type
			Debug("ISAKMP: Ignored Payload Type: %u\n", payload_type);
			pay = IkeParsePayload(payload_type, payload_data);

			if (pay == NULL)
			{
				FreeBuf(payload_data);
				Debug("ISAKMP: Broken Packet (Payload Data Parse Failed)\n");
				goto LABEL_ERROR;
			}

			Add(o, pay);
		}

		payload_type = header.NextPayload;

		FreeBuf(payload_data);
	}

	FreeBuf(b);

	if (total_read_size != NULL)
	{
		*total_read_size = total;
	}

	return o;
}

// Release the IKE payload list
void IkeFreePayloadList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *p = LIST_DATA(o, i);

		IkeFreePayload(p);
	}

	ReleaseList(o);
}

// Build an IKE packet
BUF *IkeBuild(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam)
{
	return IkeBuildEx(p, cparam, false);
}
BUF *IkeBuildEx(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam, bool use_original_decrypted)
{
	IKE_HEADER h;
	BUF *msg_buf;
	BUF *ret;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	if (p->PayloadList == NULL)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));
	h.InitiatorCookie = Endian64(p->InitiatorCookie);
	h.ResponderCookie = Endian64(p->ResponderCookie);
	h.NextPayload = IkeGetFirstPayloadType(p->PayloadList);
	h.Version = IKE_VERSION;
	h.ExchangeType = p->ExchangeType;
	h.Flag = (p->FlagEncrypted ? IKE_HEADER_FLAG_ENCRYPTED : 0) |
		(p->FlagCommit ? IKE_HEADER_FLAG_COMMIT : 0) |
		(p->FlagAuthOnly ? IKE_HEADER_FLAG_AUTH_ONLY : 0);
	h.MessageId = Endian32(p->MessageId);

	if (p->DecryptedPayload != NULL && use_original_decrypted)
	{
		msg_buf = CloneBuf(p->DecryptedPayload);
	}
	else
	{
		msg_buf = IkeBuildPayloadList(p->PayloadList);
	}

	if (p->DecryptedPayload != NULL)
	{
		FreeBuf(p->DecryptedPayload);
	}

	p->DecryptedPayload = CloneBuf(msg_buf);

	if (p->FlagEncrypted)
	{
		BUF *b;
		// Encryption
		b = IkeEncryptWithPadding(msg_buf->Buf, msg_buf->Size, cparam);

		if (b == NULL)
		{
			Debug("ISAKMP: Packet Encrypt Failed\n");
			FreeBuf(msg_buf);
			return NULL;
		}

		FreeBuf(msg_buf);

		msg_buf = b;
	}

	h.MessageSize = Endian32(msg_buf->Size + sizeof(h));

	ret = NewBuf();
	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, msg_buf);

	FreeBuf(msg_buf);

	SeekBuf(ret, 0, 0);

	return ret;
}

// Analyse the IKE packet
IKE_PACKET *IkeParseEx(void *data, UINT size, IKE_CRYPTO_PARAM *cparam, bool header_only)
{
	IKE_PACKET *p = NULL;
	BUF *b;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	b = MemToBuf(data, size);

	if (b->Size < sizeof(IKE_HEADER))
	{
		Debug("ISAKMP: Invalid Packet Size\n");
	}
	else
	{
		// Header analysis
		IKE_HEADER *h = (IKE_HEADER *)b->Buf;

		p = ZeroMalloc(sizeof(IKE_PACKET));

		p->MessageSize = Endian32(h->MessageSize);
		p->InitiatorCookie = Endian64(h->InitiatorCookie);
		p->ResponderCookie = Endian64(h->ResponderCookie);
		p->ExchangeType = h->ExchangeType;
		p->FlagEncrypted = (h->Flag & IKE_HEADER_FLAG_ENCRYPTED) ? true : false;
		p->FlagCommit = (h->Flag & IKE_HEADER_FLAG_COMMIT) ? true : false;
		p->FlagAuthOnly = (h->Flag & IKE_HEADER_FLAG_AUTH_ONLY) ? true : false;
		p->MessageId = Endian32(h->MessageId);

		if (b->Size < Endian32(h->MessageSize) ||
			Endian32(h->MessageSize) < sizeof(IKE_HEADER))
		{
			Debug("ISAKMP: Invalid Packet Size\n");

			IkeFree(p);
			p = NULL;
		}
		else
		{
			if (header_only == false)
			{
				bool ok = false;
				UCHAR *payload_data;
				UINT payload_size;
				BUF *buf = NULL;

				payload_data = ((UCHAR *)h) + sizeof(IKE_HEADER);
				payload_size = Endian32(h->MessageSize) - sizeof(IKE_HEADER);

				// Decrypt if it is encrypted
				if (p->FlagEncrypted)
				{
					buf = IkeDecrypt(payload_data, payload_size, cparam);

					if (buf != NULL)
					{
						ok = true;

						payload_data = buf->Buf;
						payload_size = buf->Size;

						p->DecryptedPayload = CloneBuf(buf);
					}
				}
				else
				{
					ok = true;
				}

				if (ok == false)
				{
					Debug("ISAKMP: Decrypt Failed\n");

					IkeFree(p);
					p = NULL;
				}
				else
				{
					UINT total_read_size;

					// Payload analysis
					p->PayloadList = IkeParsePayloadListEx(payload_data,
						payload_size,
						h->NextPayload,
						&total_read_size);

					if (p->DecryptedPayload != NULL)
					{
						p->DecryptedPayload->Size = MIN(p->DecryptedPayload->Size, total_read_size);
					}
					else
					{
						p->DecryptedPayload = MemToBuf(payload_data, payload_size);
					}
				}

				if (buf != NULL)
				{
					FreeBuf(buf);
				}
			}
		}
	}

	FreeBuf(b);

	return p;
}
IKE_PACKET *IkeParseHeader(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	return IkeParseEx(data, size, cparam, true);
}
IKE_PACKET *IkeParse(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	return IkeParseEx(data, size, cparam, false);
}

// Send packet for debugging by UDP (For debugging with Ethereal)
void IkeDebugUdpSendRawPacket(IKE_PACKET *p)
{
	BUF *b;
	IP ip;
	SOCK *udp;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->FlagEncrypted = false;

	b = NULL;

	if (b == NULL)
	{
		b = IkeBuildEx(p, NULL, true);
	}

	if (b == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));
	SetIP(&ip, 1, 2, 3, 4);

	udp = NewUDP(0);

	SendTo(udp, &ip, 500, b->Buf, b->Size);

	ReleaseSock(udp);
	FreeBuf(b);
}

// Output the payload list
void IkeDebugPrintPayloads(LIST *o, UINT depth)
{
	UINT i;
	char space[MAX_SIZE];
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	MakeCharArray2(space, ' ', depth * 2);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_PACKET_PAYLOAD *payload = LIST_DATA(o, i);

		Debug("%s%u: Type = %u, Size = %u\n", space, i, payload->PayloadType, payload->BitArray->Size);

		switch (payload->PayloadType)
		{
		case IKE_PAYLOAD_SA:
			IkeDebugPrintPayloads(payload->Payload.Sa.PayloadList, depth + 1);
			break;

		case IKE_PAYLOAD_PROPOSAL:
			IkeDebugPrintPayloads(payload->Payload.Proposal.PayloadList, depth + 1);
			break;
		}
	}
}

// Encryption (also with padding)
BUF *IkeEncryptWithPadding(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	UINT total_size;
	UINT i;
	UCHAR n = 0;
	UCHAR *tmp;
	BUF *ret;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	total_size = ((size / cparam->Key->Crypto->BlockSize) + ((size % cparam->Key->Crypto->BlockSize) == 0 ? 0 : 1))
		* cparam->Key->Crypto->BlockSize;
	if (total_size == 0)
	{
		total_size = cparam->Key->Crypto->BlockSize;
	}

	if (total_size > sizeof(tmp1600))
	{
		tmp = Malloc(total_size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	Copy(tmp, data, size);

	for (i = size;i < total_size;i++)
	{
		tmp[i] = ++n;
	}

	ret = IkeEncrypt(tmp, total_size, cparam);

	if (no_free == false)
	{
		Free(tmp);
	}

	return ret;
}

// Encryption
BUF *IkeEncrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	void *tmp;
	BUF *b;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	if ((size % cparam->Key->Crypto->BlockSize) != 0)
	{
		// Not an integral multiple of block size
		return NULL;
	}

	if (size > sizeof(tmp1600))
	{
		tmp = Malloc(size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	IkeCryptoEncrypt(cparam->Key, tmp, data, size, cparam->Iv);

	if (size >= cparam->Key->Crypto->BlockSize)
	{
		Copy(cparam->NextIv, ((UCHAR *)tmp) + (size - cparam->Key->Crypto->BlockSize), cparam->Key->Crypto->BlockSize);
	}
	else
	{
		Zero(cparam->NextIv, cparam->Key->Crypto->BlockSize);
	}

	b = MemToBuf(tmp, size);

	if (no_free == false)
	{
		Free(tmp);
	}

	return b;
}

// Decryption
BUF *IkeDecrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam)
{
	void *tmp;
	BUF *b;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (data == NULL || cparam == NULL)
	{
		return NULL;
	}

	if ((size % cparam->Key->Crypto->BlockSize) != 0)
	{
		// Not an integral multiple of block size
		return NULL;
	}

	if (size > sizeof(tmp1600))
	{
		tmp = Malloc(size);
	}
	else
	{
		tmp = tmp1600;
		no_free = true;
	}

	IkeCryptoDecrypt(cparam->Key, tmp, data, size, cparam->Iv);

	if (size >= cparam->Key->Crypto->BlockSize)
	{
		Copy(cparam->NextIv, ((UCHAR *)data) + (size - cparam->Key->Crypto->BlockSize), cparam->Key->Crypto->BlockSize);
	}
	else
	{
		Zero(cparam->NextIv, cparam->Key->Crypto->BlockSize);
	}

	b = MemToBuf(tmp, size);

	if (no_free == false)
	{
		Free(tmp);
	}

	return b;
}

// Release the IKE packet
void IkeFree(IKE_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->PayloadList != NULL)
	{
		IkeFreePayloadList(p->PayloadList);
	}

	if (p->DecryptedPayload != NULL)
	{
		FreeBuf(p->DecryptedPayload);
	}

	Free(p);
}

// Create an IKE packet
IKE_PACKET *IkeNew(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type,
				   bool encrypted, bool commit, bool auth_only, UINT msg_id,
				   LIST *payload_list)
{
	IKE_PACKET *p = ZeroMalloc(sizeof(IKE_PACKET));

	p->InitiatorCookie = init_cookie;
	p->ResponderCookie = resp_cookie;
	p->ExchangeType = exchange_type;
	p->FlagEncrypted = encrypted;
	p->FlagCommit = commit;
	p->FlagAuthOnly = auth_only;
	p->MessageId = msg_id;
	p->PayloadList = payload_list;

	return p;
}

// Create a new SPI value
UINT IkeNewSpi()
{
	while (true)
	{
		UINT i = Rand32();

		if (i >= 4096)
		{
			return i;
		}
	}
}


// Create an encryption engine for IKE
IKE_ENGINE *NewIkeEngine()
{
	IKE_ENGINE *e = ZeroMalloc(sizeof(IKE_ENGINE));
	IKE_CRYPTO *des, *des3, *aes;
	IKE_HASH *sha1, *md5;
	IKE_DH *dh1, *dh2, *dh5;
	UINT des_key_sizes[] =
	{
		8,
	};
	UINT des3_key_sizes[] =
	{
		24,
	};
	UINT aes_key_sizes[] =
	{
		16, 24, 32,
	};

	e->CryptosList = NewListFast(NULL);
	e->HashesList = NewListFast(NULL);
	e->DhsList = NewListFast(NULL);

	//// Encryption algorithm
	// DES
	des = NewIkeCrypto(e, IKE_CRYPTO_DES_ID, IKE_CRYPTO_DES_STRING,
		des_key_sizes, sizeof(des_key_sizes) / sizeof(UINT), 8);

	// 3DES
	des3 = NewIkeCrypto(e, IKE_CRYPTO_3DES_ID, IKE_CRYPTO_3DES_STRING,
		des3_key_sizes, sizeof(des3_key_sizes) / sizeof(UINT), 8);

	// AES
	aes = NewIkeCrypto(e, IKE_CRYPTO_AES_ID, IKE_CRYPTO_AES_STRING,
		aes_key_sizes, sizeof(aes_key_sizes) / sizeof(UINT), 16);

	//// Hash algorithm
	// SHA-1
	sha1 = NewIkeHash(e, IKE_HASH_SHA1_ID, IKE_HASH_SHA1_STRING, 20);

	// MD5
	md5 = NewIkeHash(e, IKE_HASH_MD5_ID, IKE_HASH_MD5_STRING, 16);

	//// DH algorithm
	dh1 = NewIkeDh(e, IKE_DH_1_ID, IKE_DH_1_STRING, 96);
	dh2 = NewIkeDh(e, IKE_DH_2_ID, IKE_DH_2_STRING, 128);
	dh5 = NewIkeDh(e, IKE_DH_5_ID, IKE_DH_5_STRING, 192);

	// Define the IKE algorithm
	e->IkeCryptos[IKE_P1_CRYPTO_DES_CBC] = des;
	e->IkeCryptos[IKE_P1_CRYPTO_3DES_CBC] = des3;
	e->IkeCryptos[IKE_P1_CRYPTO_AES_CBC] = aes;
	e->IkeHashes[IKE_P1_HASH_MD5] = md5;
	e->IkeHashes[IKE_P1_HASH_SHA1] = sha1;

	// Definition of ESP algorithm
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_DES] = des;
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_3DES] = des3;
	e->EspCryptos[IKE_TRANSFORM_ID_P2_ESP_AES] = aes;
	e->EspHashes[IKE_P2_HMAC_MD5_96] = md5;
	e->EspHashes[IKE_P2_HMAC_SHA1_96] = sha1;

	// Definition of the DH algorithm
	e->IkeDhs[IKE_P1_DH_GROUP_768_MODP] = e->EspDhs[IKE_P2_DH_GROUP_768_MODP] = dh1;
	e->IkeDhs[IKE_P1_DH_GROUP_1024_MODP] = e->EspDhs[IKE_P2_DH_GROUP_1024_MODP] = dh2;
	e->IkeDhs[IKE_P1_DH_GROUP_1536_MODP] = e->EspDhs[IKE_P2_DH_GROUP_1536_MODP] = dh5;

	return e;
}

// Release the encryption engine for IKE
void FreeIkeEngine(IKE_ENGINE *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(e->CryptosList);i++)
	{
		IKE_CRYPTO *c = LIST_DATA(e->CryptosList, i);

		FreeIkeCrypto(c);
	}

	ReleaseList(e->CryptosList);

	for (i = 0;i < LIST_NUM(e->HashesList);i++)
	{
		IKE_HASH *h = LIST_DATA(e->HashesList, i);

		FreeIkeHash(h);
	}
	ReleaseList(e->HashesList);

	for (i = 0;i < LIST_NUM(e->DhsList);i++)
	{
		IKE_DH *d = LIST_DATA(e->DhsList, i);

		FreeIkeDh(d);
	}
	ReleaseList(e->DhsList);

	Free(e);
}

// Definition of a new DH algorithm for IKE
IKE_DH *NewIkeDh(IKE_ENGINE *e, UINT dh_id, char *name, UINT key_size)
{
	IKE_DH *d;
	// Validate arguments
	if (e == NULL || name == NULL || key_size == 0)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(IKE_DH));

	d->DhId = dh_id;
	d->Name = name;
	d->KeySize = key_size;

	Add(e->DhsList, d);

	return d;
}

// Definition of a new encryption algorithm for IKE
IKE_CRYPTO *NewIkeCrypto(IKE_ENGINE *e, UINT crypto_id, char *name, UINT *key_sizes, UINT num_key_sizes, UINT block_size)
{
	IKE_CRYPTO *c;
	UINT i;
	// Validate arguments
	if (e == NULL || name == NULL || key_sizes == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(IKE_CRYPTO));

	c->CryptoId = crypto_id;
	c->Name = name;

	for (i = 0;i < MIN(num_key_sizes, 16);i++)
	{
		c->KeySizes[i] = key_sizes[i];
	}

	if (num_key_sizes >= 2)
	{
		c->VariableKeySize = true;
	}

	c->BlockSize = block_size;

	Add(e->CryptosList, c);

	return c;
}

// Release the definition of Encryption algorithm for IKE
void FreeIkeCrypto(IKE_CRYPTO *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Free(c);
}

// Release the definition of IKE hash algorithm
void FreeIkeHash(IKE_HASH *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	Free(h);
}

// Release the definition of the DH algorithm for IKE
void FreeIkeDh(IKE_DH *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Free(d);
}

// Definition of a new hash algorithm for IKE
IKE_HASH *NewIkeHash(IKE_ENGINE *e, UINT hash_id, char *name, UINT size)
{
	IKE_HASH *h;
	// Validate arguments
	if (e == NULL || name == NULL || size == 0)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(IKE_HASH));

	h->HashId = hash_id;
	h->Name = name;
	h->HashSize = size;

	Add(e->HashesList, h);

	return h;
}

// Get the encryption algorithm that is used in IKE
IKE_CRYPTO *GetIkeCrypto(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspCryptos[i];
	}
	else
	{
		return e->IkeCryptos[i];
	}
}

// Get the hash algorithm used in the IKE
IKE_HASH *GetIkeHash(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspHashes[i];
	}
	else
	{
		return e->IkeHashes[i];
	}
}

// Get the DH algorithm used in the IKE
IKE_DH *GetIkeDh(IKE_ENGINE *e, bool for_esp, UINT i)
{
	// Validate arguments
	if (e == NULL || i == 0 || i >= MAX_IKE_ENGINE_ELEMENTS)
	{
		return NULL;
	}

	if (for_esp)
	{
		return e->EspDhs[i];
	}
	else
	{
		return e->IkeDhs[i];
	}
}

// Perform encryption
void IkeCryptoEncrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec)
{
	// Validate arguments
	if (k == NULL || dst == NULL || src == NULL || size == 0 || ivec == NULL)
	{
		Zero(dst, size);
		return;
	}

	if ((size % k->Crypto->BlockSize) != 0)
	{
		Zero(dst, size);
		return;
	}

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:		// DES
		DesEncrypt(dst, src, size, k->DesKey1, ivec);
		break;

	case IKE_CRYPTO_3DES_ID:	// 3DES
		Des3Encrypt2(dst, src, size, k->DesKey1, k->DesKey2, k->DesKey3, ivec);
		break;

	case IKE_CRYPTO_AES_ID:		// AES
		AesEncrypt(dst, src, size, k->AesKey, ivec);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Perform decryption
void IkeCryptoDecrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec)
{
	// Validate arguments
	if (k == NULL || dst == NULL || src == NULL || size == 0 || ivec == NULL)
	{
		Zero(dst, size);
		return;
	}

	if ((size % k->Crypto->BlockSize) != 0)
	{
		Zero(dst, size);
		return;
	}

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:		// DES
		DesDecrypt(dst, src, size, k->DesKey1, ivec);
		break;

	case IKE_CRYPTO_3DES_ID:	// 3DES
		Des3Decrypt2(dst, src, size, k->DesKey1, k->DesKey2, k->DesKey3, ivec);
		break;

	case IKE_CRYPTO_AES_ID:		// AES
		AesDecrypt(dst, src, size, k->AesKey, ivec);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Calculate a hash
void IkeHash(IKE_HASH *h, void *dst, void *src, UINT size)
{
	// Validate arguments
	if (h == NULL || dst == NULL || (size != 0 && src == NULL))
	{
		Zero(dst, size);
		return;
	}

	switch (h->HashId)
	{
	case IKE_HASH_MD5_ID:
		// MD5
		Md5(dst, src, size);
		break;

	case IKE_HASH_SHA1_ID:
		// SHA-1
		Sha1(dst, src, size);
		break;

	default:
		// Unknown
		Zero(dst, size);
		break;
	}
}

// Calculation of HMAC
void IkeHMac(IKE_HASH *h, void *dst, void *key, UINT key_size, void *data, UINT data_size)
{
	UCHAR k[HMAC_BLOCK_SIZE];
	UCHAR *data1;
	UCHAR hash1[IKE_MAX_HASH_SIZE];
	UINT data1_size;
	UCHAR data2[IKE_MAX_HASH_SIZE + HMAC_BLOCK_SIZE];
	UINT data2_size;
	UCHAR tmp1600[1600];
	bool no_free = false;
	UINT i;
	// Validate arguments
	if (h == NULL || dst == NULL || (key == NULL && key_size != 0) || (data == NULL && data_size != 0))
	{
		return;
	}

	if (h->HashId == IKE_HASH_SHA1_ID)
	{
		// Use special function (fast) in the case of SHA-1
		HMacSha1(dst, key, key_size, data, data_size);
		return;
	}
	else if (h->HashId == IKE_HASH_MD5_ID)
	{
		// Use the special function (fast) in the case of MD5
		HMacMd5(dst, key, key_size, data, data_size);
		return;
	}

	// Creating a K
	Zero(k, sizeof(k));
	if (key_size <= HMAC_BLOCK_SIZE)
	{
		Copy(k, key, key_size);
	}
	else
	{
		IkeHash(h, k, key, key_size);
	}

	// Generation of data 1
	data1_size = data_size + HMAC_BLOCK_SIZE;

	if (data1_size > sizeof(tmp1600))
	{
		data1 = Malloc(data1_size);
	}
	else
	{
		data1 = tmp1600;
		no_free = true;
	}

	for (i = 0;i < HMAC_BLOCK_SIZE;i++)
	{
		data1[i] = k[i] ^ 0x36;
	}

	Copy(data1 + HMAC_BLOCK_SIZE, data, data_size);

	// Calculate the hash value
	IkeHash(h, hash1, data1, data1_size);

	if (no_free == false)
	{
		Free(data1);
	}

	// Generation of data 2
	data2_size = h->HashSize + HMAC_BLOCK_SIZE;

	for (i = 0;i < HMAC_BLOCK_SIZE;i++)
	{
		data2[i] = k[i] ^ 0x5c;
	}

	Copy(data2 + HMAC_BLOCK_SIZE, hash1, h->HashSize);

	// Calculate the hash value
	IkeHash(h, dst, data2, data2_size);
}
void IkeHMacBuf(IKE_HASH *h, void *dst, BUF *key, BUF *data)
{
	// Validate arguments
	if (h == NULL || dst == NULL || key == NULL || data == NULL)
	{
		return;
	}

	IkeHMac(h, dst, key->Buf, key->Size, data->Buf, data->Size);
}

// Check whether the key size is valid
bool IkeCheckKeySize(IKE_CRYPTO *c, UINT size)
{
	bool ok = false;
	UINT i;
	// Validate arguments
	if (c == NULL || size == 0)
	{
		return false;
	}

	for (i = 0;i < sizeof(c->KeySizes) / sizeof(UINT);i++)
	{
		if (c->KeySizes[i] == size)
		{
			ok = true;
			break;
		}
	}

	return ok;
}

// Create a key
IKE_CRYPTO_KEY *IkeNewKey(IKE_CRYPTO *c, void *data, UINT size)
{
	IKE_CRYPTO_KEY *k;
	// Validate arguments
	if (c == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	if (IkeCheckKeySize(c, size) == false)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(IKE_CRYPTO_KEY));
	k->Crypto = c;
	k->Data = Clone(data, size);
	k->Size = size;

	switch (k->Crypto->CryptoId)
	{
	case IKE_CRYPTO_DES_ID:
		// DES 64bit key
		k->DesKey1 = DesNewKeyValue(data);
		break;

	case IKE_CRYPTO_3DES_ID:
		// 3DES 192bit key
		k->DesKey1 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 0);
		k->DesKey2 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 1);
		k->DesKey3 = DesNewKeyValue(((UCHAR *)data) + DES_KEY_SIZE * 2);
		break;

	case IKE_CRYPTO_AES_ID:
		// AES variable length key
		k->AesKey = AesNewKey(data, size);
		break;
	}

	return k;
}

// Release the key
void IkeFreeKey(IKE_CRYPTO_KEY *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	DesFreeKeyValue(k->DesKey1);
	DesFreeKeyValue(k->DesKey2);
	DesFreeKeyValue(k->DesKey3);

	AesFreeKey(k->AesKey);

	Free(k->Data);

	Free(k);
}

// Create a DH object
DH_CTX *IkeDhNewCtx(IKE_DH *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return NULL;
	}

	switch (d->DhId)
	{
	case IKE_DH_1_ID:
		return DhNewGroup1();

	case IKE_DH_2_ID:
		return DhNewGroup2();

	case IKE_DH_5_ID:
		return DhNewGroup5();
	}

	return NULL;
}

// Release the DH object
void IkeDhFreeCtx(DH_CTX *dh)
{
	// Validate arguments
	if (dh == NULL)
	{
		return;
	}

	DhFree(dh);
}






// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
