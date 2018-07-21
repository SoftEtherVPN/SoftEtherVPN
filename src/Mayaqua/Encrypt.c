// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori, Ph.D.
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


// Encrypt.c
// Encryption and digital certification routine

#include <GlobalConst.h>

#define	ENCRYPT_C

#define	__WINCRYPT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <Mayaqua/Mayaqua.h>

#ifdef _MSC_VER
#include <intrin.h> // For __cpuid()
#else
#include <cpuid.h> // For __get_cpuid()
#endif

LOCK *openssl_lock = NULL;

int ssl_clientcert_index = 0;

LOCK **ssl_lock_obj = NULL;
UINT ssl_lock_num;
static bool openssl_inited = false;

static unsigned char *Internal_SHA0(const unsigned char *d, size_t n, unsigned char *md);

// For the callback function
typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

// Copied from t1_enc.c of OpenSSL
void Enc_tls1_P_hash(const EVP_MD *md, const unsigned char *sec, int sec_len,
				 const unsigned char *seed, int seed_len, unsigned char *out, int olen)
{
	int chunk,n;
	unsigned int j;
	HMAC_CTX *ctx;
	HMAC_CTX *ctx_tmp;
	unsigned char A1[EVP_MAX_MD_SIZE];
	unsigned int A1_len;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = HMAC_CTX_new();
	ctx_tmp = HMAC_CTX_new();
#else
	HMAC_CTX ctx_;
	HMAC_CTX ctx_tmp_;
	ctx = &ctx_;
	ctx_tmp = &ctx_tmp_;
	Zero(ctx, sizeof(HMAC_CTX));
	Zero(ctx_tmp, sizeof(HMAC_CTX));
#endif
	chunk=EVP_MD_size(md);

	HMAC_Init_ex(ctx,sec,sec_len,md, NULL);
	HMAC_Init_ex(ctx_tmp,sec,sec_len,md, NULL);
	HMAC_Update(ctx,seed,seed_len);
	HMAC_Final(ctx,A1,&A1_len);

	n=0;
	for (;;)
	{
		HMAC_Init_ex(ctx,NULL,0,NULL,NULL); /* re-init */
		HMAC_Init_ex(ctx_tmp,NULL,0,NULL,NULL); /* re-init */
		HMAC_Update(ctx,A1,A1_len);
		HMAC_Update(ctx_tmp,A1,A1_len);
		HMAC_Update(ctx,seed,seed_len);

		if (olen > chunk)
		{
			HMAC_Final(ctx,out,&j);
			out+=j;
			olen-=j;
			HMAC_Final(ctx_tmp,A1,&A1_len); /* calc the next A1 value */
		}
		else	/* last one */
		{
			HMAC_Final(ctx,A1,&A1_len);
			memcpy(out,A1,olen);
			break;
		}
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	HMAC_CTX_free(ctx);
	HMAC_CTX_free(ctx_tmp);
#else
	HMAC_CTX_cleanup(ctx);
	HMAC_CTX_cleanup(ctx_tmp);
#endif
	Zero (A1, sizeof(A1));
}

void Enc_tls1_PRF(unsigned char *label, int label_len, const unsigned char *sec,
				  int slen, unsigned char *out1, int olen)
{
	const EVP_MD *md5 = EVP_md5();
	const EVP_MD *sha1 = EVP_sha1();
	int len,i;
	const unsigned char *S1,*S2;
	unsigned char *out2;

	out2 = (unsigned char *) Malloc (olen);

	len=slen/2;
	S1=sec;
	S2= &(sec[len]);
	len+=(slen&1); /* add for odd, make longer */


	Enc_tls1_P_hash(md5 ,S1,len,label,label_len,out1,olen);
	Enc_tls1_P_hash(sha1,S2,len,label,label_len,out2,olen);

	for (i=0; i<olen; i++)
		out1[i]^=out2[i];

	memset (out2, 0, olen);
	Free(out2);
}

// Calculation of HMAC (MD5)
void HMacMd5(void *dst, void *key, UINT key_size, void *data, UINT data_size)
{
	UCHAR k[HMAC_BLOCK_SIZE];
	UCHAR hash1[MD5_SIZE];
	UCHAR data2[HMAC_BLOCK_SIZE];
	MD5_CTX md5_ctx1;
	UCHAR pad1[HMAC_BLOCK_SIZE];
	UINT i;
	// Validate arguments
	if (dst == NULL || (key == NULL && key_size != 0) || (data == NULL && data_size != 0))
	{
		return;
	}

	// Creating a K
	if (key_size <= HMAC_BLOCK_SIZE)
	{
		for (i = 0;i < key_size;i++)
		{
			pad1[i] = ((UCHAR *)key)[i] ^ 0x36;
		}
		for (i = key_size;i < HMAC_BLOCK_SIZE;i++)
		{
			pad1[i] = 0 ^ 0x36;
		}
	}
	else
	{
		Zero(k, sizeof(k));
		Hash(k, key, key_size, false);

		for (i = 0;i < HMAC_BLOCK_SIZE;i++)
		{
			pad1[i] = k[i] ^ 0x36;
		}
	}

	MD5_Init(&md5_ctx1);
	MD5_Update(&md5_ctx1, pad1, sizeof(pad1));
	MD5_Update(&md5_ctx1, data, data_size);
	MD5_Final(hash1, &md5_ctx1);

	// Generation of data 2
	if (key_size <= HMAC_BLOCK_SIZE)
	{
		for (i = 0;i < key_size;i++)
		{
			data2[i] = ((UCHAR *)key)[i] ^ 0x5c;
		}
		for (i = key_size;i < HMAC_BLOCK_SIZE;i++)
		{
			data2[i] = 0 ^ 0x5c;
		}
	}
	else
	{
		for (i = 0;i < HMAC_BLOCK_SIZE;i++)
		{
			data2[i] = k[i] ^ 0x5c;
		}
	}

	MD5_Init(&md5_ctx1);
	MD5_Update(&md5_ctx1, data2, HMAC_BLOCK_SIZE);
	MD5_Update(&md5_ctx1, hash1, MD5_SIZE);
	MD5_Final(dst, &md5_ctx1);
}

// Calculation of HMAC (SHA-1)
void HMacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size)
{
	UCHAR k[HMAC_BLOCK_SIZE];
	UCHAR hash1[SHA1_SIZE];
	UCHAR data2[HMAC_BLOCK_SIZE];
	SHA_CTX sha_ctx1;
	UCHAR pad1[HMAC_BLOCK_SIZE];
	UINT i;
	// Validate arguments
	if (dst == NULL || (key == NULL && key_size != 0) || (data == NULL && data_size != 0))
	{
		return;
	}

	// Creating a K
	if (key_size <= HMAC_BLOCK_SIZE)
	{
		for (i = 0;i < key_size;i++)
		{
			pad1[i] = ((UCHAR *)key)[i] ^ 0x36;
		}
		for (i = key_size;i < HMAC_BLOCK_SIZE;i++)
		{
			pad1[i] = 0 ^ 0x36;
		}
	}
	else
	{
		Zero(k, sizeof(k));
		HashSha1(k, key, key_size);

		for (i = 0;i < HMAC_BLOCK_SIZE;i++)
		{
			pad1[i] = k[i] ^ 0x36;
		}
	}

	SHA1_Init(&sha_ctx1);
	SHA1_Update(&sha_ctx1, pad1, sizeof(pad1));
	SHA1_Update(&sha_ctx1, data, data_size);
	SHA1_Final(hash1, &sha_ctx1);

	// Generation of data 2
	if (key_size <= HMAC_BLOCK_SIZE)
	{
		for (i = 0;i < key_size;i++)
		{
			data2[i] = ((UCHAR *)key)[i] ^ 0x5c;
		}
		for (i = key_size;i < HMAC_BLOCK_SIZE;i++)
		{
			data2[i] = 0 ^ 0x5c;
		}
	}
	else
	{
		for (i = 0;i < HMAC_BLOCK_SIZE;i++)
		{
			data2[i] = k[i] ^ 0x5c;
		}
	}

	SHA1_Init(&sha_ctx1);
	SHA1_Update(&sha_ctx1, data2, HMAC_BLOCK_SIZE);
	SHA1_Update(&sha_ctx1, hash1, SHA1_SIZE);
	SHA1_Final(dst, &sha_ctx1);
}

// Calculate the HMAC
void MdProcess(MD *md, void *dest, void *src, UINT size)
{
	int r;
	// Validate arguments
	if (md == NULL || dest == NULL || (src != NULL && size == 0))
	{
		return;
	}

	HMAC_Init_ex(md->Ctx, NULL, 0, NULL, NULL);
	HMAC_Update(md->Ctx, src, size);

	r = 0;
	HMAC_Final(md->Ctx, dest, &r);
}

// Set the key to the message digest object
void SetMdKey(MD *md, void *key, UINT key_size)
{
	// Validate arguments
	if (md == NULL || (key != NULL && key_size == 0))
	{
		return;
	}

	HMAC_Init_ex(md->Ctx, key, key_size, (const EVP_MD *)md->Md, NULL);
}

// Creating a message digest object
MD *NewMd(char *name)
{
	MD *m;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	m = ZeroMalloc(sizeof(MD));

	StrCpy(m->Name, sizeof(m->Name), name);
	m->Md = (const struct evp_md_st *)EVP_get_digestbyname(name);
	if (m->Md == NULL)
	{
		FreeMd(m);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	m->Ctx = HMAC_CTX_new();
#else
	m->Ctx = ZeroMalloc(sizeof(struct hmac_ctx_st));
	HMAC_CTX_init(m->Ctx);
#endif

	m->Size = EVP_MD_size((const EVP_MD *)m->Md);

	return m;
}

// Release of the message digest object
void FreeMd(MD *md)
{
	// Validate arguments
	if (md == NULL)
	{
		return;
	}

	if (md->Ctx != NULL)
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		HMAC_CTX_free(md->Ctx);
#else
		HMAC_CTX_cleanup(md->Ctx);
		Free(md->Ctx);
#endif
	}

	Free(md);
}

// Creating a cipher object
CIPHER *NewCipher(char *name)
{
	CIPHER *c;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CIPHER));

	StrCpy(c->Name, sizeof(c->Name), name);

	if (StrCmpi(name, "[null-cipher]") == 0 ||
		StrCmpi(name, "NULL") == 0 ||
		IsEmptyStr(name))
	{
		c->IsNullCipher = true;
		return c;
	}

	c->Cipher = EVP_get_cipherbyname(c->Name);
	if (c->Cipher == NULL)
	{
		FreeCipher(c);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	c->Ctx = EVP_CIPHER_CTX_new();
#else
	c->Ctx = ZeroMalloc(sizeof(struct evp_cipher_ctx_st));
	EVP_CIPHER_CTX_init(c->Ctx);
#endif

	c->BlockSize = EVP_CIPHER_block_size(c->Cipher);
	c->KeySize = EVP_CIPHER_key_length(c->Cipher);
	c->IvSize = EVP_CIPHER_iv_length(c->Cipher);

	return c;
}

// Set the key to the cipher object
void SetCipherKey(CIPHER *c, void *key, bool enc)
{
	// Validate arguments
	if (c == NULL || key == NULL)
	{
		return;
	}

	if (c->IsNullCipher == false)
	{
		if (c->Ctx != NULL)
		{
			EVP_CipherInit(c->Ctx, c->Cipher, key, NULL, enc);
		}
	}

	c->Encrypt = enc;
}

// Process encryption / decryption
UINT CipherProcess(CIPHER *c, void *iv, void *dest, void *src, UINT size)
{
	int r = size;
	int r2 = 0;
	if (c != NULL && c->IsNullCipher)
	{
		if (dest != src)
		{
			Copy(dest, src, size);
		}
		return size;
	}
	// Validate arguments
	if (c == NULL || iv == NULL || dest == NULL || src == NULL || size == 0)
	{
		return 0;
	}

	if (EVP_CipherInit(c->Ctx, NULL, NULL, iv, c->Encrypt) == 0)
	{
		return 0;
	}

	if (EVP_CipherUpdate(c->Ctx, dest, &r, src, size) == 0)
	{
		return 0;
	}

	if (EVP_CipherFinal(c->Ctx, ((UCHAR *)dest) + (UINT)r, &r2) == 0)
	{
		return 0;
	}

	return r + r2;
}

// Release of the cipher object
void FreeCipher(CIPHER *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->Ctx != NULL)
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EVP_CIPHER_CTX_free(c->Ctx);
#else
		EVP_CIPHER_CTX_cleanup(c->Ctx);
		Free(c->Ctx);
#endif
	}

	Free(c);
}

// Convert the public key to a buffer
BUF *RsaPublicToBuf(K *k)
{
	BUF *b;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RSA *rsa;
	const BIGNUM *n;
#endif
	// Validate arguments
	if (k == NULL || k->pkey == NULL)
	{
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	rsa = EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
	{
		return NULL;
	}

	RSA_get0_key(rsa, &n, NULL, NULL);
	if (n == NULL)
	{
		return NULL;
	}

	b = BigNumToBuf(n);
#else
	if (k->pkey->pkey.rsa == NULL || k->pkey->pkey.rsa->n == NULL)
	{
		return NULL;
	}

	b = BigNumToBuf(k->pkey->pkey.rsa->n);
#endif

	if (b == NULL)
	{
		return NULL;
	}

	return b;
}

// Get public key size
UINT RsaPublicSize(K *k)
{
	BUF *b;
	UINT ret;

	b = RsaPublicToBuf(k);
	if (b == NULL)
	{
		return 0;
	}

	ret = b->Size;

	FreeBuf(b);

	return ret;
}

// Hash a pointer to a 32-bit
UINT HashPtrToUINT(void *p)
{
	UCHAR hash_data[MD5_SIZE];
	UINT ret;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	Hash(hash_data, &p, sizeof(p), false);

	Copy(&ret, hash_data, sizeof(ret));

	return ret;
}

// Copy of the NAME
NAME *CopyName(NAME *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return NULL;
	}

	return NewName(n->CommonName, n->Organization, n->Unit,
		n->Country, n->State, n->Local);
}

// Convert the binary to the BIGNUM
BIGNUM *BinToBigNum(void *data, UINT size)
{
	BIGNUM *bn;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	bn = BN_new();
	BN_bin2bn(data, size, bn);

	return bn;
}

// Convert a BIGNUM to a buffer
BUF *BigNumToBuf(const BIGNUM *bn)
{
	UINT size;
	UCHAR *tmp;
	BUF *b;
	// Validate arguments
	if (bn == NULL)
	{
		return NULL;
	}

	size = BN_num_bytes(bn);
	tmp = ZeroMalloc(size);
	BN_bn2bin(bn, tmp);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	SeekBuf(b, 0, 0);

	return b;
}

// Initialization of the lock of OpenSSL
void OpenSSL_InitLock()
{
	UINT i;

	// Initialization of the lock object
	ssl_lock_num = CRYPTO_num_locks();
	ssl_lock_obj = Malloc(sizeof(LOCK *) * ssl_lock_num);
	for (i = 0;i < ssl_lock_num;i++)
	{
		ssl_lock_obj[i] = NewLock();
	}

	// Setting the lock function
	CRYPTO_set_locking_callback(OpenSSL_Lock);
	CRYPTO_set_id_callback(OpenSSL_Id);
}

// Release of the lock of OpenSSL
void OpenSSL_FreeLock()
{
	UINT i;

	for (i = 0;i < ssl_lock_num;i++)
	{
		DeleteLock(ssl_lock_obj[i]);
	}
	Free(ssl_lock_obj);
	ssl_lock_obj = NULL;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);
}

// Lock function for OpenSSL
void OpenSSL_Lock(int mode, int n, const char *file, int line)
{
	LOCK *lock = ssl_lock_obj[n];

	if (mode & CRYPTO_LOCK)
	{
		// Lock
		Lock(lock);
	}
	else
	{
		// Unlock
		Unlock(lock);
	}
}

// Return the thread ID
unsigned long OpenSSL_Id(void)
{
	return (unsigned long)ThreadId();
}

// Get the display name of the certificate
void GetPrintNameFromX(wchar_t *str, UINT size, X *x)
{
	// Validate arguments
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetPrintNameFromName(str, size, x->subject_name);
}
void GetPrintNameFromXA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetPrintNameFromX(tmp, sizeof(tmp), x);

	UniToStr(str, size, tmp);
}
void GetAllNameFromXEx(wchar_t *str, UINT size, X *x)
{
	// Validate arguments
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetAllNameFromNameEx(str, size, x->subject_name);
}

// Get the display name from NAME
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name)
{
	// Validate arguments
	if (str == NULL || name == NULL)
	{
		return;
	}

	if (name->CommonName != NULL)
	{
		UniStrCpy(str, size, name->CommonName);
	}
	else if (name->Organization != NULL)
	{
		UniStrCpy(str, size, name->Organization);
	}
	else if (name->Unit != NULL)
	{
		UniStrCpy(str, size, name->Unit);
	}
	else if (name->State != NULL)
	{
		UniStrCpy(str, size, name->State);
	}
	else if (name->Local != NULL)
	{
		UniStrCpy(str, size, name->Local);
	}
	else if (name->Country != NULL)
	{
		UniStrCpy(str, size, name->Country);
	}
	else
	{
		UniStrCpy(str, size, L"untitled");
	}
}

// Get all the name strings from the certificate
void GetAllNameFromX(wchar_t *str, UINT size, X *x)
{
	UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];
	char tmp1[MD5_SIZE * 3 + 8], tmp2[SHA1_SIZE * 3 + 8];
	wchar_t tmp3[sizeof(tmp1) + sizeof(tmp2) + 64];
	// Validate arguments
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromName(str, size, x->subject_name);

	if (x->serial != NULL && x->serial->size >= 1)
	{
		char tmp[128];
		wchar_t tmp2[128];

		BinToStr(tmp, sizeof(tmp), x->serial->data, x->serial->size);
		UniFormat(tmp2, sizeof(tmp2), L", SERIAL=\"%S\"", tmp);

		UniStrCat(str, size, tmp2);
	}

	// Digest value
	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	BinToStr(tmp1, sizeof(tmp1), md5, MD5_SIZE);
	BinToStr(tmp2, sizeof(tmp2), sha1, SHA1_SIZE);

	UniFormat(tmp3, sizeof(tmp3), L" (Digest: MD5=\"%S\", SHA1=\"%S\")", tmp1, tmp2);
	UniStrCat(str, size, tmp3);
}

// Get the all name strings from NAME
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name)
{
	UniStrCpy(str, size, L"");
	// Validate arguments
	if (str == NULL || name == NULL)
	{
		return;
	}

	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%sCN=%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%sO=%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%sOU=%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%sS=%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%sL=%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%sC=%s, ", str, name->Country);
	}

	if (UniStrLen(str) >= 3)
	{
		UINT len = UniStrLen(str);
		if (str[len - 2] == L',' &&
			str[len - 1] == L' ')
		{
			str[len - 2] = 0;
		}
	}
}
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name)
{
	// Validate arguments
	if (str == NULL || name == NULL)
	{
		return;
	}

	UniStrCpy(str, size, L"");
	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Country);
	}

	if (UniStrLen(str) >= 3)
	{
		UINT len = UniStrLen(str);
		if (str[len - 2] == L',' &&
			str[len - 1] == L' ')
		{
			str[len - 2] = 0;
		}
	}
}

// Clone of the key
K *CloneK(K *k)
{
	BUF *b;
	K *ret;
	// Validate arguments
	if (k == NULL)
	{
		return NULL;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToK(b, k->private_key, false, NULL);
	FreeBuf(b);

	return ret;
}

// Clone of certificate
X *CloneX(X *x)
{
	BUF *b;
	X *ret;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToX(b, false);
	FreeBuf(b);

	return ret;
}

// Generate a P12
P12 *NewP12(X *x, K *k, char *password)
{
	PKCS12 *pkcs12;
	P12 *p12;
	// Validate arguments
	if (x == NULL || k == NULL)
	{
		return false;
	}
	if (password && StrLen(password) == 0)
	{
		password = NULL;
	}

	Lock(openssl_lock);
	{
		pkcs12 = PKCS12_create(password, NULL, k->pkey, x->x509, NULL, 0, 0, 0, 0, 0);
		if (pkcs12 == NULL)
		{
			Unlock(openssl_lock);
			return NULL;
		}
	}
	Unlock(openssl_lock);

	p12 = PKCS12ToP12(pkcs12);

	return p12;
}

// Check whether the P12 is encrypted
bool IsEncryptedP12(P12 *p12)
{
	X *x;
	K *k;
	// Validate arguments
	if (p12 == NULL)
	{
		return false;
	}

	if (ParseP12(p12, &x, &k, NULL) == true)
	{
		FreeX(x);
		FreeK(k);
		return false;
	}

	return true;
}

// Extract the X and the K from the P12
bool ParseP12(P12 *p12, X **x, K **k, char *password)
{
	EVP_PKEY *pkey;
	X509 *x509;
	// Validate arguments
	if (p12 == NULL || x == NULL || k == NULL)
	{
		return false;
	}
	if (password && StrLen(password) == 0)
	{
		password = NULL;
	}
	if (password == NULL)
	{
		password = "";
	}

	// Password confirmation
	Lock(openssl_lock);
	{
		if (PKCS12_verify_mac(p12->pkcs12, password, -1) == false &&
			PKCS12_verify_mac(p12->pkcs12, NULL, -1) == false)
		{
			Unlock(openssl_lock);
			return false;
		}
	}
	Unlock(openssl_lock);

	// Extraction
	Lock(openssl_lock);
	{
		if (PKCS12_parse(p12->pkcs12, password, &pkey, &x509, NULL) == false)
		{
			if (PKCS12_parse(p12->pkcs12, NULL, &pkey, &x509, NULL) == false)
			{
				Unlock(openssl_lock);
				return false;
			}
		}
	}
	Unlock(openssl_lock);

	// Conversion
	*x = X509ToX(x509);

	if (*x == NULL)
	{
		FreePKey(pkey);
		return false;
	}

	*k = ZeroMalloc(sizeof(K));
	(*k)->private_key = true;
	(*k)->pkey = pkey;

	return true;
}

// Write the P12 to a file
bool P12ToFileW(P12 *p12, wchar_t *filename)
{
	BUF *b;
	// Validate arguments
	if (p12 == NULL || filename == NULL)
	{
		return false;
	}

	b = P12ToBuf(p12);
	if (b == NULL)
	{
		return false;
	}

	if (DumpBufW(b, filename) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// Read a P12 from the file
P12 *FileToP12W(wchar_t *filename)
{
	BUF *b;
	P12 *p12;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	p12 = BufToP12(b);
	FreeBuf(b);

	return p12;
}

// Release of P12
void FreeP12(P12 *p12)
{
	// Validate arguments
	if (p12 == NULL)
	{
		return;
	}

	FreePKCS12(p12->pkcs12);
	Free(p12);
}

// Release of PKCS12
void FreePKCS12(PKCS12 *pkcs12)
{
	// Validate arguments
	if (pkcs12 == NULL)
	{
		return;
	}

	PKCS12_free(pkcs12);
}

// Converted the P12 to a BUF
BUF *P12ToBuf(P12 *p12)
{
	BIO *bio;
	BUF *buf;
	// Validate arguments
	if (p12 == NULL)
	{
		return NULL;
	}

	bio = P12ToBio(p12);
	if (bio == NULL)
	{
		return NULL;
	}

	buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

// Converted the P12 to a BIO
BIO *P12ToBio(P12 *p12)
{
	BIO *bio;
	// Validate arguments
	if (p12 == NULL)
	{
		return NULL;
	}

	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_PKCS12_bio(bio, p12->pkcs12);
	}
	Unlock(openssl_lock);

	return bio;
}

// Read the P12 from the BUF
P12 *BufToP12(BUF *b)
{
	P12 *p12;
	BIO *bio;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	p12 = BioToP12(bio);
	FreeBio(bio);

	return p12;
}

// Read the P12 from the BIO
P12 *BioToP12(BIO *bio)
{
	PKCS12 *pkcs12;
	// Validate arguments
	if (bio == NULL)
	{
		return NULL;
	}

	// Conversion
	Lock(openssl_lock);
	{
		pkcs12 = d2i_PKCS12_bio(bio, NULL);
	}
	Unlock(openssl_lock);
	if (pkcs12 == NULL)
	{
		// Failure
		return NULL;
	}

	return PKCS12ToP12(pkcs12);
}

// Generate a P12 from a PKCS12
P12 *PKCS12ToP12(PKCS12 *pkcs12)
{
	P12 *p12;
	// Validate arguments
	if (pkcs12 == NULL)
	{
		return NULL;
	}

	p12 = ZeroMalloc(sizeof(P12));
	p12->pkcs12 = pkcs12;

	return p12;
}

// Release of X_SERIAL
void FreeXSerial(X_SERIAL *serial)
{
	// Validate arguments
	if (serial == NULL)
	{
		return;
	}

	Free(serial->data);
	Free(serial);
}

// Comparison of X_SERIAL
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2)
{
	// Validate arguments
	if (s1 == NULL || s2 == NULL)
	{
		return false;
	}

	if (s1->size != s2->size)
	{
		return false;
	}

	if (Cmp(s1->data, s2->data, s1->size) != 0)
	{
		return false;
	}

	return true;
}

// Copy of X_SERIAL
X_SERIAL *CloneXSerial(X_SERIAL *src)
{
	X_SERIAL *s;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(X_SERIAL));
	s->data = ZeroMalloc(src->size);
	Copy(s->data, src->data, src->size);
	s->size = src->size;

	return s;
}

// Initialization of X_SERIAL
X_SERIAL *NewXSerial(void *data, UINT size)
{
	X_SERIAL *serial;
	UCHAR *buf = (UCHAR *)data;
	UINT i;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	for (i = 0;i < size;i++)
	{
		if (buf[i] != 0)
		{
			break;
		}
	}
	if (i == size)
	{
		i = size - 1;
	}
	buf += i;

	serial = Malloc(sizeof(X_SERIAL));
	serial->size = size - i;
	serial->data = ZeroMalloc(size + 16);
	Copy(serial->data, buf, size - i);

	return serial;
}

// Get the number of days till January 1, 2038
UINT GetDaysUntil2038()
{
	UINT64 now = SystemTime64();
	UINT64 target;
	SYSTEMTIME st;

	Zero(&st, sizeof(st));
	st.wYear = 2038;
	st.wMonth = 1;
	st.wDay = 1;

	target = SystemToUINT64(&st);

	if (now >= target)
	{
		return 0;
	}
	else
	{
		return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
	}
}
UINT GetDaysUntil2038Ex()
{
	SYSTEMTIME now;

	Zero(&now, sizeof(now));
	SystemTime(&now);

	if (now.wYear >= 2030)
	{
		UINT64 now = SystemTime64();
		UINT64 target;
		SYSTEMTIME st;

		Zero(&st, sizeof(st));
		st.wYear = 2049;
		st.wMonth = 12;
		st.wDay = 30;

		target = SystemToUINT64(&st);

		if (now >= target)
		{
			return 0;
		}
		else
		{
			return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
		}
	}
	else
	{
		return GetDaysUntil2038();
	}
}

// Issue an X509 certificate
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x;
	// Validate arguments
	if (pub == NULL || priv == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}

	x509 = NewX509(pub, priv, ca, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		return NULL;
	}

	return x;
}

// Create a root certificate
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x, *x2;
	// Validate arguments
	if (pub == NULL || priv == NULL || name == NULL)
	{
		return NULL;
	}

	x509 = NewRootX509(pub, priv, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);
	if (x == NULL)
	{
		return NULL;
	}

	x2 = CloneX(x);
	FreeX(x);

	return x2;
}

// Create new X509 basic & extended key usage
void AddKeyUsageX509(EXTENDED_KEY_USAGE *ex, int nid)
{
	ASN1_OBJECT *obj;
	// Validate arguments
	if (ex == NULL)
	{
		return;
	}

	obj = OBJ_nid2obj(nid);
	if (obj != NULL)
	{
		sk_ASN1_OBJECT_push(ex, obj);
	}
}
X509_EXTENSION *NewExtendedKeyUsageForX509()
{
	EXTENDED_KEY_USAGE *ex = sk_ASN1_OBJECT_new_null();
	X509_EXTENSION *ret;

	AddKeyUsageX509(ex, NID_server_auth);
	AddKeyUsageX509(ex, NID_client_auth);
	AddKeyUsageX509(ex, NID_code_sign);
	AddKeyUsageX509(ex, NID_email_protect);
	AddKeyUsageX509(ex, NID_ipsecEndSystem);
	AddKeyUsageX509(ex, NID_ipsecTunnel);
	AddKeyUsageX509(ex, NID_ipsecUser);
	AddKeyUsageX509(ex, NID_time_stamp);
	AddKeyUsageX509(ex, NID_OCSP_sign);

	ret = X509V3_EXT_i2d(NID_ext_key_usage, 0, ex);

	sk_ASN1_OBJECT_pop_free(ex, ASN1_OBJECT_free);

	return ret;
}
void BitStringSetBit(ASN1_BIT_STRING *str, int bit)
{
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	ASN1_BIT_STRING_set_bit(str, bit, 1);
}
X509_EXTENSION *NewBasicKeyUsageForX509()
{
	X509_EXTENSION *ret = NULL;
	ASN1_BIT_STRING *str;

	str = ASN1_BIT_STRING_new();
	if (str != NULL)
	{
		BitStringSetBit(str, 0);	// KU_DIGITAL_SIGNATURE
		BitStringSetBit(str, 1);	// KU_NON_REPUDIATION
		BitStringSetBit(str, 2);	// KU_KEY_ENCIPHERMENT
		BitStringSetBit(str, 3);	// KU_DATA_ENCIPHERMENT
		//BitStringSetBit(str, 4);	// KU_KEY_AGREEMENT
		BitStringSetBit(str, 5);	// KU_KEY_CERT_SIGN
		BitStringSetBit(str, 6);	// KU_CRL_SIGN

		ret = X509V3_EXT_i2d(NID_key_usage, 0, str);

		ASN1_BIT_STRING_free(str);
	}

	return ret;
}

// Issue an X509 certificate
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	X509_EXTENSION *ex = NULL;
	X509_EXTENSION *eku = NULL;
	X509_EXTENSION *busage = NULL;
	ASN1_INTEGER *s;
	// Validate arguments
	if (pub == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;

	// Creating a X509
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// Make it a v3 certificate
	X509_set_version(x509, 2L);

	// Set the Expiration
	t1 = X509_get_notBefore(x509);
	t2 = X509_get_notAfter(x509);
	if (!UINT64ToAsn1Time(t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time(t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	// Set the name
	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = X509_get_subject_name(ca->x509);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);

	// Set the Serial Number
	s = X509_get_serialNumber(x509);
	OPENSSL_free(s->data);
	if (serial == NULL)
	{
		char zero = 0;
		s->data = OPENSSL_malloc(sizeof(char));
		Copy(s->data, &zero, sizeof(char));
		s->length = sizeof(char);
	}
	else
	{
		s->data = OPENSSL_malloc(serial->size);
		Copy(s->data, serial->data, serial->size);
		s->length = serial->size;
	}

	/*
	// Extensions
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,	"critical,CA:TRUE");
	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);
*/

	// Basic usage
	busage = NewBasicKeyUsageForX509();
	if (busage != NULL)
	{
		X509_add_ext(x509, busage, -1);
		X509_EXTENSION_free(busage);
	}

	// EKU
	eku = NewExtendedKeyUsageForX509();
	if (eku != NULL)
	{
		X509_add_ext(x509, eku, -1);
		X509_EXTENSION_free(eku);
	}

	// Alternative subject name
	if (UniIsEmptyStr(name->CommonName) == false)
	{
		char alt_dns[MAX_PATH];

		Format(alt_dns, sizeof(alt_dns), "DNS.1:%S", name->CommonName);

		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,	alt_dns);
		X509_add_ext(x509, ex, -1);
		X509_EXTENSION_free(ex);
	}

	Lock(openssl_lock);
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	Unlock(openssl_lock);

	return x509;
}

// Create an X509 root certificate
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	X509_EXTENSION *ex = NULL;
	X509_EXTENSION *eku = NULL;
	X509_EXTENSION *busage = NULL;
	ASN1_INTEGER *s;
	// Validate arguments
	if (pub == NULL || name == NULL || priv == NULL)
	{
		return NULL;
	}
	if (days == 0)
	{
		days = 365;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;

	// Creating a X509
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// Make it a v3 certificate
	X509_set_version(x509, 2L);

	// Set the Expiration
	t1 = X509_get_notBefore(x509);
	t2 = X509_get_notAfter(x509);
	if (!UINT64ToAsn1Time(t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time(t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	// Set the name
	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = NameToX509Name(name);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);
	FreeX509Name(issuer_name);

	// Set a Serial Number
	s = X509_get_serialNumber(x509);
	OPENSSL_free(s->data);
	if (serial == NULL)
	{
		char zero = 0;
		s->data = OPENSSL_malloc(sizeof(char));
		Copy(s->data, &zero, sizeof(char));
		s->length = sizeof(char);
	}
	else
	{
		s->data = OPENSSL_malloc(serial->size);
		Copy(s->data, serial->data, serial->size);
		s->length = serial->size;
	}

	// Extensions
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,	"critical,CA:TRUE");
	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);

	// Basic usage
	busage = NewBasicKeyUsageForX509();
	if (busage != NULL)
	{
		X509_add_ext(x509, busage, -1);
		X509_EXTENSION_free(busage);
	}

	// EKU
	eku = NewExtendedKeyUsageForX509();
	if (eku != NULL)
	{
		X509_add_ext(x509, eku, -1);
		X509_EXTENSION_free(eku);
	}

	Lock(openssl_lock);
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	Unlock(openssl_lock);

	return x509;
}

// Convert the NAMEto a X509_NAME
void *NameToX509Name(NAME *nm)
{
	X509_NAME *xn;
	// Validate arguments
	if (nm == NULL)
	{
		return NULL;
	}

	xn = X509_NAME_new();
	if (xn == NULL)
	{
		return NULL;
	}

	// Add the entries
	AddX509Name(xn, NID_commonName, nm->CommonName);
	AddX509Name(xn, NID_organizationName, nm->Organization);
	AddX509Name(xn, NID_organizationalUnitName, nm->Unit);
	AddX509Name(xn, NID_countryName, nm->Country);
	AddX509Name(xn, NID_stateOrProvinceName, nm->State);
	AddX509Name(xn, NID_localityName, nm->Local);

	return xn;
}

// Add an entry to the X509_NAME
bool AddX509Name(void *xn, int nid, wchar_t *str)
{
	X509_NAME *x509_name;
	UINT utf8_size;
	BYTE *utf8;
	int encoding_type = MBSTRING_ASC;
	// Validate arguments
	if (xn == NULL || str == NULL)
	{
		return false;
	}

	// Convert to UTF-8
	utf8_size = CalcUniToUtf8(str);
	if (utf8_size == 0)
	{
		return false;
	}
	utf8 = ZeroMalloc(utf8_size + 1);
	UniToUtf8(utf8, utf8_size, str);
	utf8[utf8_size] = 0;

	if (StrLen(utf8) != UniStrLen(str))
	{
		encoding_type = MBSTRING_UTF8;
	}

	// Adding
	x509_name = (X509_NAME *)xn;
	Lock(openssl_lock);
	{
		X509_NAME_add_entry_by_NID(x509_name, nid, encoding_type, utf8, utf8_size, -1, 0);
	}
	Unlock(openssl_lock);
	Free(utf8);

	return true;
}

// Release the X509_NAME
void FreeX509Name(void *xn)
{
	X509_NAME *x509_name;
	// Validate arguments
	if (xn == NULL)
	{
		return;
	}

	x509_name = (X509_NAME *)xn;
	X509_NAME_free(x509_name);
}

// Creating the NAME
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local)
{
	NAME *nm = ZeroMalloc(sizeof(NAME));

	if (UniIsEmptyStr(common_name) == false)
	{
		nm->CommonName = CopyUniStr(common_name);
	}

	if (UniIsEmptyStr(organization) == false)
	{
		nm->Organization = CopyUniStr(organization);
	}

	if (UniIsEmptyStr(unit) == false)
	{
		nm->Unit = CopyUniStr(unit);
	}

	if (UniIsEmptyStr(country) == false)
	{
		nm->Country = CopyUniStr(country);
	}

	if (UniIsEmptyStr(state) == false)
	{
		nm->State = CopyUniStr(state);
	}

	if (UniIsEmptyStr(local) == false)
	{
		nm->Local = CopyUniStr(local);
	}

	return nm;
}

// Check the expiration date of the certificate by the current time
bool CheckXDateNow(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	return CheckXDate(x, SystemTime64());
}

// Check the expiration date of the certificate
bool CheckXDate(X *x, UINT64 current_system_time)
{
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	if (x->notBefore >= current_system_time || x->notAfter <= current_system_time)
	{
		return false;
	}
	return true;
}

// Read the expiration date of the certificate
void LoadXDates(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	x->notBefore = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notBefore(x->x509));
	x->notAfter = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notAfter(x->x509));
}

// Convert the 64bit system time to ASN1 time
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t)
{
	SYSTEMTIME st;
	// Validate arguments
	if (asn1_time == NULL)
	{
		return false;
	}

	UINT64ToSystem(&st, t);
	return SystemToAsn1Time(asn1_time, &st);
}

// Convert the system time to the ASN1 time
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s)
{
	char tmp[20];
	ASN1_TIME *t;
	// Validate arguments
	if (asn1_time == NULL || s == NULL)
	{
		return false;
	}

	if (SystemToStr(tmp, sizeof(tmp), s) == false)
	{
		return false;
	}
	t = (ASN1_TIME *)asn1_time;
	if (t->data == NULL || t->length < sizeof(tmp))
	{
		t->data = OPENSSL_malloc(sizeof(tmp));
	}
	StrCpy((char *)t->data, t->length, tmp);
	t->length = StrLen(tmp);
	t->type = V_ASN1_UTCTIME;

	return true;
}

// Convert the system time to a string
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s)
{
	// Validate arguments
	if (str == NULL || s == NULL)
	{
		return false;
	}

	Format(str, size, "%02u%02u%02u%02u%02u%02uZ",
		s->wYear % 100, s->wMonth, s->wDay,
		s->wHour, s->wMinute, s->wSecond);

	return true;
}

// Convert an ASN1 time to an UINT64 time
UINT64 Asn1TimeToUINT64(void *asn1_time)
{
	SYSTEMTIME st;
	// Validate arguments
	if (asn1_time == NULL)
	{
		return 0;
	}

	if (Asn1TimeToSystem(&st, asn1_time) == false)
	{
		return 0;
	}
	return SystemToUINT64(&st);
}

// Converted an ASN1 time to a system time
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time)
{
	ASN1_TIME *t;
	// Validate arguments
	if (s == NULL || asn1_time == NULL)
	{
		return false;
	}

	t = (ASN1_TIME *)asn1_time;
	if (StrToSystem(s, (char *)t->data) == false)
	{
		return false;
	}

	if (t->type == V_ASN1_GENERALIZEDTIME)
	{
		LocalToSystem(s, s);
	}

	return true;
}

// Convert the string to the system time
bool StrToSystem(SYSTEMTIME *s, char *str)
{
	char century[3] = {0, 0, 0};
	bool fourdigityear = false;

	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return false;
	}
	if (StrLen(str) != 13)
	{
		if (StrLen(str) != 15)
		{
			return false;
		}

		// Year has 4 digits - save first two and use the rest
		// as if it had two digits
		fourdigityear = true;
		century[0] = str[0];
		century[1] = str[1];
		str += 2;
	}
	if (str[12] != 'Z')
	{
		return false;
	}

	// Conversion
	{
		char year[3] = {str[0], str[1], 0},
			month[3] = {str[2], str[3], 0},
			day[3] = {str[4], str[5], 0},
			hour[3] = {str[6], str[7], 0},
			minute[3] = {str[8], str[9], 0},
			second[3] = {str[10], str[11], 0};
		Zero(s, sizeof(SYSTEMTIME));
		s->wYear = ToInt(year);
		if (fourdigityear)
		{
			s->wYear += ToInt(century) * 100;
		}
		else if (s->wYear >= 60)
		{
			s->wYear += 1900;
		}
		else
		{
			s->wYear += 2000;
		}
		s->wMonth = ToInt(month);
		s->wDay = ToInt(day);
		s->wHour = ToInt(hour);
		s->wMinute = ToInt(minute);
		s->wSecond = ToInt(second);
		NormalizeSystem(s);
	}

	return true;
}

// Verify the RSA signature
bool RsaVerify(void *data, UINT data_size, void *sign, K *k)
{
	return RsaVerifyEx(data, data_size, sign, k, 0);
}

bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits)
{
	UCHAR hash_data[SIGN_HASH_SIZE];
	UCHAR decrypt_data[SIGN_HASH_SIZE];
	// Validate arguments
	if (data == NULL || sign == NULL || k == NULL || k->private_key != false)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = 1024;
	}

	// Hash the data
	if (HashForSign(hash_data, sizeof(hash_data), data, data_size) == false)
	{
		return false;
	}

	// Decode the signature
	if (RSA_public_decrypt(bits / 8, sign, decrypt_data, EVP_PKEY_get0_RSA(k->pkey), RSA_PKCS1_PADDING) <= 0)
	{
		return false;
	}

	// Comparison
	if (Cmp(decrypt_data, hash_data, SIGN_HASH_SIZE) != 0)
	{
		return false;
	}

	return true;
}

// RSA signature
bool RsaSign(void *dst, void *src, UINT size, K *k)
{
	return RsaSignEx(dst, src, size, k, 0);
}
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits)
{
	UCHAR hash[SIGN_HASH_SIZE];
	// Validate arguments
	if (dst == NULL || src == NULL || k == NULL || EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = 1024;
	}

	Zero(dst, bits / 8);

	// Hash
	if (HashForSign(hash, sizeof(hash), src, size) == false)
	{
		return false;
	}

	// Signature
	if (RSA_private_encrypt(sizeof(hash), hash, dst, EVP_PKEY_get0_RSA(k->pkey), RSA_PKCS1_PADDING) <= 0)
	{
		return false;
	}

	return true;
}

// Generation of signature data by SHA-1
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size)
{
	UCHAR *buf = (UCHAR *)dst;
	UCHAR sign_data[] =
	{
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
		0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
	};
	// Validate arguments
	if (dst == NULL || src == NULL || src_size == 0 || MIN_SIGN_HASH_SIZE > dst_size)
	{
		return false;
	}

	// Header part
	Copy(buf, sign_data, sizeof(sign_data));

	// Hash
	HashSha1(HASHED_DATA(buf), src, src_size);

	return true;
}

// RSA operating environment check
bool RsaCheckEx()
{
	UINT num = 20;
	UINT i;

	for (i = 0;i < num;i++)
	{
		if (RsaCheck())
		{
			return true;
		}

		SleepThread(100);
	}

	return false;
}
bool RsaCheck()
{
	RSA *rsa;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	UINT bit = 32;
	// Validate arguments

	// Key generation
	Lock(openssl_lock);
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	Unlock(openssl_lock);
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// Secret key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	size = RsaPublicSize(pub_key);

	if (size != ((bit + 7) / 8))
	{
		FreeK(priv_key);
		FreeK(pub_key);

		return false;
	}

	FreeK(priv_key);
	FreeK(pub_key);

	return true;
}

// Generation of RSA key
bool RsaGen(K **priv, K **pub, UINT bit)
{
	RSA *rsa;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	// Validate arguments
	if (priv == NULL || pub == NULL)
	{
		return false;
	}
	if (bit == 0)
	{
		bit = 1024;
	}

	// Key generation
	Lock(openssl_lock);
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	Unlock(openssl_lock);
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// Secret key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	*priv = priv_key;
	*pub = pub_key;

	RSA_free(rsa);

	size = RsaPublicSize(*pub);

	if (size != ((bit + 7) / 8))
	{
		FreeK(*priv);
		FreeK(*pub);

		return RsaGen(priv, pub, bit);
	}

	return true;
}

// Confirm whether the certificate X is signed by the issuer of the certificate x_issuer
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date)
{
	K *k;
	bool ret;
	// Validate arguments
	if (x == NULL || x_issuer == NULL)
	{
		return false;
	}

	k = GetKFromX(x_issuer);
	if (k == NULL)
	{
		return false;
	}

	ret = CheckSignature(x, k);

	if (ret)
	{
		if (check_name)
		{
			if (CompareName(x->issuer_name, x_issuer->subject_name) == false)
			{
				ret = false;
			}
		}

		if (check_date)
		{
			if (CheckXDateNow(x_issuer) == false)
			{
				ret = false;
			}
		}
	}

	FreeK(k);

	return ret;
}

// Confirm the signature of the certificate X with the public key K
bool CheckSignature(X *x, K *k)
{
	// Validate arguments
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	{
		if (X509_verify(x->x509, k->pkey) == 0)
		{
			Unlock(openssl_lock);
			return false;
		}
	}
	Unlock(openssl_lock);
	return true;
}

// Get the public key from the certificate
K *GetKFromX(X *x)
{
	EVP_PKEY *pkey;
	K *k;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		pkey = X509_get_pubkey(x->x509);
	}
	Unlock(openssl_lock);
	if (pkey == NULL)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;

	return k;
}

// The name comparison
bool CompareName(NAME *n1, NAME *n2)
{
	// Validate arguments
	if (n1 == NULL || n2 == NULL)
	{
		return false;
	}

	// Name comparison
	if (UniStrCmpi(n1->CommonName, n2->CommonName) == 0 &&
		UniStrCmpi(n1->Organization, n2->Organization) == 0 &&
		UniStrCmpi(n1->Unit, n2->Unit) == 0 &&
		UniStrCmpi(n1->Country, n2->Country) == 0 &&
		UniStrCmpi(n1->State, n2->State) == 0 &&
		UniStrCmpi(n1->Local, n2->Local) == 0)
	{
		return true;
	}

	return false;
}

// Release the name of the X
void FreeXNames(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	FreeName(x->issuer_name);
	x->issuer_name = NULL;

	FreeName(x->subject_name);
	x->subject_name = NULL;
}

// Release the name
void FreeName(NAME *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Release the string
	Free(n->CommonName);
	Free(n->Organization);
	Free(n->Unit);
	Free(n->Country);
	Free(n->State);
	Free(n->Local);

	// Release the object
	Free(n);

	return;
}

// Get the name of the certificate
void LoadXNames(X *x)
{
	X509 *x509;
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	x509 = x->x509;
	x->issuer_name = X509NameToName(X509_get_issuer_name(x509));
	x->subject_name = X509NameToName(X509_get_subject_name(x509));
}

// Convert the X509_NAME structure to the NAME structure
NAME *X509NameToName(void *xn)
{
	NAME *n;
	// Validate arguments
	if (xn == NULL)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAME));

	// Get the strings one by one
	n->CommonName = GetUniStrFromX509Name(xn, NID_commonName);
	n->Organization = GetUniStrFromX509Name(xn, NID_organizationName);
	n->Unit = GetUniStrFromX509Name(xn, NID_organizationalUnitName);
	n->Country = GetUniStrFromX509Name(xn, NID_countryName);
	n->State = GetUniStrFromX509Name(xn, NID_stateOrProvinceName);
	n->Local = GetUniStrFromX509Name(xn, NID_localityName);

	return n;
}

// Read a Unicode string from the X509_NAME structure
wchar_t *GetUniStrFromX509Name(void *xn, int nid)
{
	UCHAR txt[1024];
	bool b = false;
	UINT i, size;
	int index;
	bool unicode = false;
	bool is_utf_8 = false;
	ASN1_OBJECT *obj;
	ASN1_STRING *data;
	// Validate arguments
	if (xn == NULL || nid == 0)
	{
		return NULL;
	}

	Zero(txt, sizeof(txt));
	if (X509_NAME_get_text_by_NID(xn, nid, (char *)txt, sizeof(txt) - 2) <= 0)
	{
		return NULL;
	}

	obj = OBJ_nid2obj(nid);
	if (obj == NULL)
	{
		return NULL;
	}
	index = X509_NAME_get_index_by_OBJ(xn, obj, -1);
	if (index < 0)
	{
		return NULL;
	}
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn, index));
	if (data == NULL)
	{
		return NULL;
	}
	if (data->type == V_ASN1_BMPSTRING)
	{
		unicode = true;
	}
	if (data->type == V_ASN1_UTF8STRING || data->type == V_ASN1_T61STRING)
	{
		is_utf_8 = true;
	}

	size = UniStrLen((wchar_t *)txt) * 4 + 8;
	for (i = 0;i < size;i++)
	{
		if (txt[i] >= 0x80)
		{
			unicode = true;
			break;
		}
	}

	if (is_utf_8)
	{
		wchar_t *ret;
		UINT ret_size;

		ret_size = CalcUtf8ToUni(txt, StrLen(txt));
		ret = ZeroMalloc(ret_size + 8);
		Utf8ToUni(ret, ret_size, txt, StrLen(txt));

		return ret;
	}
	else if (unicode == false)
	{
		wchar_t tmp[1024];
		StrToUni(tmp, sizeof(tmp), (char *)txt);
		return CopyUniStr(tmp);
	}
	else
	{
		EndianUnicode((wchar_t *)txt);
		return CopyUniStr((wchar_t *)txt);
	}
}

// Check whether the certificate x1 equal to x2
bool CompareX(X *x1, X *x2)
{
	// Validate arguments
	if (x1 == NULL || x2 == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	if (X509_cmp(x1->x509, x2->x509) == 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
		return false;
	}
}

// Check whether K is private key of X
bool CheckXandK(X *x, K *k)
{
	// Validate arguments
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	if (X509_check_private_key(x->x509, k->pkey) != 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
		return false;
	}
}

// Read a X from the file
X *FileToX(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	X *ret = FileToXW(filename_w);

	Free(filename_w);

	return ret;
}
X *FileToXW(wchar_t *filename)
{
	bool text;
	BUF *b;
	X *x;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	text = IsBase64(b);

	x = BufToX(b, text);
	FreeBuf(b);

	return x;
}

// Write the X to a file
bool XToFile(X *x, char *filename, bool text)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = XToFileW(x, filename_w, text);

	Free(filename_w);

	return ret;
}
bool XToFileW(X *x, wchar_t *filename, bool text)
{
	BUF *b;
	bool ret;
	// Validate arguments
	if (x == NULL || filename == NULL)
	{
		return false;
	}

	b = XToBuf(x, text);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

// Read a K from the file
K *FileToKW(wchar_t *filename, bool private_key, char *password)
{
	bool text;
	BUF *b;
	K *k;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	text = IsBase64(b);
	if (text == false)
	{
		k = BufToK(b, private_key, false, NULL);
	}
	else
	{
		k = BufToK(b, private_key, true, NULL);
		if (k == NULL)
		{
			k = BufToK(b, private_key, true, password);
		}
	}

	FreeBuf(b);

	return k;
}

// Save the K to a file
bool KToFileW(K *k, wchar_t *filename, bool text, char *password)
{
	BUF *b;
	bool ret;
	// Validate arguments
	if (k == NULL || filename == NULL)
	{
		return false;
	}

	b = KToBuf(k, text, password);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

// Convert the K to the BUF
BUF *KToBuf(K *k, bool text, char *password)
{
	BUF *buf;
	BIO *bio;
	// Validate arguments
	if (k == NULL)
	{
		return NULL;
	}

	bio = KToBio(k, text, password);
	if (bio == NULL)
	{
		return NULL;
	}

	buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

// Convert the K to the BIO
BIO *KToBio(K *k, bool text, char *password)
{
	BIO *bio;
	// Validate arguments
	if (k == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	if (k->private_key)
	{
		// Secret key
		if (text == false)
		{
			// Binary format
			Lock(openssl_lock);
			{
				i2d_PrivateKey_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// Text format
			if (password == 0 || StrLen(password) == 0)
			{
				// No encryption
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
				}
				Unlock(openssl_lock);
			}
			else
			{
				// Encrypt
				CB_PARAM cb;
				cb.password = password;
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
						NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
				}
				Unlock(openssl_lock);
			}
		}
	}
	else
	{
		// Public key
		if (text == false)
		{
			// Binary format
			Lock(openssl_lock);
			{
				i2d_PUBKEY_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// Text format
			Lock(openssl_lock);
			{
				PEM_write_bio_PUBKEY(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
	}

	return bio;
}

// Check whether the BUF is encoded as the Base64
bool IsBase64(BUF *b)
{
	UINT i;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	if (SearchAsciiInBinary(b->Buf, b->Size, "-----BEGIN", false) != INFINITE)
	{
		return true;
	}

	for (i = 0;i < b->Size;i++)
	{
		char c = ((char *)b->Buf)[i];
		bool b = false;
		if ('a' <= c && c <= 'z')
		{
			b = true;
		}
		else if ('A' <= c && c <= 'Z')
		{
			b = true;
		}
		else if ('0' <= c && c <= '9')
		{
			b = true;
		}
		else if (c == ':' || c == '.' || c == ';' || c == ',')
		{
			b = true;
		}
		else if (c == '!' || c == '&' || c == '#' || c == '(' || c == ')')
		{
			b = true;
		}
		else if (c == '-' || c == ' ')
		{
			b = true;
		}
		else if (c == 13 || c == 10 || c == EOF)
		{
			b = true;
		}
		else if (c == '\t' || c == '=' || c == '+' || c == '/')
		{
			b = true;
		}
		if (b == false)
		{
			return false;
		}
	}
	return true;
}

// Check whether the K in the BUF is encrypted
bool IsEncryptedK(BUF *b, bool private_key)
{
	K *k;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}
	if (IsBase64(b) == false)
	{
		return false;
	}

	k = BufToK(b, private_key, true, NULL);
	if (k != NULL)
	{
		FreeK(k);
		return false;
	}

	return true;
}

// Convert the BUF to a K
K *BufToK(BUF *b, bool private_key, bool text, char *password)
{
	BIO *bio;
	K *k;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	k = BioToK(bio, private_key, text, password);
	FreeBio(bio);

	return k;
}

// Release of K
void FreeK(K *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	FreePKey(k->pkey);
	Free(k);
}

// Release the secret key
void FreePKey(EVP_PKEY *pkey)
{
	// Validate arguments
	if (pkey == NULL)
	{
		return;
	}

	EVP_PKEY_free(pkey);
}

// Convert the BIO to the K
K *BioToK(BIO *bio, bool private_key, bool text, char *password)
{
	EVP_PKEY *pkey;
	K *k;
	// Validate arguments
	if (bio == NULL)
	{
		return NULL;
	}

	if (password != NULL && StrLen(password) == 0)
	{
		password = NULL;
	}

	if (private_key == false)
	{
		// Public key
		if (text == false)
		{
			// Binary format
			pkey = d2i_PUBKEY_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			// Text format
			CB_PARAM cb;
			cb.password = password;
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}
	else
	{
		if (text == false)
		{
			// Binary format
			Lock(openssl_lock);
			{
				pkey = d2i_PrivateKey_bio(bio, NULL);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			// Text format
			CB_PARAM cb;
			cb.password = password;
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;
	k->private_key = private_key;

	return k;
}

// Password callback function
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param)
{
	CB_PARAM *cb;
	// Validate arguments
	if (buf == NULL || param == NULL || bufsize == 0)
	{
		return 0;
	}

	cb = (CB_PARAM *)param;
	if (cb->password == NULL)
	{
		return 0;
	}

	return StrCpy(buf, bufsize, cb->password);
}

// Convert the X to a BUF
BUF *XToBuf(X *x, bool text)
{
	BIO *bio;
	BUF *b;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	bio = XToBio(x, text);
	if (bio == NULL)
	{
		return NULL;
	}

	b = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(b, 0, 0);

	return b;
}

// Convert the X to a BIO
BIO *XToBio(X *x, bool text)
{
	BIO *bio;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	Lock(openssl_lock);
	{
		if (text == false)
		{
			// Binary format
			i2d_X509_bio(bio, x->x509);
		}
		else
		{
			// Text format
			PEM_write_bio_X509(bio, x->x509);
		}
	}
	Unlock(openssl_lock);

	return bio;
}

// Release of the X
void FreeX(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	// Release the name
	FreeXNames(x);


	// Release the Serial
	FreeXSerial(x->serial);

	if (x->do_not_free == false)
	{
		FreeX509(x->x509);
	}
	Free(x);
}

// Release of the X509
void FreeX509(X509 *x509)
{
	// Validate arguments
	if (x509 == NULL)
	{
		return;
	}

	Lock(openssl_lock);
	{
		X509_free(x509);
	}
	Unlock(openssl_lock);
}

// Convert the BUF to a X
X *BufToX(BUF *b, bool text)
{
	X *x;
	BIO *bio;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	x = BioToX(bio, text);

	FreeBio(bio);

	return x;
}

// Get a digest of the X
void GetXDigest(X *x, UCHAR *buf, bool sha1)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	if (sha1 == false)
	{
		UINT size = MD5_SIZE;
		X509_digest(x->x509, EVP_md5(), buf, (unsigned int *)&size);
	}
	else
	{
		UINT size = SHA1_SIZE;
		X509_digest(x->x509, EVP_sha1(), buf, (unsigned int *)&size);
	}
}

// Convert BIO to X
X *BioToX(BIO *bio, bool text)
{
	X *x;
	X509 *x509;
	// Validate arguments
	if (bio == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		// Reading x509
		if (text == false)
		{
			// Binary mode
			x509 = d2i_X509_bio(bio, NULL);
		}
		else
		{
			// Text mode
			x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		}
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		return NULL;
	}

	return x;
}

// Convert the X509 to X
X *X509ToX(X509 *x509)
{
	X *x;
	K *k;
	BUF *b;
	UINT size;
	UINT type;
	ASN1_INTEGER *s;
	// Validate arguments
	if (x509 == NULL)
	{
		return NULL;
	}

	x = ZeroMalloc(sizeof(X));
	x->x509 = x509;

	// Name
	LoadXNames(x);

	// Expiration date
	LoadXDates(x);

	// Check whether it is a root certificate
	if (CompareName(x->issuer_name, x->subject_name))
	{
		K *pubkey = GetKFromX(x);
		if (pubkey != NULL)
		{
			if (CheckXandK(x, pubkey))
			{
				x->root_cert = true;
			}
			FreeK(pubkey);
		}
	}

	// Check whether there is basic constraints
	if (X509_get_ext_by_NID(x509, NID_basic_constraints, -1) != -1)
	{
		x->has_basic_constraints = true;
	}

	// Get the "Certification Authority Issuer" (1.3.6.1.5.5.7.48.2) field value
	if (x->root_cert == false)
	{
		AUTHORITY_INFO_ACCESS *ads = (AUTHORITY_INFO_ACCESS *)X509_get_ext_d2i(x509, NID_info_access, NULL, NULL);

		if (ads != NULL)
		{
			int i;

			for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ads); i++)
			{
				ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(ads, i);
				if (ad != NULL)
				{
					if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location->type == GEN_URI)
					{
						char *uri = (char *)ASN1_STRING_data(ad->location->d.uniformResourceIdentifier);

						if (IsEmptyStr(uri) == false)
						{
							StrCpy(x->issuer_url, sizeof(x->issuer_url), uri);
							break;
						}
					}
				}
			}

			AUTHORITY_INFO_ACCESS_free(ads);
		}
	}

	// Get the Serial Number
	s = X509_get_serialNumber(x509);
	x->serial = NewXSerial(s->data, s->length);
	if (x->serial == NULL)
	{
		char zero = 0;
		x->serial = NewXSerial(&zero, sizeof(char));
	}

	k = GetKFromX(x);
	if (k == NULL)
	{
		FreeX(x);
		return NULL;
	}

	b = KToBuf(k, false, NULL);

	size = b->Size;
	type = EVP_PKEY_base_id(k->pkey);

	FreeBuf(b);
	
	//Fixed to get actual RSA key bits
	x->bits = EVP_PKEY_bits(k->pkey);
	
	FreeK(k);

	if (type == EVP_PKEY_RSA)
	{
		x->is_compatible_bit = true;

		if(x->bits != 1024 && x->bits != 1536 && x->bits != 2048 && x->bits != 3072 && x->bits != 4096)
		{
			x->is_compatible_bit = false;
		}
		else
		{
			x->is_compatible_bit = true;
		}
		
		/*switch (size)
		{
		case 162:
			x->bits = 1024;
			break;

		case 226:
			x->bits = 1536;
			break;

		case 294:
			x->bits = 2048;
			break;

		case 442:
			x->bits = 3072;
			break;

		case 550:
			x->bits = 4096;
			break;

		default:
			x->is_compatible_bit = false;
			break;
		}*/
	}

	return x;
}

// Create a BIO
BIO *NewBio()
{
	return BIO_new(BIO_s_mem());
}

// Release the BIO
void FreeBio(BIO *bio)
{
	// Validate arguments
	if (bio == NULL)
	{
		return;
	}

	BIO_free(bio);
}

// Convert the BIO to the BUF
BUF *BioToBuf(BIO *bio)
{
	BUF *b;
	UINT size;
	void *tmp;
	// Validate arguments
	if (bio == NULL)
	{
		return NULL;
	}

	BIO_seek(bio, 0);
	size = (UINT)BIO_number_written(bio);
	tmp = Malloc(size);
	BIO_read(bio, tmp, size);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	return b;
}

// Convert the BUF to a BIO
BIO *BufToBio(BUF *b)
{
	BIO *bio;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
		{
			Unlock(openssl_lock);
			return NULL;
		}
		BIO_write(bio, b->Buf, b->Size);
		BIO_seek(bio, 0);
	}
	Unlock(openssl_lock);

	return bio;
}

// 64-bit random number generation
UINT64 Rand64()
{
	UINT64 i;
	Rand(&i, sizeof(i));
	return i;
}

// 32-bit random number generation
UINT Rand32()
{
	UINT i;
	Rand(&i, sizeof(i));
	return i;
}

// 16-bit random number generation
USHORT Rand16()
{
	USHORT i;
	Rand(&i, sizeof(i));
	return i;
}

// 8-bit random number generation
UCHAR Rand8()
{
	UCHAR i;
	Rand(&i, sizeof(i));
	return i;
}

// 1-bit random number generation
bool Rand1()
{
	return (Rand32() % 2) == 0 ? false : true;
}

// Random number generation
void Rand(void *buf, UINT size)
{
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return;
	}
	RAND_bytes(buf, size);
}

// Delete a thread-specific information that OpenSSL has holded
void FreeOpenSSLThreadState()
{
	ERR_remove_state(0);
}

// Release the Crypt library
void FreeCryptLibrary()
{
	openssl_inited = false;

	DeleteLock(openssl_lock);
	openssl_lock = NULL;
//	RAND_Free_For_SoftEther();
	OpenSSL_FreeLock();
}

// Initialize the Crypt library
void InitCryptLibrary()
{
	char tmp[16];

//	RAND_Init_For_SoftEther()
	openssl_lock = NewLock();
	SSL_library_init();
	//OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	ssl_clientcert_index = SSL_get_ex_new_index(0, "struct SslClientCertInfo *", NULL, NULL, NULL);

#ifdef	OS_UNIX
	{
		char *name1 = "/dev/random";
		char *name2 = "/dev/urandom";
		IO *o;
		o = FileOpen(name1, false);
		if (o == NULL)
		{
			o = FileOpen(name2, false);
			if (o == NULL)
			{
				UINT64 now = SystemTime64();
				BUF *b;
				UINT i;
				b = NewBuf();
				for (i = 0;i < 4096;i++)
				{
					UCHAR c = rand() % 256;
					WriteBuf(b, &c, 1);
				}
				WriteBuf(b, &now, sizeof(now));
				RAND_seed(b->Buf, b->Size);
				FreeBuf(b);
			}
			else
			{
				FileClose(o);
			}
		}
		else
		{
			FileClose(o);
		}
	}
#endif	// OS_UNIX

	RAND_poll();

#ifdef	OS_WIN32
//	RAND_screen();
#endif
	Rand(tmp, sizeof(tmp));
	OpenSSL_InitLock();

	openssl_inited = true;
}

// Hash function
void Hash(void *dst, void *src, UINT size, bool sha)
{
	// Validate arguments
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	if (sha == false)
	{
		// MD5 hash
		MD5(src, size, dst);
	}
	else
	{
		// SHA hash
		Internal_SHA0(src, size, dst);
	}
}

// MD4 specific hash function
void HashMd4(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (size != 0 && src == NULL))
	{
		return;
	}
	MD4(src, size, dst);
}

// Hash with the SHA-1 and convert it to UINT
UINT HashToUINT(void *data, UINT size)
{
	UCHAR hash[SHA1_SIZE];
	UINT u;
	// Validate arguments
	if (data == NULL && size != 0)
	{
		return 0;
	}

	HashSha1(hash, data, size);

	Copy(&u, hash, sizeof(UINT));

	u = Endian32(u);

	return u;
}

// SHA-1 specific hash function
void HashSha1(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (size != 0 && src == NULL))
	{
		return;
	}
	SHA1(src, size, dst);
}

// Creating a new CRYPT object
CRYPT *NewCrypt(void *key, UINT size)
{
	CRYPT *c = ZeroMalloc(sizeof(CRYPT));

	c->Rc4Key = Malloc(sizeof(struct rc4_key_st));

	RC4_set_key(c->Rc4Key, size, (UCHAR *)key);

	return c;
}

// Release the CRYPT object
void FreeCrypt(CRYPT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Memory release
	Free(c->Rc4Key);
	Free(c);
}

// Encryption and decryption
void Encrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	RC4(c->Rc4Key, size, src, dst);
}

// SHA-1 hash
void Sha(UINT sha_type, void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	switch(sha_type) {
	case SHA1_160:
		SHA1(src, size, dst);
		break;
	case SHA2_256:
		SHA256(src, size, dst);
		break;
	case SHA2_384:
		SHA384(src, size, dst);
		break;
	case SHA2_512:
		SHA512(src, size, dst);
		break;
	}

}


// SHA-1 hash
void Sha1(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	SHA1(src, size, dst);
}

void Sha2_256(void *dst, void *src, UINT size) {
	Sha(SHA2_256, dst, src, size);
}
void Sha2_384(void *dst, void *src, UINT size) {
	Sha(SHA2_384, dst, src, size);
}
void Sha2_512(void *dst, void *src, UINT size) {
	Sha(SHA2_512, dst, src, size);
}

// MD5 hash
void Md5(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	MD5(src, size, dst);
}

// 3DES encryption
void Des3Encrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k1 == NULL || k2 == NULL || k3 == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_ede3_cbc_encrypt(src, dest, size,
		k1->KeySchedule,
		k2->KeySchedule,
		k3->KeySchedule,
		(DES_cblock *)ivec_copy,
		1);
}

// DES encryption
void DesEncrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_cbc_encrypt(src, dest, size,
		k->KeySchedule,
		(DES_cblock *)ivec_copy,
		1);
}

// 3DES decryption
void Des3Decrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k1 == NULL || k2 == NULL || k3 == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_ede3_cbc_encrypt(src, dest, size,
		k1->KeySchedule,
		k2->KeySchedule,
		k3->KeySchedule,
		(DES_cblock *)ivec_copy,
		0);
}

// DES-ECB encryption
void DesEcbEncrypt(void *dst, void *src, void *key_7bytes)
{
	UCHAR *key_56;
	DES_cblock key;
	DES_key_schedule ks;
	// Validate arguments
	if (dst == NULL || src == NULL || key_7bytes == NULL)
	{
		return;
	}

	key_56 = (UCHAR *)key_7bytes;

	Zero(&key, sizeof(key));
	Zero(&ks, sizeof(ks));

	key[0] = key_56[0];
	key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
	key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
	key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
	key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
	key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
	key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
	key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);

	DES_set_odd_parity(&key);
	DES_set_key_unchecked(&key, &ks);

	DES_ecb_encrypt(src, dst, &ks, 1);
}

// DES decryption
void DesDecrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_cbc_encrypt(src, dest, size,
		k->KeySchedule,
		(DES_cblock *)ivec_copy,
		0);
}

// Release the 3DES key
void Des3FreeKey(DES_KEY *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	DesFreeKeyValue(k->k1);
	DesFreeKeyValue(k->k2);
	DesFreeKeyValue(k->k3);

	Free(k);
}

// Create a 3DES key
DES_KEY *Des3NewKey(void *k1, void *k2, void *k3)
{
	DES_KEY *k;
	// Validate arguments
	if (k1 == NULL || k2 == NULL || k3 == NULL)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(DES_KEY));

	k->k1 = DesNewKeyValue(k1);
	k->k2 = DesNewKeyValue(k2);
	k->k3 = DesNewKeyValue(k3);

	return k;
}

// Create a new DES key element
DES_KEY_VALUE *DesNewKeyValue(void *value)
{
	DES_KEY_VALUE *v;
	// Validate arguments
	if (value == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(DES_KEY_VALUE));

	Copy(v->KeyValue, value, DES_KEY_SIZE);

	v->KeySchedule = ZeroMalloc(sizeof(DES_key_schedule));

	DES_set_key_unchecked(value, v->KeySchedule);

	return v;
}

// Random generation of new DES key element
DES_KEY_VALUE *DesRandKeyValue()
{
	UCHAR key_value[DES_KEY_SIZE];

	DES_random_key((DES_cblock *)key_value);

	return DesNewKeyValue(key_value);
}

// Release of DES key element
void DesFreeKeyValue(DES_KEY_VALUE *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Free(v->KeySchedule);
	Free(v);
}

// Create a new AES key
AES_KEY_VALUE *AesNewKey(void *data, UINT size)
{
	AES_KEY_VALUE *k;
	// Validate arguments
	if (data == NULL || (!(size == 16 || size == 24 || size == 32)))
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(AES_KEY_VALUE));

	k->EncryptKey = ZeroMalloc(sizeof(struct aes_key_st));
	k->DecryptKey = ZeroMalloc(sizeof(struct aes_key_st));

	k->KeySize = size;
	Copy(k->KeyValue, data, size);

	AES_set_encrypt_key(data, size * 8, k->EncryptKey);
	AES_set_decrypt_key(data, size * 8, k->DecryptKey);

	return k;
}

// Release the AES key
void AesFreeKey(AES_KEY_VALUE *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	Free(k->EncryptKey);
	Free(k->DecryptKey);

	Free(k);
}

// AES encryption
void AesEncrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int dest_len = 0;
	int len = 0;
	int ret = 0;

	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	// Create and initialize the context
	ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		return;
	}

	// Disable padding, as it's handled by IkeEncryptWithPadding()
	EVP_CIPHER_CTX_set_padding(ctx, false);

	// Initialize the encryption operation
	switch (k->KeySize)
	{
	case 16:
		ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, k->KeyValue, ivec);
		break;

	case 24:
		ret = EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, k->KeyValue, ivec);
		break;

	case 32:
		ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k->KeyValue, ivec);
		break;
	}

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	// Provide the message to be encrypted and obtain the cipher output
	ret = EVP_EncryptUpdate(ctx, dest, &dest_len, src, size);

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	// Finalize the encryption
	ret = EVP_EncryptFinal_ex(ctx, (unsigned char *) dest + dest_len, &len);

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	dest_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);
}

// AES decryption
void AesDecrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int dest_len = 0;
	int len = 0;
	int ret = 0;

	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	// Create and initialize the context
	ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		return;
	}

	// Disable padding, as it's handled by IkeEncryptWithPadding()
	EVP_CIPHER_CTX_set_padding(ctx, false);

	// Initialize the decryption operation
	switch (k->KeySize)
	{
	case 16:
		ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, k->KeyValue, ivec);
		break;

	case 24:
		ret = EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, k->KeyValue, ivec);
		break;

	case 32:
		ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k->KeyValue, ivec);
		break;
	}

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	// Provide the message to be decrypted and obtain the plaintext output
	ret = EVP_DecryptUpdate(ctx, dest, &dest_len, src, size);

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	// Finalize the decryption
	ret = EVP_DecryptFinal_ex(ctx, (unsigned char *) dest + dest_len, &len);

	if (ret != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	dest_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);
}

// Determine whether the AES-NI instruction set is supported by the CPU
bool IsAesNiSupported()
{
	bool supported = false;

	// Unfortunately OpenSSL doesn't provide a function to do it
#ifdef _MSC_VER
	int regs[4]; // EAX, EBX, ECX, EDX
	__cpuid(regs, 1);
	supported = (regs[2] >> 25) & 1;
#else
	uint32_t eax, ebx, ecx, edx;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);
	supported = (ecx & bit_AES) > 0;
#endif

	return supported;
}

// Calculation of HMAC-SHA-1
void MacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size)
{
	UCHAR key_plus[SHA1_BLOCK_SIZE];
	UCHAR key_plus2[SHA1_BLOCK_SIZE];
	UCHAR key_plus5[SHA1_BLOCK_SIZE];
	UCHAR hash4[SHA1_HASH_SIZE];
	UINT i;
	BUF *buf3;
	BUF *buf6;
	// Validate arguments
	if (dst == NULL || key == NULL || data == NULL)
	{
		return;
	}

	Zero(key_plus, sizeof(key_plus));
	if (key_size <= SHA1_BLOCK_SIZE)
	{
		Copy(key_plus, key, key_size);
	}
	else
	{
		Sha1(key_plus, key, key_size);
	}

	for (i = 0;i < sizeof(key_plus);i++)
	{
		key_plus2[i] = key_plus[i] ^ 0x36;
	}

	buf3 = NewBuf();
	WriteBuf(buf3, key_plus2, sizeof(key_plus2));
	WriteBuf(buf3, data, data_size);

	Sha1(hash4, buf3->Buf, buf3->Size);

	for (i = 0;i < sizeof(key_plus);i++)
	{
		key_plus5[i] = key_plus[i] ^ 0x5c;
	}

	buf6 = NewBuf();
	WriteBuf(buf6, key_plus5, sizeof(key_plus5));
	WriteBuf(buf6, hash4, sizeof(hash4));

	Sha1(dst, buf6->Buf, buf6->Size);

	FreeBuf(buf3);
	FreeBuf(buf6);
}

// DH calculation
bool DhCompute(DH_CTX *dh, void *dst_priv_key, void *src_pub_key, UINT key_size)
{
	int i;
	BIGNUM *bn;
	bool ret = false;
	// Validate arguments
	if (dh == NULL || dst_priv_key == NULL || src_pub_key == NULL)
	{
		return false;
	}
	if (key_size > dh->Size)
	{
		return false;
	}

	bn = BinToBigNum(src_pub_key, key_size);

	i = DH_compute_key(dst_priv_key, bn, dh->dh);

	if (i == dh->Size)
	{
		ret = true;
	}
	else if ((UINT)i < dh->Size)
	{
		UCHAR *dst2 = Clone(dst_priv_key, i);

		Zero(dst_priv_key, dh->Size);

		Copy(((UCHAR *)dst_priv_key) + (dh->Size - i), dst2, i);

		ret = true;
	}

	BN_free(bn);

	return ret;
}

// Creating a DH 2048bit
DH_CTX *DhNew2048()
{
	return DhNew(DH_SET_2048, 2);
}
// Creating a DH 3072bit
DH_CTX *DhNew3072()
{
	return DhNew(DH_SET_3072, 2);
}
// Creating a DH 4096bit
DH_CTX *DhNew4096()
{
	return DhNew(DH_SET_4096, 2);
}

// Creating a DH GROUP1
DH_CTX *DhNewGroup1()
{
	return DhNew(DH_GROUP1_PRIME_768, 2);
}

// Creating a DH GROUP2
DH_CTX *DhNewGroup2()
{
	return DhNew(DH_GROUP2_PRIME_1024, 2);
}

// Creating a DH GROUP5
DH_CTX *DhNewGroup5()
{
	return DhNew(DH_GROUP5_PRIME_1536, 2);
}


// Creating a DH SIMPLE 160bits
DH_CTX *DhNewSimple160()
{
	return DhNew(DH_SIMPLE_160, 2);
}

DH_CTX *DhNewFromBits(UINT bits)
{
	switch (bits)
	{
	case 160:
		return DhNewSimple160();
	case 768:
		return DhNewGroup1();
	case 1024:
		return DhNewGroup2();
	case 1536:
		return DhNewGroup5();
	case 2048:
		return DhNew2048();
	case 3072:
		return DhNew3072();
	case 4096:
		return DhNew4096();
	default:
		return DhNew2048();
	}
}

// Creating a new DH
DH_CTX *DhNew(char *prime, UINT g)
{
	DH_CTX *dh;
	BUF *buf;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BIGNUM *dhp, *dhg;
	const BIGNUM *pub, *priv;
#endif
	// Validate arguments
	if (prime == NULL || g == 0)
	{
		return NULL;
	}

	buf = StrToBin(prime);

	dh = ZeroMalloc(sizeof(DH_CTX));

	dh->dh = DH_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	dhp = BinToBigNum(buf->Buf, buf->Size);
	dhg = BN_new();
	BN_set_word(dhg, g);
	DH_set0_pqg(dh->dh, dhp, NULL, dhg);
#else
	dh->dh->p = BinToBigNum(buf->Buf, buf->Size);
	dh->dh->g = BN_new();
	BN_set_word(dh->dh->g, g);
#endif

	DH_generate_key(dh->dh);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	DH_get0_key(dh->dh, &pub, &priv);
	dh->MyPublicKey = BigNumToBuf(pub);
	dh->MyPrivateKey = BigNumToBuf(priv);
#else
	dh->MyPublicKey = BigNumToBuf(dh->dh->pub_key);
	dh->MyPrivateKey = BigNumToBuf(dh->dh->priv_key);
#endif

	dh->Size = buf->Size;

	FreeBuf(buf);

	return dh;
}

// Release of DH
void DhFree(DH_CTX *dh)
{
	// Validate arguments
	if (dh == NULL)
	{
		return;
	}

	DH_free(dh->dh);

	FreeBuf(dh->MyPrivateKey);
	FreeBuf(dh->MyPublicKey);

	Free(dh);
}

/////////////////////////
// SHA0 implementation //
/////////////////////////
// 
// From: https://bitbucket.org/Polarina/ampheck/src/097585ce2a74/src/
/*
	Copyright (C) 2009  Gabriel A. Petursson
	
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

struct ampheck_sha0
{
	UINT h[5];
	UCHAR buffer[64];
	UINT64 length;
};
#define ROR(x, y) (((x) >> (y)) ^ ((x) << ((sizeof(x) * 8) - (y))))
#define ROL(x, y) (((x) << (y)) ^ ((x) >> ((sizeof(x) * 8) - (y))))
#define UNPACK_32_BE(x, str) { \
	*((str))     = (UCHAR) ((x) >> 24); \
	*((str) + 1) = (UCHAR) ((x) >> 16); \
	*((str) + 2) = (UCHAR) ((x) >>  8); \
	*((str) + 3) = (UCHAR) (x); \
}
#define UNPACK_64_BE(x, str) { \
	*((str))     = (UCHAR) ((x) >> 56); \
	*((str) + 1) = (UCHAR) ((x) >> 48); \
	*((str) + 2) = (UCHAR) ((x) >> 40); \
	*((str) + 3) = (UCHAR) ((x) >> 32); \
	*((str) + 4) = (UCHAR) ((x) >> 24); \
	*((str) + 5) = (UCHAR) ((x) >> 16); \
	*((str) + 6) = (UCHAR) ((x) >>  8); \
	*((str) + 7) = (UCHAR) (x); \
}
#define PACK_32_BE(str, x) { \
	*(x) = ((UINT) *((str)    ) << 24) \
	^ ((UINT) *((str) + 1) << 16) \
	^ ((UINT) *((str) + 2) <<  8) \
	^ ((UINT) *((str) + 3)); \
}
#define PACK_64_BE(str, x) { \
	*(x) = ((UINT64) *((str)    ) << 56) \
	^ ((UINT64) *((str) + 1) << 48) \
	^ ((UINT64) *((str) + 2) << 40) \
	^ ((UINT64) *((str) + 3) << 32) \
	^ ((UINT64) *((str) + 4) << 24) \
	^ ((UINT64) *((str) + 5) << 16) \
	^ ((UINT64) *((str) + 6) << 8) \
	^ ((UINT64) *((str) + 7)); \
}
#define UNPACK_32_LE(x, str) { \
	*((str))     = (UCHAR) (x); \
	*((str) + 1) = (UCHAR) ((x) >>  8); \
	*((str) + 2) = (UCHAR) ((x) >> 16); \
	*((str) + 3) = (UCHAR) ((x) >> 24); \
}
#define UNPACK_64_LE(x, str) { \
	*((str))     = (UCHAR) (x); \
	*((str) + 1) = (UCHAR) ((x) >>  8); \
	*((str) + 2) = (UCHAR) ((x) >> 16); \
	*((str) + 3) = (UCHAR) ((x) >> 24); \
	*((str) + 4) = (UCHAR) ((x) >> 32); \
	*((str) + 5) = (UCHAR) ((x) >> 40); \
	*((str) + 6) = (UCHAR) ((x) >> 48); \
	*((str) + 7) = (UCHAR) ((x) >> 56); \
}
#define PACK_32_LE(str, x) { \
	*(x) = ((UINT) *((str)    )) \
	^ ((UINT) *((str) + 1) <<  8) \
	^ ((UINT) *((str) + 2) << 16) \
	^ ((UINT) *((str) + 3) << 24); \
}
#define PACK_64_LE(str, x) { \
	*(x) = ((UINT64) *((str)    )) \
	^ ((UINT64) *((str) + 1) <<  8) \
	^ ((UINT64) *((str) + 2) << 16) \
	^ ((UINT64) *((str) + 3) << 24) \
	^ ((UINT64) *((str) + 4) << 32) \
	^ ((UINT64) *((str) + 5) << 40) \
	^ ((UINT64) *((str) + 6) << 48) \
	^ ((UINT64) *((str) + 7) << 56); \
}
#define SHA0_R1(x, y, z) ((z ^ (x & (y ^ z)))       + 0x5a827999)
#define SHA0_R2(x, y, z) ((x ^ y ^ z)               + 0x6ed9eba1)
#define SHA0_R3(x, y, z) (((x & y) | (z & (x | y))) + 0x8f1bbcdc)
#define SHA0_R4(x, y, z) ((x ^ y ^ z)               + 0xca62c1d6)
#define SHA0_PRC(a, b, c, d, e, idx, rnd) { \
	wv[e] += ROR(wv[a], 27) + SHA0_R##rnd(wv[b], wv[c], wv[d]) + idx; \
	wv[b]  = ROR(wv[b], 2); \
}
#define SHA0_EXT(i) ( \
	w[i] ^= w[(i - 3) & 0x0F] ^ w[(i - 8) & 0x0F] ^ w[(i - 14) & 0x0F] \
	)
static void ampheck_sha0_init(struct ampheck_sha0 *ctx);
static void ampheck_sha0_update(struct ampheck_sha0 *ctx, const UCHAR *data, UINT length);
static void ampheck_sha0_finish(const struct ampheck_sha0 *ctx, UCHAR *digest);
static void ampheck_sha0_init(struct ampheck_sha0 *ctx)
{
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;

	ctx->length = 0;
}

static void ampheck_sha0_transform(struct ampheck_sha0 *ctx, const UCHAR *data, UINT blocks)
{
	UINT i;
	for (i = 0; i < blocks; ++i)
	{
		UINT wv[5];
		UINT w[16];

		PACK_32_BE(&data[(i << 6)     ], &w[ 0]);
		PACK_32_BE(&data[(i << 6) +  4], &w[ 1]);
		PACK_32_BE(&data[(i << 6) +  8], &w[ 2]);
		PACK_32_BE(&data[(i << 6) + 12], &w[ 3]);
		PACK_32_BE(&data[(i << 6) + 16], &w[ 4]);
		PACK_32_BE(&data[(i << 6) + 20], &w[ 5]);
		PACK_32_BE(&data[(i << 6) + 24], &w[ 6]);
		PACK_32_BE(&data[(i << 6) + 28], &w[ 7]);
		PACK_32_BE(&data[(i << 6) + 32], &w[ 8]);
		PACK_32_BE(&data[(i << 6) + 36], &w[ 9]);
		PACK_32_BE(&data[(i << 6) + 40], &w[10]);
		PACK_32_BE(&data[(i << 6) + 44], &w[11]);
		PACK_32_BE(&data[(i << 6) + 48], &w[12]);
		PACK_32_BE(&data[(i << 6) + 52], &w[13]);
		PACK_32_BE(&data[(i << 6) + 56], &w[14]);
		PACK_32_BE(&data[(i << 6) + 60], &w[15]);

		wv[0] = ctx->h[0];
		wv[1] = ctx->h[1];
		wv[2] = ctx->h[2];
		wv[3] = ctx->h[3];
		wv[4] = ctx->h[4];

		SHA0_PRC(0, 1, 2, 3, 4, w[ 0], 1);
		SHA0_PRC(4, 0, 1, 2, 3, w[ 1], 1);
		SHA0_PRC(3, 4, 0, 1, 2, w[ 2], 1);
		SHA0_PRC(2, 3, 4, 0, 1, w[ 3], 1);
		SHA0_PRC(1, 2, 3, 4, 0, w[ 4], 1);
		SHA0_PRC(0, 1, 2, 3, 4, w[ 5], 1);
		SHA0_PRC(4, 0, 1, 2, 3, w[ 6], 1);
		SHA0_PRC(3, 4, 0, 1, 2, w[ 7], 1);
		SHA0_PRC(2, 3, 4, 0, 1, w[ 8], 1);
		SHA0_PRC(1, 2, 3, 4, 0, w[ 9], 1);
		SHA0_PRC(0, 1, 2, 3, 4, w[10], 1);
		SHA0_PRC(4, 0, 1, 2, 3, w[11], 1);
		SHA0_PRC(3, 4, 0, 1, 2, w[12], 1);
		SHA0_PRC(2, 3, 4, 0, 1, w[13], 1);
		SHA0_PRC(1, 2, 3, 4, 0, w[14], 1);
		SHA0_PRC(0, 1, 2, 3, 4, w[15], 1);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 0), 1);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 1), 1);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 2), 1);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 3), 1);

		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 4), 2);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 5), 2);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 6), 2);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 7), 2);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 8), 2);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 9), 2);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT(10), 2);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT(11), 2);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT(12), 2);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT(13), 2);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT(14), 2);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT(15), 2);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 0), 2);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 1), 2);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 2), 2);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 3), 2);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 4), 2);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 5), 2);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 6), 2);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 7), 2);

		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 8), 3);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 9), 3);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT(10), 3);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT(11), 3);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT(12), 3);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT(13), 3);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT(14), 3);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT(15), 3);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 0), 3);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 1), 3);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 2), 3);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 3), 3);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 4), 3);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 5), 3);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 6), 3);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 7), 3);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 8), 3);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 9), 3);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT(10), 3);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT(11), 3);

		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT(12), 4);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT(13), 4);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT(14), 4);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT(15), 4);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 0), 4);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 1), 4);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 2), 4);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 3), 4);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 4), 4);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT( 5), 4);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT( 6), 4);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT( 7), 4);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT( 8), 4);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT( 9), 4);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT(10), 4);
		SHA0_PRC(0, 1, 2, 3, 4, SHA0_EXT(11), 4);
		SHA0_PRC(4, 0, 1, 2, 3, SHA0_EXT(12), 4);
		SHA0_PRC(3, 4, 0, 1, 2, SHA0_EXT(13), 4);
		SHA0_PRC(2, 3, 4, 0, 1, SHA0_EXT(14), 4);
		SHA0_PRC(1, 2, 3, 4, 0, SHA0_EXT(15), 4);

		ctx->h[0] += wv[0];
		ctx->h[1] += wv[1];
		ctx->h[2] += wv[2];
		ctx->h[3] += wv[3];
		ctx->h[4] += wv[4];
	}
}

static void ampheck_sha0_update(struct ampheck_sha0 *ctx, const UCHAR *data, UINT size)
{
	UINT tmp = size;

	if (size >= 64 - ctx->length % 64)
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, 64 - ctx->length % 64);

		data += 64 - ctx->length % 64;
		size -= 64 - ctx->length % 64;

		ampheck_sha0_transform(ctx, ctx->buffer, 1);
		ampheck_sha0_transform(ctx, data, size / 64);

		data += size & ~63;
		size %= 64;

		memcpy(ctx->buffer, data, size);
	}
	else
	{
		memcpy(&ctx->buffer[ctx->length % 64], data, size);
	}

	ctx->length += tmp;
}

static void ampheck_sha0_finish(const struct ampheck_sha0 *ctx, UCHAR *digest)
{
	struct ampheck_sha0 tmp;

	memcpy(tmp.h, ctx->h, 5 * sizeof(UINT));
	memcpy(tmp.buffer, ctx->buffer, ctx->length % 64);

	tmp.buffer[ctx->length % 64] = 0x80;

	if (ctx->length % 64 < 56)
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 55 - ctx->length % 64);
	}
	else
	{
		memset(&tmp.buffer[ctx->length % 64 + 1], 0x00, 63 - ctx->length % 64);
		ampheck_sha0_transform(&tmp, tmp.buffer, 1);

		memset(tmp.buffer, 0x00, 56);
	}

	UNPACK_64_BE(ctx->length * 8, &tmp.buffer[56]);
	ampheck_sha0_transform(&tmp, tmp.buffer, 1);

	UNPACK_32_BE(tmp.h[0], &digest[ 0]);
	UNPACK_32_BE(tmp.h[1], &digest[ 4]);
	UNPACK_32_BE(tmp.h[2], &digest[ 8]);
	UNPACK_32_BE(tmp.h[3], &digest[12]);
	UNPACK_32_BE(tmp.h[4], &digest[16]);
}
static unsigned char *Internal_SHA0(const unsigned char *d, size_t n, unsigned char *md)
{
	struct ampheck_sha0 c;
	static unsigned char m[SHA_DIGEST_LENGTH];

	if (md == NULL) md=m;

	ampheck_sha0_init(&c);
	ampheck_sha0_update(&c, d, (UINT)n);
	ampheck_sha0_finish(&c, md);

	return md;
}


int GetSslClientCertIndex()
{
	return ssl_clientcert_index;
}


