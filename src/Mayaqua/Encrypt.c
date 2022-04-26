// SoftEther VPN Source Code - Stable Edition Repository
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
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
#include <openssl/ocsp.h>
#include <openssl/ocsperr.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif // OPENSSL_VERSION_NUMBER

#include <Mayaqua/Mayaqua.h>

#ifdef	USE_INTEL_AESNI_LIBRARY
#include <intelaes/iaesni.h>
#endif	// USE_INTEL_AESNI_LIBRARY

LOCK *openssl_lock = NULL;

int ssl_clientcert_index = 0;

LOCK **ssl_lock_obj = NULL;
UINT ssl_lock_num;
static bool openssl_inited = false;
static bool is_intel_aes_supported = false;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER* ossl_provider_legacy = NULL;
static OSSL_PROVIDER* ossl_provider_default = NULL;
#endif

static unsigned char *Internal_SHA0(const unsigned char *d, size_t n, unsigned char *md);

// For the callback function
typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;


LIST* BufToXList(BUF* b)
{
	LIST* ret;
	UINT mode = 0;
	BUF* current_buf;
	if (b == NULL)
	{
		return NULL;
	}

	SeekBufToBegin(b);

	ret = NewList(NULL);

	current_buf = NewBuf();

	while (true)
	{
		char* line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		if (mode == 0 && StrCmpi(line, "-----BEGIN CERTIFICATE-----") == 0)
		{
			mode = 1;
			WriteBuf(current_buf, line, StrLen(line));
			WriteBuf(current_buf, "\n", 1);
		}
		else if (mode == 1)
		{
			if (StrCmpi(line, "-----END CERTIFICATE-----") == 0)
			{
				mode = 0;
			}
			WriteBuf(current_buf, line, StrLen(line));
			WriteBuf(current_buf, "\n", 1);

			if (mode == 0)
			{
				X* x = BufToX(current_buf, true);
				if (x != NULL)
				{
					Add(ret, x);
				}

				FreeBuf(current_buf);
				current_buf = NewBuf();
			}
		}

		Free(line);
	}

	FreeBuf(current_buf);

	if (LIST_NUM(ret) == 0)
	{
		ReleaseList(ret);
		return NULL;
	}

	return ret;
}

void FreeXList(LIST* o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X* x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

bool CheckCertsAndKey(CERTS_AND_KEY* c)
{
	X* x;
	K* k;
	if (c == NULL)
	{
		return false;
	}
	if (LIST_NUM(c->CertList) == 0)
	{
		return false;
	}

	x = LIST_DATA(c->CertList, 0);
	k = c->Key;

	return CheckXandK(x, k);
}

bool CertsAndKeyAlwaysUseCallback(char* sni_name, void* param)
{
	return true;
}

CERTS_AND_KEY* CloneCertsAndKey(CERTS_AND_KEY* c)
{
	CERTS_AND_KEY* ret;
	if (c == NULL)
	{
		return NULL;
	}

	ret = NewCertsAndKeyFromObjects(c->CertList, c->Key, false);

	return ret;
}

UINT64 GetCertsAndKeyListHash(LIST* o)
{
	UINT i;
	UINT64 ret = 0;
	if (o == NULL)
	{
		return 0;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CERTS_AND_KEY* c = LIST_DATA(o, i);

		UINT64 hash = GetCertsAndKeyHash(c);

		ret += hash;

		ret *= GOLDEN_PRIME_NUMBER;
	}

	if (ret == 0) ret = 1;

	return ret;
}

void FreeCertsAndKeyList(LIST* o)
{
	UINT i;

	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CERTS_AND_KEY* s = LIST_DATA(o, i);

		ReleaseCertsAndKey(s);
	}

	ReleaseList(o);
}

LIST* CloneCertsAndKeyList(LIST* o)
{
	LIST* ret;
	UINT i;

	if (o == NULL)
	{
		return NULL;
	}

	ret = NewList(NULL);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CERTS_AND_KEY* s = LIST_DATA(o, i);

		if (s != NULL)
		{
			CERTS_AND_KEY* d = s;

			AddRef(d->Ref);

			Add(ret, d);
		}
	}

	return ret;
}

UINT64 GetCertsAndKeyHash(CERTS_AND_KEY* c)
{
	UINT64 ret;

	if (c == NULL)
	{
		return 0;
	}

	ret = c->HashCache;

	ret += (UINT64)c->DetermineUseCallback;

	if (ret == 0) ret = 1;

	return ret;
}

UINT64 CalcCertsAndKeyHashCache(CERTS_AND_KEY* c)
{
	BUF* buf;
	UINT i;
	BUF *key_buf;
	UCHAR hash[SHA1_SIZE] = CLEAN;
	UINT64 ret;

	if (c == NULL)
	{
		return 0;
	}

	buf = NewBuf();

	for (i = 0;i < LIST_NUM(c->CertList);i++)
	{
		X* x = LIST_DATA(c->CertList, i);
		UCHAR sha1[SHA1_SIZE] = CLEAN;

		GetXDigest(x, sha1, true);

		WriteBuf(buf, sha1, SHA1_SIZE);
	}

	key_buf = KToBuf(c->Key, true, NULL);

	WriteBufBuf(buf, key_buf);

	FreeBuf(key_buf);

	HashSha1(hash, buf->Buf, buf->Size);

	FreeBuf(buf);

	ret = READ_UINT64(hash);

	if (ret == 0) ret = 1;

	return ret;
}

void UpdateCertsAndKeyHashCacheAndCheckedState(CERTS_AND_KEY* c)
{
	if (c == NULL)
	{
		return;
	}

	c->HashCache = CalcCertsAndKeyHashCache(c);
	c->HasValidPrivateKey = CheckCertsAndKey(c);
}

CERTS_AND_KEY* NewCertsAndKeyFromDir(wchar_t* dir_name)
{
	CERTS_AND_KEY* ret = NULL;
	BUF* key_buf = NULL;
	wchar_t key_fn[MAX_PATH] = CLEAN;
	UINT i;

	if (dir_name == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CERTS_AND_KEY));

	ret->Ref = NewRef();

	ret->CertList = NewListFast(NULL);

	CombinePathW(key_fn, sizeof(key_fn), dir_name, L"cert.key");
	key_buf = ReadDumpW(key_fn);

	ret->Key = BufToK(key_buf, true, true, NULL);
	if (ret->Key == NULL)
	{
		goto L_ERROR;
	}

	for (i = 0;;i++)
	{
		wchar_t cert_fn[MAX_PATH] = CLEAN;
		wchar_t tmp[MAX_PATH] = CLEAN;
		BUF* cert_buf;
		X* x;

		UniFormat(tmp, sizeof(tmp), L"cert_%04u.cer", i);
		CombinePathW(cert_fn, sizeof(cert_fn), dir_name, tmp);

		cert_buf = ReadDumpW(cert_fn);
		if (cert_buf == NULL)
		{
			break;
		}

		x = BufToX(cert_buf, true);

		if (x != NULL)
		{
			Add(ret->CertList, x);
		}

		FreeBuf(cert_buf);
	}

	if (LIST_NUM(ret->CertList) == 0)
	{
		goto L_ERROR;
	}

	FreeBuf(key_buf);

	UpdateCertsAndKeyHashCacheAndCheckedState(ret);

	return ret;

L_ERROR:
	ReleaseCertsAndKey(ret);
	FreeBuf(key_buf);
	return NULL;
}

bool SaveCertsAndKeyToDir(CERTS_AND_KEY* c, wchar_t* dir)
{
	wchar_t tmp[MAX_PATH] = CLEAN;
	wchar_t tmp2[MAX_PATH] = CLEAN;
	bool ret = true;
	LIST* filename_list;
	UINT count;

	if (c == NULL || dir == NULL)
	{
		return false;
	}

	filename_list = NewList(NULL);

	MakeDirExW(dir);

	// サーバーから受信した証明書情報の websocket_certs_cache ディレクトリへの書き込み
	count = LIST_NUM(c->CertList);

	if (count >= 1)
	{
		BUF* key_buf = KToBuf(c->Key, true, NULL);
		if (key_buf != NULL && key_buf->Size >= 1)
		{
			UINT i;
			for (i = 0;i < count;i++)
			{
				X* x = LIST_DATA(c->CertList, i);
				if (x != NULL)
				{
					BUF* cert_buf = XToBuf(x, true);
					if (cert_buf != NULL)
					{
						UniFormat(tmp2, sizeof(tmp2), L"cert_%04u.cer", i);
						CombinePathW(tmp, sizeof(tmp), dir, tmp2);

						if (DumpBufWIfNecessary(cert_buf, tmp) == false)
						{
							ret = false;
						}

						AddUniStrToUniStrList(filename_list, tmp2);
					}
					FreeBuf(cert_buf);
				}
			}

			CombinePathW(tmp, sizeof(tmp), dir, L"cert.key");
			if (DumpBufWIfNecessary(key_buf, tmp) == false)
			{
				ret = false;
			}
		}
		FreeBuf(key_buf);
	}
	else
	{
		ret = false;
	}

	// websocket_certs_cache ディレクトリにある不要ファイルの削除
	if (LIST_NUM(filename_list) >= 1)
	{
		DIRLIST* dirlist = EnumDirW(dir);

		if (dirlist != NULL)
		{
			UINT i;
			for (i = 0;i < dirlist->NumFiles;i++)
			{
				DIRENT* f = dirlist->File[i];

				if (UniStartWith(f->FileNameW, L"cert_") && UniEndWith(f->FileNameW, L".cer"))
				{
					if (IsInListUniStr(filename_list, f->FileNameW) == false)
					{
						CombinePathW(tmp, sizeof(tmp), dir, f->FileNameW);
						FileDeleteW(tmp);
					}
				}
			}
		}

		FreeDir(dirlist);
	}

	FreeStrList(filename_list);

	return ret;
}

CERTS_AND_KEY* NewCertsAndKeyFromObjectSingle(X* cert, K* key, bool fast)
{
	LIST* cert_list;
	CERTS_AND_KEY* ret;
	if (cert == NULL || key == NULL)
	{
		return NULL;
	}

	cert_list = NewList(NULL);
	Add(cert_list, cert);

	ret = NewCertsAndKeyFromObjects(cert_list, key, fast);

	ReleaseList(cert_list);

	return ret;
}

CERTS_AND_KEY* NewCertsAndKeyFromObjects(LIST* cert_list, K* key, bool fast)
{
	UINT i;
	UINT64 fast_hash = 1;
	CERTS_AND_KEY* ret = NULL;
	if (cert_list == NULL || LIST_NUM(cert_list) == 0 || key == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CERTS_AND_KEY));

	ret->Ref = NewRef();

	ret->CertList = NewListFast(NULL);

	if (fast == false)
	{
		ret->Key = CloneK(key);
	}
	else
	{
		ret->Key = CloneKFast(key);

		fast_hash += (UINT64)(key->pkey);
		fast_hash *= GOLDEN_PRIME_NUMBER;
	}

	if (ret->Key == NULL) goto L_ERROR;

	for (i = 0;i < LIST_NUM(cert_list);i++)
	{
		X* clone_x;
		X* x = LIST_DATA(cert_list, i);
		if (x == NULL) goto L_ERROR;

		if (fast == false)
		{
			clone_x = CloneX(x);
		}
		else
		{
			clone_x = CloneXFast(x);
			fast_hash += (UINT64)(x->x509);
			fast_hash *= GOLDEN_PRIME_NUMBER;
		}

		Add(ret->CertList, clone_x);
	}

	if (fast == false)
	{
		UpdateCertsAndKeyHashCacheAndCheckedState(ret);
	}
	else
	{
		ret->HashCache = fast_hash;
		ret->HasValidPrivateKey = true;
	}

	return ret;

L_ERROR:
	ReleaseCertsAndKey(ret);
	return NULL;
}

CERTS_AND_KEY* NewCertsAndKeyFromMemory(LIST* cert_buf_list, BUF* key_buf)
{
	UINT i;
	CERTS_AND_KEY* ret = NULL;
	if (cert_buf_list == NULL || LIST_NUM(cert_buf_list) == 0 || key_buf == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CERTS_AND_KEY));

	ret->Ref = NewRef();

	ret->CertList = NewListFast(NULL);

	ret->Key = BufToK(key_buf, true, true, NULL);
	if (ret->Key == NULL) goto L_ERROR;

	for (i = 0;i < LIST_NUM(cert_buf_list);i++)
	{
		BUF* b = LIST_DATA(cert_buf_list, i);

		X* x = BufToX(b, true);
		if (x == NULL) goto L_ERROR;

		Add(ret->CertList, x);
	}

	UpdateCertsAndKeyHashCacheAndCheckedState(ret);

	return ret;

L_ERROR:
	ReleaseCertsAndKey(ret);
	return NULL;
}

void ReleaseCertsAndKey(CERTS_AND_KEY* c)
{
	if (c == NULL)
	{
		return;
	}

	if (Release(c->Ref) == 0)
	{
		CleanupCertsAndKey(c);
	}
}

void CleanupCertsAndKey(CERTS_AND_KEY* c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(c->CertList);i++)
	{
		X* x = LIST_DATA(c->CertList, i);

		FreeX(x);
	}

	FreeK(c->Key);

	ReleaseList(c->CertList);

	Free(c);
}

// 証明書が特定のディレクトリの CRL によって無効化されているかどうか確認する
bool IsXRevoked(X *x)
{
	char dirname[MAX_PATH];
	UINT i;
	bool ret = false;
	DIRLIST *t;
	// 引数チェック
	if (x == NULL)
	{
		return false;
	}

	GetExeDir(dirname, sizeof(dirname));

	// CRL ファイルの検索
	t = EnumDir(dirname);

	for (i = 0;i < t->NumFiles;i++)
	{
		char *name = t->File[i]->FileName;
		if (t->File[i]->Folder == false)
		{
			if (EndWith(name, ".crl"))
			{
				char filename[MAX_PATH];
				X_CRL *r;

				ConbinePath(filename, sizeof(filename), dirname, name);

				r = FileToXCrl(filename);

				if (r != NULL)
				{
					if (IsXRevokedByXCrl(x, r))
					{
						ret = true;
					}

					FreeXCrl(r);
				}
			}
		}
	}

	FreeDir(t);

	return ret;
}

// 証明書が CRL によって無効化されているかどうか確認する
bool IsXRevokedByXCrl(X *x, X_CRL *r)
{
	// 手抜きさん
	return false;
}

// CRL の解放
void FreeXCrl(X_CRL *r)
{
	// 引数チェック
	if (r == NULL)
	{
		return;
	}

	X509_CRL_free(r->Crl);

	Free(r);
}

// ファイルを CRL に変換
X_CRL *FileToXCrl(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	X_CRL *ret = FileToXCrlW(filename_w);

	Free(filename_w);

	return ret;
}
X_CRL *FileToXCrlW(wchar_t *filename)
{
	BUF *b;
	X_CRL *r;
	// 引数チェック
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	r = BufToXCrl(b);

	FreeBuf(b);

	return r;
}

// バッファを CRL に変換
X_CRL *BufToXCrl(BUF *b)
{
	X_CRL *r;
	X509_CRL *x509crl;
	BIO *bio;
	// 引数チェック
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	x509crl	= NULL;

	if (d2i_X509_CRL_bio(bio, &x509crl) == NULL || x509crl == NULL)
	{
		FreeBio(bio);
		return NULL;
	}

	r = ZeroMalloc(sizeof(X_CRL));
	r->Crl = x509crl;

	FreeBio(bio);

	return r;
}

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

// Easy encryption
BUF *EasyEncrypt(BUF *src_buf)
{
	UCHAR key[SHA1_SIZE];
	BUF *tmp_data;
	CRYPT *rc4;
	BUF *ret;
	// Validate arguments
	if (src_buf == NULL)
	{
		return NULL;
	}

	Rand(key, SHA1_SIZE);

	tmp_data = CloneBuf(src_buf);

	rc4 = NewCrypt(key, SHA1_SIZE);

	Encrypt(rc4, tmp_data->Buf, tmp_data->Buf, tmp_data->Size);

	ret = NewBuf();

	WriteBuf(ret, key, SHA1_SIZE);
	WriteBufBuf(ret, tmp_data);

	FreeCrypt(rc4);
	FreeBuf(tmp_data);

	SeekBufToBegin(ret);

	return ret;
}

// Easy decryption
BUF *EasyDecrypt(BUF *src_buf)
{
	UCHAR key[SHA1_SIZE];
	BUF *tmp_buf;
	CRYPT *rc4;
	// Validate arguments
	if (src_buf == NULL)
	{
		return NULL;
	}

	SeekBufToBegin(src_buf);

	if (ReadBuf(src_buf, key, SHA1_SIZE) != SHA1_SIZE)
	{
		return NULL;
	}

	tmp_buf = ReadRemainBuf(src_buf);
	if (tmp_buf == NULL)
	{
		return NULL;
	}

	rc4 = NewCrypt(key, SHA1_SIZE);
	Encrypt(rc4, tmp_buf->Buf, tmp_buf->Buf, tmp_buf->Size);
	FreeCrypt(rc4);

	SeekBufToBegin(tmp_buf);

	return tmp_buf;
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

// Convert the buffer to the public key
K *RsaBinToPublic(void *data, UINT size)
{
	RSA *rsa;
	K *k;
	BIO *bio;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BIGNUM *e, *n;
#endif
	// Validate arguments
	if (data == NULL || size < 4)
	{
		return NULL;
	}

	rsa = RSA_new();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	e = BN_new();
	BN_set_word(e, RSA_F4);

	n = BinToBigNum(data, size);

	RSA_set0_key(rsa, n, e, NULL);
#else
	if (rsa->e != NULL)
	{
		BN_free(rsa->e);
	}

	rsa->e = BN_new();
	BN_set_word(rsa->e, RSA_F4);

	if (rsa->n != NULL)
	{
		BN_free(rsa->n);
	}

	rsa->n = BinToBigNum(data, size);
#endif

	bio = NewBio();
	LockOpenSSL();
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	UnlockOpenSSL();
	BIO_seek(bio, 0);
	k = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	return k;
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
	rsa = (RSA*)EVP_PKEY_get0_RSA(k->pkey);
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

// Convert the public key to a binary
void RsaPublicToBin(K *k, void *data)
{
	BUF *b;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	b = RsaPublicToBuf(k);
	if (b == NULL)
	{
		return;
	}

	Copy(data, b->Buf, b->Size);

	FreeBuf(b);
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

// Stupid test
void CertTest2()
{
}

// Yagi test
void CertTest()
{
}

// Test function related to certificate
void CertTest_()
{
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

// Convert a BIGNUM to a string
char *BigNumToStr(BIGNUM *bn)
{
	BIO *bio;
	BUF *b;
	char *ret;
	// Validate arguments
	if (bn == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	BN_print(bio, bn);

	b = BioToBuf(bio);

	FreeBio(bio);

	ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);
	FreeBuf(b);

	return ret;
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

// Convert the buffer to a BIGNUM
BIGNUM *BufToBigNum(BUF *b)
{
	if (b == NULL)
	{
		return NULL;
	}

	return BinToBigNum(b->Buf, b->Size);
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
void GetAllNameFromXExA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromXEx(tmp, sizeof(tmp), x);

	UniToStr(str, size, tmp);
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
void GetAllNameFromA(char *str, UINT size, X *x)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromX(tmp, sizeof(tmp), x);
	UniToStr(str, size, tmp);
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

K* CloneKFast(K* k)
{
	K* ret;
	// Validate arguments
	if (k == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(K));

	ret->private_key = k->private_key;
	ret->pkey = k->pkey;

	if (ret->pkey != NULL)
	{
		EVP_PKEY_up_ref(ret->pkey);
	}

	return ret;
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

X* CloneXFast(X* x)
{
	X* ret;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(X));

	ret->issuer_name = CopyName(x->issuer_name);
	ret->subject_name = CopyName(x->subject_name);
	ret->root_cert = x->root_cert;
	ret->notBefore = x->notBefore;
	ret->notAfter = x->notAfter;
	ret->serial = CloneXSerial(x->serial);
	ret->do_not_free = false;
	ret->is_compatible_bit = x->is_compatible_bit;
	ret->bits = x->bits;
	ret->has_basic_constraints = x->has_basic_constraints;
	StrCpy(ret->issuer_url, sizeof(ret->issuer_url), x->issuer_url);

	ret->x509 = x->x509;

	if (ret->x509 != NULL)
	{
		X509_up_ref(ret->x509);
	}

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

	LockOpenSSL();
	{
		pkcs12 = PKCS12_create(password, NULL, k->pkey, x->x509, NULL, 0, 0, 0, 0, 0);
		if (pkcs12 == NULL)
		{
			UnlockOpenSSL();
			return NULL;
		}
	}
	UnlockOpenSSL();

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
	LockOpenSSL();
	{
		if (PKCS12_verify_mac(p12->pkcs12, password, -1) == false &&
			PKCS12_verify_mac(p12->pkcs12, NULL, -1) == false)
		{
			UnlockOpenSSL();
			return false;
		}
	}
	UnlockOpenSSL();

	// Extraction
	LockOpenSSL();
	{
		if (PKCS12_parse(p12->pkcs12, password, &pkey, &x509, NULL) == false)
		{
			if (PKCS12_parse(p12->pkcs12, NULL, &pkey, &x509, NULL) == false)
			{
				UnlockOpenSSL();
				return false;
			}
		}
	}
	UnlockOpenSSL();

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
bool P12ToFile(P12 *p12, char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = P12ToFileW(p12, filename_w);

	return ret;
}
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
P12 *FileToP12(char *filename)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	P12 *ret = FileToP12W(filename_w);

	Free(filename_w);

	return ret;
}
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
	LockOpenSSL();
	{
		i2d_PKCS12_bio(bio, p12->pkcs12);
	}
	UnlockOpenSSL();

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
	LockOpenSSL();
	{
		pkcs12 = d2i_PKCS12_bio(bio, NULL);
	}
	UnlockOpenSSL();
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

// Convert a binary to a string
char *ByteToStr(BYTE *src, UINT src_size)
{
	UINT size;
	char *dst;
	UINT i;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	size = MAX(src_size * 3, 1);
	dst = Malloc(size);
	dst[size - 1] = 0;
	for (i = 0;i < src_size;i++)
	{
		char tmp[3];
		Format(tmp, sizeof(tmp), "%02x", src[i]);
		dst[i * 3 + 0] = tmp[0];
		dst[i * 3 + 1] = tmp[1];
		dst[i * 3 + 2] = ((i == (src_size - 1) ? 0 : ' '));
	}

	return dst;
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
	return NewXEx(pub, priv, ca, name, days, serial, NULL);
}
X *NewXEx(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial, NAME *name_issuer)
{
	X509 *x509;
	X *x;
	// Validate arguments
	if (pub == NULL || priv == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}

	x509 = NewX509Ex(pub, priv, ca, name, days, serial, name_issuer);
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
	return NewX509Ex(pub, priv, ca, name, days, serial, NULL);
}
X509 *NewX509Ex(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial, NAME *name_issuer)
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
	if (name_issuer == NULL)
	{
		issuer_name = X509_get_subject_name(ca->x509);
	}
	else
	{
		issuer_name = NameToX509Name(name_issuer);
	}

	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);

	if (name_issuer != NULL)
	{
		FreeX509Name(issuer_name);
	}

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

	LockOpenSSL();
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	UnlockOpenSSL();

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

	LockOpenSSL();
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	UnlockOpenSSL();

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
	LockOpenSSL();
	{
		X509_NAME_add_entry_by_NID(x509_name, nid, encoding_type, utf8, utf8_size, -1, 0);
	}
	UnlockOpenSSL();
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

	if (t->length == 15)
	{
		// YYYYMMDDHHMMSSZ
		t->type = V_ASN1_GENERALIZEDTIME;
	}
	else
	{
		// YYMMDDHHMMSSZ
		t->type = V_ASN1_UTCTIME;
	}
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

	if (s->wYear <= 2049)
	{
		// 2000 to 2049: Use YYMMDDHHMMSSZ
		Format(str, size, "%02u%02u%02u%02u%02u%02uZ",
			s->wYear % 100, s->wMonth, s->wDay,
			s->wHour, s->wMinute, s->wSecond);
	}
	else
	{
		// 2050 to 9999: Use YYYYMMDDHHMMSSZ
		Format(str, size, "%04u%02u%02u%02u%02u%02uZ",
			s->wYear, s->wMonth, s->wDay,
			s->wHour, s->wMinute, s->wSecond);
	}

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
		if (StrLen(str) != 15) return false;

		//Year has 4 digits - save first two and use the rest
		//as if it had two digits
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
		if( fourdigityear ) {
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
	UCHAR *decrypt_data;
	RSA *rsa;
	// Validate arguments
	if (data == NULL || sign == NULL || k == NULL || k->private_key != false)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = 1024;
	}

	rsa = (RSA*)EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
	{
		return false;
	}

	decrypt_data = ZeroMalloc(RSA_size(rsa));

	// Hash the data
	if (HashForSign(hash_data, sizeof(hash_data), data, data_size) == false)
	{
		Free(decrypt_data);
		return false;
	}

	// Decode the signature
	if (RSA_public_decrypt(bits / 8, sign, decrypt_data, rsa, RSA_PKCS1_PADDING) <= 0)
	{
		Free(decrypt_data);
		return false;
	}

	// Comparison
	if (Cmp(decrypt_data, hash_data, SIGN_HASH_SIZE) != 0)
	{
		Free(decrypt_data);
		return false;
	}

	Free(decrypt_data);

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
	if (RSA_private_encrypt(sizeof(hash), hash, dst, (RSA*)EVP_PKEY_get0_RSA(k->pkey), RSA_PKCS1_PADDING) <= 0)
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

// Decrypt with the RSA public key
bool RsaPublicDecrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// Validate arguments
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	LockOpenSSL();
	{
		ret = RSA_public_decrypt(size, src, tmp, (RSA *)EVP_PKEY_get0_RSA(k->pkey), RSA_NO_PADDING);
	}
	UnlockOpenSSL();
	if (ret <= 0)
	{
/*		Debug("RSA Error: 0x%x\n",
			ERR_get_error());
*/		Free(tmp);
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// Encrypt with the RSA private key
bool RsaPrivateEncrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// Validate arguments
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	LockOpenSSL();
	{
		ret = RSA_private_encrypt(size, src, tmp, (RSA *)EVP_PKEY_get0_RSA(k->pkey), RSA_NO_PADDING);
	}
	UnlockOpenSSL();
	if (ret <= 0)
	{
		Debug("RSA Error: %u\n",
			ERR_GET_REASON(ERR_get_error()));
		Free(tmp);
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// Decrypt with the RSA private key
bool RsaPrivateDecrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// Validate arguments
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	LockOpenSSL();
	{
		ret = RSA_private_decrypt(size, src, tmp, (RSA *)EVP_PKEY_get0_RSA(k->pkey), RSA_NO_PADDING);
	}
	UnlockOpenSSL();
	if (ret <= 0)
	{
		Free(tmp);
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

	return true;
}

// Encrypt with the RSA public key
bool RsaPublicEncrypt(void *dst, void *src, UINT size, K *k)
{
	void *tmp;
	int ret;
	// Validate arguments
	if (src == NULL || size == 0 || k == NULL)
	{
		return false;
	}

	tmp = ZeroMalloc(size);
	LockOpenSSL();
	{
		ret = RSA_public_encrypt(size, src, tmp, (RSA*)EVP_PKEY_get0_RSA(k->pkey), RSA_NO_PADDING);
	}
	UnlockOpenSSL();
	if (ret <= 0)
	{
		return false;
	}

	Copy(dst, tmp, size);
	Free(tmp);

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
	UINT bit = 1024;
	// Validate arguments

	// Key generation
	LockOpenSSL();
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	UnlockOpenSSL();
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// Secret key
	bio = NewBio();
	LockOpenSSL();
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	UnlockOpenSSL();
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
	LockOpenSSL();
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	UnlockOpenSSL();
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
	LockOpenSSL();
	{
		rsa = RSA_generate_key(bit, RSA_F4, NULL, NULL);
	}
	UnlockOpenSSL();
	if (rsa == NULL)
	{
		Debug("RSA_generate_key: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	// Secret key
	bio = NewBio();
	LockOpenSSL();
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	UnlockOpenSSL();
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
	LockOpenSSL();
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	UnlockOpenSSL();
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
bool CheckX(X *x, X *x_issuer)
{
	return CheckXEx(x, x_issuer, false, false);
}
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

	LockOpenSSL();
	{
		if (X509_verify(x->x509, k->pkey) == 0)
		{
			UnlockOpenSSL();
			return false;
		}
	}
	UnlockOpenSSL();
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

	LockOpenSSL();
	{
		pkey = X509_get_pubkey(x->x509);
	}
	UnlockOpenSSL();
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

	LockOpenSSL();
	if (X509_cmp(x1->x509, x2->x509) == 0)
	{
		UnlockOpenSSL();
		return true;
	}
	else
	{
		UnlockOpenSSL();
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

	LockOpenSSL();
	if (X509_check_private_key(x->x509, k->pkey) != 0)
	{
		UnlockOpenSSL();
		return true;
	}
	else
	{
		UnlockOpenSSL();
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
K *FileToK(char *filename, bool private_key, char *password)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	K *ret;

	ret = FileToKW(filename_w, private_key, password);

	Free(filename_w);

	return ret;
}
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
bool KToFile(K *k, char *filename, bool text, char *password)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret = KToFileW(k, filename_w, text, password);

	Free(filename_w);

	return ret;
}
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
			LockOpenSSL();
			{
				i2d_PrivateKey_bio(bio, k->pkey);
			}
			UnlockOpenSSL();
		}
		else
		{
			// Text format
			if (password == 0 || StrLen(password) == 0)
			{
				// No encryption
				LockOpenSSL();
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
				}
				UnlockOpenSSL();
			}
			else
			{
				// Encrypt
				CB_PARAM cb;
				cb.password = password;
				LockOpenSSL();
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
						NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
				}
				UnlockOpenSSL();
			}
		}
	}
	else
	{
		// Public key
		if (text == false)
		{
			// Binary format
			LockOpenSSL();
			{
				i2d_PUBKEY_bio(bio, k->pkey);
			}
			UnlockOpenSSL();
		}
		else
		{
			// Text format
			LockOpenSSL();
			{
				PEM_write_bio_PUBKEY(bio, k->pkey);
			}
			UnlockOpenSSL();
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
			LockOpenSSL();
			{
				pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			UnlockOpenSSL();
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
			LockOpenSSL();
			{
				pkey = d2i_PrivateKey_bio(bio, NULL);
			}
			UnlockOpenSSL();
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
			LockOpenSSL();
			{
				pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			UnlockOpenSSL();
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

	LockOpenSSL();
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
	UnlockOpenSSL();

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

	LockOpenSSL();
	{
		X509_free(x509);
	}
	UnlockOpenSSL();
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

// Create a new buffer by skipping the contents of the buffer to the specified string
BUF *SkipBufBeforeString(BUF *b, char *str)
{
	char *tmp;
	UINT tmp_size;
	BUF *ret;
	UINT i;
	UINT offset = 0;
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return NULL;
	}

	tmp_size = b->Size + 1;
	tmp = ZeroMalloc(tmp_size);
	Copy(tmp, b->Buf, b->Size);

	i = SearchStrEx(tmp, str, 0, false);
	if (i != INFINITE)
	{
		offset = i;
	}

	ret = NewBuf();
	WriteBuf(ret, ((UCHAR *)b->Buf) + offset, b->Size - offset);
	SeekBuf(ret, 0, 0);

	Free(tmp);

	return ret;
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

	LockOpenSSL();
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
	UnlockOpenSSL();

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

	LockOpenSSL();
	{
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
		{
			UnlockOpenSSL();
			return NULL;
		}
		BIO_write(bio, b->Buf, b->Size);
		BIO_seek(bio, 0);
	}
	UnlockOpenSSL();

	return bio;
}

// New seed rand
SEEDRAND *NewSeedRand(void *seed, UINT seed_size)
{
	SEEDRAND *r = ZeroMalloc(sizeof(SEEDRAND));

	if (seed == NULL || seed_size == 0)
	{
		HashSha1(r->InitialSeed, NULL, 0);
	}
	else
	{
		HashSha1(r->InitialSeed, seed, seed_size);
	}

	return r;
}

// Free seed rand
void FreeSeedRand(SEEDRAND *r)
{
	if (r == NULL)
	{
		return;
	}

	Free(r);
}

// Get seed rand next byte
UCHAR SeedRand8(SEEDRAND *r)
{
	UCHAR tmp[SHA1_SIZE + sizeof(UINT64)];
	UCHAR hash[SHA1_SIZE];
	if (r == NULL)
	{
		return 0;
	}

	Copy(tmp, r->InitialSeed, SHA1_SIZE);
	WRITE_UINT64(tmp + SHA1_SIZE, r->CurrentCounter);

	HashSha1(hash, tmp, sizeof(tmp));

	r->CurrentCounter++;

	return hash[0];
}
void SeedRand(SEEDRAND *r, void *buf, UINT size)
{
	UINT i;
	if (buf == NULL || size == 0)
	{
		return;
	}
	for (i = 0;i < size;i++)
	{
		((UCHAR *)buf)[i] = SeedRand8(r);
	}
}
USHORT SeedRand16(SEEDRAND *r)
{
	USHORT i;
	SeedRand(r, &i, sizeof(i));
	return i;
}
UINT SeedRand32(SEEDRAND *r)
{
	UINT i;
	SeedRand(r, &i, sizeof(i));
	return i;
}
UINT64 SeedRand64(SEEDRAND *r)
{
	UINT64 i;
	SeedRand(r, &i, sizeof(i));
	return i;
}

// 128-bit random number generation
void Rand128(void *buf)
{
	Rand(buf, 16);
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (ossl_provider_default != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_default);
		ossl_provider_default = NULL;
	}

	if (ossl_provider_legacy != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_legacy);
		ossl_provider_legacy = NULL;
	}
#endif

	DeleteLock(openssl_lock);
	openssl_lock = NULL;
//	RAND_Free_For_SoftEther();
	OpenSSL_FreeLock();
}

// Initialize the Crypt library
void InitCryptLibrary()
{
	char tmp[16];

	CheckIfIntelAesNiSupportedInit();
//	RAND_Init_For_SoftEther()
	openssl_lock = NewLock();


#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OPENSSL_init_ssl(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
#else
	SSL_library_init();
#endif
	//OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ossl_provider_legacy = OSSL_PROVIDER_load(NULL, "legacy");
	ossl_provider_default = OSSL_PROVIDER_load(NULL, "default");
#endif

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

// SHA-256 specific hash function
void HashSha256(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (size != 0 && src == NULL))
	{
		return;
	}
	SHA256(src, size, dst);
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

void Sha1__(void *dst, void *src, UINT size) {
	Sha(SHA1_160, dst, src, size);
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
void Des3Encrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || key == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_ede3_cbc_encrypt(src, dest, size,
		key->k1->KeySchedule,
		key->k2->KeySchedule,
		key->k3->KeySchedule,
		(DES_cblock *)ivec_copy,
		1);
}
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
void Des3Decrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec)
{
	UCHAR ivec_copy[DES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || key == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, DES_IV_SIZE);

	DES_ede3_cbc_encrypt(src, dest, size,
		key->k1->KeySchedule,
		key->k2->KeySchedule,
		key->k3->KeySchedule,
		(DES_cblock *)ivec_copy,
		0);
}
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
	if (dst == NULL || src == NULL || key == NULL)
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

// Generate a random 3DES key
DES_KEY *Des3RandKey()
{
	DES_KEY *k = ZeroMalloc(sizeof(DES_KEY));

	k->k1 = DesRandKeyValue();
	k->k2 = DesRandKeyValue();
	k->k3 = DesRandKeyValue();

	return k;
}

// Generate a random DES key
DES_KEY *DesRandKey()
{
	DES_KEY *k = ZeroMalloc(sizeof(DES_KEY));

	k->k1 = DesRandKeyValue();
	k->k2 = DesNewKeyValue(k->k1->KeyValue);
	k->k3 = DesNewKeyValue(k->k1->KeyValue);

	return k;
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

// Release the DES key
void DesFreeKey(DES_KEY *k)
{
	Des3FreeKey(k);
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

// Create a DES key
DES_KEY *DesNewKey(void *k1)
{
	return Des3NewKey(k1, k1, k1);
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
	UCHAR ivec_copy[AES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

#ifdef	USE_INTEL_AESNI_LIBRARY
	if (is_intel_aes_supported)
	{
		AesEncryptWithIntel(dest, src, size, k, ivec);
		return;
	}
#endif	// USE_INTEL_AESNI_LIBRARY

	Copy(ivec_copy, ivec, AES_IV_SIZE);

	AES_cbc_encrypt(src, dest, size, k->EncryptKey, ivec, 1);
}

// AES decryption
void AesDecrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec)
{
	UCHAR ivec_copy[AES_IV_SIZE];
	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

#ifdef	USE_INTEL_AESNI_LIBRARY
	if (is_intel_aes_supported)
	{
		AesDecryptWithIntel(dest, src, size, k, ivec);
		return;
	}
#endif	// USE_INTEL_AESNI_LIBRARY

	Copy(ivec_copy, ivec, AES_IV_SIZE);

	AES_cbc_encrypt(src, dest, size, k->DecryptKey, ivec, 0);
}

// Determine whether the Intel AES-NI is supported
bool IsIntelAesNiSupported()
{
	return is_intel_aes_supported;
}
void CheckIfIntelAesNiSupportedInit()
{
#ifdef	USE_INTEL_AESNI_LIBRARY
	if (check_for_aes_instructions())
	{
		is_intel_aes_supported = true;
	}
	else
	{
		is_intel_aes_supported = false;
	}
#else	// USE_INTEL_AESNI_LIBRARY
	is_intel_aes_supported = false;
#endif	// USE_INTEL_AESNI_LIBRARY
}

// Disable the Intel AES-NI
void DisableIntelAesAccel()
{
	is_intel_aes_supported = false;
}

#ifdef	USE_INTEL_AESNI_LIBRARY
// Encrypt AES using the Intel AES-NI
void AesEncryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec)
{
	UCHAR ivec_copy[AES_IV_SIZE];

	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, AES_IV_SIZE);

	switch (k->KeySize)
	{
	case 16:
		intel_AES_enc128_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;

	case 24:
		intel_AES_enc192_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;

	case 32:
		intel_AES_enc256_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;
	}
}

// Decrypt AES using the Intel AES-NI
void AesDecryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec)
{
	UCHAR ivec_copy[AES_IV_SIZE];

	// Validate arguments
	if (dest == NULL || src == NULL || size == 0 || k == NULL || ivec == NULL)
	{
		return;
	}

	Copy(ivec_copy, ivec, AES_IV_SIZE);

	switch (k->KeySize)
	{
	case 16:
		intel_AES_dec128_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;

	case 24:
		intel_AES_dec192_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;

	case 32:
		intel_AES_dec256_CBC(src, dest, k->KeyValue, (size / AES_IV_SIZE), ivec_copy);
		break;
	}
}
#endif	// USE_INTEL_AESNI_LIBRARY

// Calculation of HMAC-SHA-1-96
void MacSha196(void *dst, void *key, void *data, UINT data_size)
{
	UCHAR tmp[HMAC_SHA1_SIZE];
	// Validate arguments
	if (dst == NULL || key == NULL || data == NULL)
	{
		return;
	}

	MacSha1(tmp, key, HMAC_SHA1_96_KEY_SIZE, data, data_size);

	Copy(dst, tmp, HMAC_SHA1_96_HASH_SIZE);
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

// Convert the DH parameters to file
BUF *DhToBuf(DH_CTX *dh)
{
	BIO *bio;
	BUF *buf = NULL;
	int r;
	// Validate arguments
	if (dh == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	r = i2d_DHparams_bio(bio, dh->dh);
	if (r > 1)
	{
		buf = BioToBuf(bio);
	}

	FreeBio(bio);

	return buf;
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

// Source codes from:
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/libmincrypt/sha.c
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/hash-internal.h
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/sha.h

/*
 * Copyright 2013 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

typedef struct MY_SHA0_CTX {
//	const HASH_VTAB * f;
	UINT64 count;
	UCHAR buf[64];
	UINT state[8];  // upto SHA2
} MY_SHA0_CTX;

#define MY_SHA0_DIGEST_SIZE 20

static void MY_SHA0_Transform(MY_SHA0_CTX* ctx) {
	UINT W[80];
	UINT A, B, C, D, E;
	UCHAR* p = ctx->buf;
	int t;
	for(t = 0; t < 16; ++t) {
		UINT tmp =  *p++ << 24;
		tmp |= *p++ << 16;
		tmp |= *p++ << 8;
		tmp |= *p++;
		W[t] = tmp;
	}
	for(; t < 80; t++) {
		//W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
		W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	for(t = 0; t < 80; t++) {
		UINT tmp = rol(5,A) + E + W[t];
		if (t < 20)
			tmp += (D^(B&(C^D))) + 0x5A827999;
		else if ( t < 40)
			tmp += (B^C^D) + 0x6ED9EBA1;
		else if ( t < 60)
			tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC;
		else
			tmp += (B^C^D) + 0xCA62C1D6;
		E = D;
		D = C;
		C = rol(30,B);
		B = A;
		A = tmp;
	}
	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}
void MY_SHA0_init(MY_SHA0_CTX* ctx) {
	//ctx->f = &SHA_VTAB;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->count = 0;
}
void MY_SHA0_update(MY_SHA0_CTX* ctx, const void* data, int len) {
	int i = (int) (ctx->count & 63);
	const UCHAR* p = (const UCHAR*)data;
	ctx->count += len;
	while (len--) {
		ctx->buf[i++] = *p++;
		if (i == 64) {
			MY_SHA0_Transform(ctx);
			i = 0;
		}
	}
}
const UCHAR* MY_SHA0_final(MY_SHA0_CTX* ctx) {
	UCHAR *p = ctx->buf;
	UINT64 cnt = ctx->count * 8;
	int i;
	MY_SHA0_update(ctx, (UCHAR*)"\x80", 1);
	while ((ctx->count & 63) != 56) {
		MY_SHA0_update(ctx, (UCHAR*)"\0", 1);
	}
	for (i = 0; i < 8; ++i) {
		UCHAR tmp = (UCHAR) (cnt >> ((7 - i) * 8));
		MY_SHA0_update(ctx, &tmp, 1);
	}
	for (i = 0; i < 5; i++) {
		UINT tmp = ctx->state[i];
		*p++ = tmp >> 24;
		*p++ = tmp >> 16;
		*p++ = tmp >> 8;
		*p++ = tmp >> 0;
	}
	return ctx->buf;
}
/* Convenience function */
const UCHAR* MY_SHA0_hash(const void* data, int len, UCHAR* digest) {
	MY_SHA0_CTX ctx;
	MY_SHA0_init(&ctx);
	MY_SHA0_update(&ctx, data, len);
	memcpy(digest, MY_SHA0_final(&ctx), MY_SHA0_DIGEST_SIZE);
	return digest;
}
static unsigned char *Internal_SHA0(const unsigned char *d, size_t n, unsigned char *md)
{
	return (unsigned char *)MY_SHA0_hash(d, (int)n, md);
}


int GetSslClientCertIndex()
{
	return ssl_clientcert_index;
}



//// RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
//// Implementation from libsodium: https://github.com/jedisct1/libsodium
//// 
//// SoftEther VPN must support OpenSSL versions between 1.0.2 to the latest version.
//// Since we are unable to use ChaCha20 and Poly1305 on OpenSSL 1.0.x,
//// we copied the C implementation from libsodium.
//// Please note that the C implementation for ChaCha20 and Poly1305 is slow than
//// the OpenSSL 1.0.0 or later's implementation for ChaCha20 and Poly1305.
//// 
//// If OpenSSL 1.1.0 or later is linked, we use OpenSSL's ChaCha20 and Poly1305 implementation.

/*
 * ISC License
 *
 * Copyright (c) 2013-2018
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef	OS_WIN32
#define inline __inline
#endif

#define poly1305_block_size 16

#define U32C(v) (v##U)
#define U32V(v) ((UINT)(v) &U32C(0xFFFFFFFF))
#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d) \
	a = PLUS(a, b);              \
	d = ROTATE(XOR(d, a), 16);   \
	c = PLUS(c, d);              \
	b = ROTATE(XOR(b, c), 12);   \
	a = PLUS(a, b);              \
	d = ROTATE(XOR(d, a), 8);    \
	c = PLUS(c, d);              \
	b = ROTATE(XOR(b, c), 7);

#define ROTL32(X, B) rotl32((X), (B))
static inline UINT
rotl32(const UINT x, const int b)
{
	return (x << b) | (x >> (32 - b));
}


#define LOAD32_LE(SRC) load32_le(SRC)

static inline UINT
load32_le(const UCHAR src[4])
{
	if (IsBigEndian() == false)
	{
		UINT w;
		memcpy(&w, src, sizeof w);
		return w;
	}
	else
	{
		UINT w = (UINT) src[0];
		w |= (UINT) src[1] <<  8;
		w |= (UINT) src[2] << 16;
		w |= (UINT) src[3] << 24;
		return w;
	}
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(UCHAR dst[4], UINT w)
{
	if (IsBigEndian() == false)
	{
		memcpy(dst, &w, sizeof w);
	}
	else
	{
		dst[0] = (UCHAR) w; w >>= 8;
		dst[1] = (UCHAR) w; w >>= 8;
		dst[2] = (UCHAR) w; w >>= 8;
		dst[3] = (UCHAR) w;
	}
}


#define LOAD64_LE(SRC) load64_le(SRC)
static inline UINT64
load64_le(const UCHAR src[8])
{
	if (IsBigEndian() == false)
	{
		UINT64 w;
		memcpy(&w, src, sizeof w);
		return w;
	}
	else
	{
		UINT64 w = (UINT64) src[0];
		w |= (UINT64) src[1] <<  8;
		w |= (UINT64) src[2] << 16;
		w |= (UINT64) src[3] << 24;
		w |= (UINT64) src[4] << 32;
		w |= (UINT64) src[5] << 40;
		w |= (UINT64) src[6] << 48;
		w |= (UINT64) src[7] << 56;
		return w;
	}
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(UCHAR dst[8], UINT64 w)
{
	if (IsBigEndian() == false)
	{
		memcpy(dst, &w, sizeof w);
	}
	else
	{
		dst[0] = (UCHAR) w; w >>= 8;
		dst[1] = (UCHAR) w; w >>= 8;
		dst[2] = (UCHAR) w; w >>= 8;
		dst[3] = (UCHAR) w; w >>= 8;
		dst[4] = (UCHAR) w; w >>= 8;
		dst[5] = (UCHAR) w; w >>= 8;
		dst[6] = (UCHAR) w; w >>= 8;
		dst[7] = (UCHAR) w;
	}
}



typedef struct chacha_ctx {
	UINT input[16];
} chacha_ctx;




#define crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX \
	(64ULL * (1ULL << 32))

typedef struct crypto_onetimeauth_poly1305_state {
	unsigned char opaque[256];
} crypto_onetimeauth_poly1305_state;

/* 17 + sizeof(unsigned long long) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long      r[5];
	unsigned long      h[5];
	unsigned long      pad[4];
	unsigned long long leftover;
	unsigned char      buffer[poly1305_block_size];
	unsigned char      final;
} poly1305_state_internal_t;
static void
chacha_keysetup(chacha_ctx *ctx, const UCHAR *k)
{
	ctx->input[0]  = U32C(0x61707865);
	ctx->input[1]  = U32C(0x3320646e);
	ctx->input[2]  = U32C(0x79622d32);
	ctx->input[3]  = U32C(0x6b206574);
	ctx->input[4]  = LOAD32_LE(k + 0);
	ctx->input[5]  = LOAD32_LE(k + 4);
	ctx->input[6]  = LOAD32_LE(k + 8);
	ctx->input[7]  = LOAD32_LE(k + 12);
	ctx->input[8]  = LOAD32_LE(k + 16);
	ctx->input[9]  = LOAD32_LE(k + 20);
	ctx->input[10] = LOAD32_LE(k + 24);
	ctx->input[11] = LOAD32_LE(k + 28);
}

static void
chacha_ietf_ivsetup(chacha_ctx *ctx, const UCHAR *iv, const UCHAR *counter)
{
	ctx->input[12] = counter == NULL ? 0 : LOAD32_LE(counter);
	ctx->input[13] = LOAD32_LE(iv + 0);
	ctx->input[14] = LOAD32_LE(iv + 4);
	ctx->input[15] = LOAD32_LE(iv + 8);
}

static void
chacha20_encrypt_bytes(chacha_ctx *ctx, const UCHAR *m, UCHAR *c,
					   unsigned long long bytes)
{
	UINT x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14,
		x15;
	UINT j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14,
		j15;
	UCHAR     *ctarget = NULL;
	UCHAR      tmp[64];
	unsigned int i;

	if (!bytes) {
		return; /* LCOV_EXCL_LINE */
	}
	j0  = ctx->input[0];
	j1  = ctx->input[1];
	j2  = ctx->input[2];
	j3  = ctx->input[3];
	j4  = ctx->input[4];
	j5  = ctx->input[5];
	j6  = ctx->input[6];
	j7  = ctx->input[7];
	j8  = ctx->input[8];
	j9  = ctx->input[9];
	j10 = ctx->input[10];
	j11 = ctx->input[11];
	j12 = ctx->input[12];
	j13 = ctx->input[13];
	j14 = ctx->input[14];
	j15 = ctx->input[15];

	for (;;) {
		if (bytes < 64) {
			memset(tmp, 0, 64);
			for (i = 0; i < bytes; ++i) {
				tmp[i] = m[i];
			}
			m       = tmp;
			ctarget = c;
			c       = tmp;
		}
		x0  = j0;
		x1  = j1;
		x2  = j2;
		x3  = j3;
		x4  = j4;
		x5  = j5;
		x6  = j6;
		x7  = j7;
		x8  = j8;
		x9  = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;
		for (i = 20; i > 0; i -= 2) {
			QUARTERROUND(x0, x4, x8, x12)
				QUARTERROUND(x1, x5, x9, x13)
				QUARTERROUND(x2, x6, x10, x14)
				QUARTERROUND(x3, x7, x11, x15)
				QUARTERROUND(x0, x5, x10, x15)
				QUARTERROUND(x1, x6, x11, x12)
				QUARTERROUND(x2, x7, x8, x13)
				QUARTERROUND(x3, x4, x9, x14)
		}
		x0  = PLUS(x0, j0);
		x1  = PLUS(x1, j1);
		x2  = PLUS(x2, j2);
		x3  = PLUS(x3, j3);
		x4  = PLUS(x4, j4);
		x5  = PLUS(x5, j5);
		x6  = PLUS(x6, j6);
		x7  = PLUS(x7, j7);
		x8  = PLUS(x8, j8);
		x9  = PLUS(x9, j9);
		x10 = PLUS(x10, j10);
		x11 = PLUS(x11, j11);
		x12 = PLUS(x12, j12);
		x13 = PLUS(x13, j13);
		x14 = PLUS(x14, j14);
		x15 = PLUS(x15, j15);

		x0  = XOR(x0, LOAD32_LE(m + 0));
		x1  = XOR(x1, LOAD32_LE(m + 4));
		x2  = XOR(x2, LOAD32_LE(m + 8));
		x3  = XOR(x3, LOAD32_LE(m + 12));
		x4  = XOR(x4, LOAD32_LE(m + 16));
		x5  = XOR(x5, LOAD32_LE(m + 20));
		x6  = XOR(x6, LOAD32_LE(m + 24));
		x7  = XOR(x7, LOAD32_LE(m + 28));
		x8  = XOR(x8, LOAD32_LE(m + 32));
		x9  = XOR(x9, LOAD32_LE(m + 36));
		x10 = XOR(x10, LOAD32_LE(m + 40));
		x11 = XOR(x11, LOAD32_LE(m + 44));
		x12 = XOR(x12, LOAD32_LE(m + 48));
		x13 = XOR(x13, LOAD32_LE(m + 52));
		x14 = XOR(x14, LOAD32_LE(m + 56));
		x15 = XOR(x15, LOAD32_LE(m + 60));

		j12 = PLUSONE(j12);
		/* LCOV_EXCL_START */
		if (!j12) {
			j13 = PLUSONE(j13);
		}
		/* LCOV_EXCL_STOP */

		STORE32_LE(c + 0, x0);
		STORE32_LE(c + 4, x1);
		STORE32_LE(c + 8, x2);
		STORE32_LE(c + 12, x3);
		STORE32_LE(c + 16, x4);
		STORE32_LE(c + 20, x5);
		STORE32_LE(c + 24, x6);
		STORE32_LE(c + 28, x7);
		STORE32_LE(c + 32, x8);
		STORE32_LE(c + 36, x9);
		STORE32_LE(c + 40, x10);
		STORE32_LE(c + 44, x11);
		STORE32_LE(c + 48, x12);
		STORE32_LE(c + 52, x13);
		STORE32_LE(c + 56, x14);
		STORE32_LE(c + 60, x15);

		if (bytes <= 64) {
			if (bytes < 64) {
				for (i = 0; i < (unsigned int) bytes; ++i) {
					ctarget[i] = c[i]; /* ctarget cannot be NULL */
				}
			}
			ctx->input[12] = j12;
			ctx->input[13] = j13;

			return;
		}
		bytes -= 64;
		c += 64;
		m += 64;
	}
}

static int
stream_ietf_ext_ref(unsigned char *c, unsigned long long clen,
					const unsigned char *n, const unsigned char *k)
{
	struct chacha_ctx ctx;

	if (!clen) {
		return 0;
	}
	chacha_keysetup(&ctx, k);
	chacha_ietf_ivsetup(&ctx, n, NULL);
	memset(c, 0, (UINT)clen);
	chacha20_encrypt_bytes(&ctx, c, c, clen);
	Zero(&ctx, sizeof ctx);

	return 0;
}

int
crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
							const unsigned char *n, const unsigned char *k)
{
	return stream_ietf_ext_ref(c, clen, n, k);
}

static void
poly1305_init(poly1305_state_internal_t *st, const unsigned char key[32])
{
	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff - wiped after finalization */
	st->r[0] = (LOAD32_LE(&key[0])) & 0x3ffffff;
	st->r[1] = (LOAD32_LE(&key[3]) >> 2) & 0x3ffff03;
	st->r[2] = (LOAD32_LE(&key[6]) >> 4) & 0x3ffc0ff;
	st->r[3] = (LOAD32_LE(&key[9]) >> 6) & 0x3f03fff;
	st->r[4] = (LOAD32_LE(&key[12]) >> 8) & 0x00fffff;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* save pad for later */
	st->pad[0] = LOAD32_LE(&key[16]);
	st->pad[1] = LOAD32_LE(&key[20]);
	st->pad[2] = LOAD32_LE(&key[24]);
	st->pad[3] = LOAD32_LE(&key[28]);

	st->leftover = 0;
	st->final    = 0;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m,
				unsigned long long bytes)
{
	const unsigned long hibit = (st->final) ? 0UL : (1UL << 24); /* 1 << 128 */
	unsigned long       r0, r1, r2, r3, r4;
	unsigned long       s1, s2, s3, s4;
	unsigned long       h0, h1, h2, h3, h4;
	unsigned long long  d0, d1, d2, d3, d4;
	unsigned long       c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_block_size) {
		/* h += m[i] */
		h0 += (LOAD32_LE(m + 0)) & 0x3ffffff;
		h1 += (LOAD32_LE(m + 3) >> 2) & 0x3ffffff;
		h2 += (LOAD32_LE(m + 6) >> 4) & 0x3ffffff;
		h3 += (LOAD32_LE(m + 9) >> 6) & 0x3ffffff;
		h4 += (LOAD32_LE(m + 12) >> 8) | hibit;

		/* h *= r */
		d0 = ((unsigned long long) h0 * r0) + ((unsigned long long) h1 * s4) +
			((unsigned long long) h2 * s3) + ((unsigned long long) h3 * s2) +
			((unsigned long long) h4 * s1);
		d1 = ((unsigned long long) h0 * r1) + ((unsigned long long) h1 * r0) +
			((unsigned long long) h2 * s4) + ((unsigned long long) h3 * s3) +
			((unsigned long long) h4 * s2);
		d2 = ((unsigned long long) h0 * r2) + ((unsigned long long) h1 * r1) +
			((unsigned long long) h2 * r0) + ((unsigned long long) h3 * s4) +
			((unsigned long long) h4 * s3);
		d3 = ((unsigned long long) h0 * r3) + ((unsigned long long) h1 * r2) +
			((unsigned long long) h2 * r1) + ((unsigned long long) h3 * r0) +
			((unsigned long long) h4 * s4);
		d4 = ((unsigned long long) h0 * r4) + ((unsigned long long) h1 * r3) +
			((unsigned long long) h2 * r2) + ((unsigned long long) h3 * r1) +
			((unsigned long long) h4 * r0);

		/* (partial) h %= p */
		c  = (unsigned long) (d0 >> 26);
		h0 = (unsigned long) d0 & 0x3ffffff;
		d1 += c;
		c  = (unsigned long) (d1 >> 26);
		h1 = (unsigned long) d1 & 0x3ffffff;
		d2 += c;
		c  = (unsigned long) (d2 >> 26);
		h2 = (unsigned long) d2 & 0x3ffffff;
		d3 += c;
		c  = (unsigned long) (d3 >> 26);
		h3 = (unsigned long) d3 & 0x3ffffff;
		d4 += c;
		c  = (unsigned long) (d4 >> 26);
		h4 = (unsigned long) d4 & 0x3ffffff;
		h0 += c * 5;
		c  = (h0 >> 26);
		h0 = h0 & 0x3ffffff;
		h1 += c;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
				unsigned long long bytes)
{
	unsigned long long i;

	/* handle leftover */
	if (st->leftover) {
		unsigned long long want = (poly1305_block_size - st->leftover);

		if (want > bytes) {
			want = bytes;
		}
		for (i = 0; i < want; i++) {
			st->buffer[st->leftover + i] = m[i];
		}
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size) {
			return;
		}
		poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		unsigned long long want = (bytes & ~(poly1305_block_size - 1));

		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++) {
			st->buffer[st->leftover + i] = m[i];
		}
		st->leftover += bytes;
	}
}

static int
crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
									   const unsigned char *key)
{
	poly1305_init((poly1305_state_internal_t *) (void *) state, key);

	return 0;
}

static int
crypto_onetimeauth_poly1305_update(
	crypto_onetimeauth_poly1305_state *state, const unsigned char *in,
	unsigned long long inlen)
{
	poly1305_update((poly1305_state_internal_t *) (void *) state, in, inlen);

	return 0;
}

static int
stream_ietf_ext_ref_xor_ic(unsigned char *c, const unsigned char *m,
						   unsigned long long mlen, const unsigned char *n,
						   UINT ic, const unsigned char *k)
{
	struct chacha_ctx ctx;
	UCHAR           ic_bytes[4];

	if (!mlen) {
		return 0;
	}
	STORE32_LE(ic_bytes, ic);
	chacha_keysetup(&ctx, k);
	chacha_ietf_ivsetup(&ctx, n, ic_bytes);
	chacha20_encrypt_bytes(&ctx, m, c, mlen);
	Zero(&ctx, sizeof ctx);

	return 0;
}

int
crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
								   unsigned long long mlen,
								   const unsigned char *n, UINT ic,
								   const unsigned char *k)
{
	return stream_ietf_ext_ref_xor_ic(c, m, mlen, n, ic, k);
}


static void
poly1305_finish(poly1305_state_internal_t *st, unsigned char mac[16])
{
	unsigned long      h0, h1, h2, h3, h4, c;
	unsigned long      g0, g1, g2, g3, g4;
	unsigned long long f;
	unsigned long      mask;

	/* process the remaining block */
	if (st->leftover) {
		unsigned long long i = st->leftover;

		st->buffer[i++] = 1;
		for (; i < poly1305_block_size; i++) {
			st->buffer[i] = 0;
		}
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	c  = h1 >> 26;
	h1 = h1 & 0x3ffffff;
	h2 += c;
	c  = h2 >> 26;
	h2 = h2 & 0x3ffffff;
	h3 += c;
	c  = h3 >> 26;
	h3 = h3 & 0x3ffffff;
	h4 += c;
	c  = h4 >> 26;
	h4 = h4 & 0x3ffffff;
	h0 += c * 5;
	c  = h0 >> 26;
	h0 = h0 & 0x3ffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5;
	c  = g0 >> 26;
	g0 &= 0x3ffffff;
	g1 = h1 + c;
	c  = g1 >> 26;
	g1 &= 0x3ffffff;
	g2 = h2 + c;
	c  = g2 >> 26;
	g2 &= 0x3ffffff;
	g3 = h3 + c;
	c  = g3 >> 26;
	g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;

	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

	/* mac = (h + pad) % (2^128) */
	f  = (unsigned long long) h0 + st->pad[0];
	h0 = (unsigned long) f;
	f  = (unsigned long long) h1 + st->pad[1] + (f >> 32);
	h1 = (unsigned long) f;
	f  = (unsigned long long) h2 + st->pad[2] + (f >> 32);
	h2 = (unsigned long) f;
	f  = (unsigned long long) h3 + st->pad[3] + (f >> 32);
	h3 = (unsigned long) f;

	STORE32_LE(mac + 0, (UINT) h0);
	STORE32_LE(mac + 4, (UINT) h1);
	STORE32_LE(mac + 8, (UINT) h2);
	STORE32_LE(mac + 12, (UINT) h3);

	/* zero out the state */
	Zero((void *) st, sizeof *st);
}

static int
crypto_onetimeauth_poly1305_final(
										crypto_onetimeauth_poly1305_state *state, unsigned char *out)
{
	poly1305_finish((poly1305_state_internal_t *) (void *) state, out);

	return 0;
}

static const unsigned char _pad0[16] = { 0 };

int
crypto_aead_chacha20poly1305_ietf_encrypt_detached(unsigned char *c,
												   unsigned char *mac,
												   unsigned long long *maclen_p,
												   const unsigned char *m,
												   unsigned long long mlen,
												   const unsigned char *ad,
												   unsigned long long adlen,
												   const unsigned char *nsec,
												   const unsigned char *npub,
												   const unsigned char *k)
{
	crypto_onetimeauth_poly1305_state state;
	unsigned char                     block0[64U];
	unsigned char                     slen[8U];

	(void) nsec;
	Zero(block0, sizeof block0);
	crypto_stream_chacha20_ietf(block0, sizeof block0, npub, k);
	crypto_onetimeauth_poly1305_init(&state, block0);

	crypto_onetimeauth_poly1305_update(&state, ad, adlen);
	crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - adlen) & 0xf);

	crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, npub, 1U, k);

	crypto_onetimeauth_poly1305_update(&state, c, mlen);
	crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - mlen) & 0xf);

	STORE64_LE(slen, (UINT64) adlen);
	crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

	STORE64_LE(slen, (UINT64) mlen);
	crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

	crypto_onetimeauth_poly1305_final(&state, mac);
	Zero(&state, sizeof state);

	if (maclen_p != NULL) {
		*maclen_p = 16;
	}
	return 0;
}



int
crypto_aead_chacha20poly1305_ietf_decrypt_detached(unsigned char *m,
												   unsigned char *nsec,
												   const unsigned char *c,
												   unsigned long long clen,
												   const unsigned char *mac,
												   const unsigned char *ad,
												   unsigned long long adlen,
												   const unsigned char *npub,
												   const unsigned char *k)
{
	crypto_onetimeauth_poly1305_state state;
	unsigned char                     block0[64U];
	unsigned char                     slen[8U];
	unsigned char                     computed_mac[16];
	unsigned long long                mlen;
	int                               ret;

	(void) nsec;
	Zero(block0, sizeof block0);
	crypto_stream_chacha20_ietf(block0, sizeof block0, npub, k);
	crypto_onetimeauth_poly1305_init(&state, block0);

	crypto_onetimeauth_poly1305_update(&state, ad, adlen);
	crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - adlen) & 0xf);

	mlen = clen;
	crypto_onetimeauth_poly1305_update(&state, c, mlen);
	crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - mlen) & 0xf);

	STORE64_LE(slen, (UINT64) adlen);
	crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

	STORE64_LE(slen, (UINT64) mlen);
	crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

	crypto_onetimeauth_poly1305_final(&state, computed_mac);
	Zero(&state, sizeof state);

	ret = Cmp((void *)computed_mac, (void *)mac, 16);
	Zero(computed_mac, sizeof computed_mac);
	if (m == NULL) {
		return ret;
	}
	if (ret != 0) {
		memset(m, 0, (UINT)mlen);
		return -1;
	}
	crypto_stream_chacha20_ietf_xor_ic(m, c, mlen, npub, 1U, k);

	return 0;
}

int
crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
										  unsigned long long *mlen_p,
										  unsigned char *nsec,
										  const unsigned char *c,
										  unsigned long long clen,
										  const unsigned char *ad,
										  unsigned long long adlen,
										  const unsigned char *npub,
										  const unsigned char *k)
{
	unsigned long long mlen = 0ULL;
	int                ret = -1;

	if (clen >= 16) {
		ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached
			(m, nsec,
			c, clen - 16,
			c + clen - AEAD_CHACHA20_POLY1305_MAC_SIZE,
			ad, adlen, npub, k);
	}
	if (mlen_p != NULL) {
		if (ret == 0) {
			mlen = clen - AEAD_CHACHA20_POLY1305_MAC_SIZE;
		}
		*mlen_p = mlen;
	}
	return ret;
}


int
crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
										  unsigned long long *clen_p,
										  const unsigned char *m,
										  unsigned long long mlen,
										  const unsigned char *ad,
										  unsigned long long adlen,
										  const unsigned char *nsec,
										  const unsigned char *npub,
										  const unsigned char *k)
{
	unsigned long long clen = 0ULL;
	int                ret;

	ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c,
		c + mlen, NULL,
		m, mlen,
		ad, adlen,
		nsec, npub, k);
	if (clen_p != NULL) {
		if (ret == 0) {
			clen = mlen + AEAD_CHACHA20_POLY1305_MAC_SIZE;
		}
		*clen_p = clen;
	}
	return ret;
}

// RFC 8439: ChaCha20-Poly1305-IETF Encryption with AEAD
void Aead_ChaCha20Poly1305_Ietf_Encrypt(void *dst, void *src, UINT src_size,
										void *key, void *nonce, void *aad, UINT aad_size)
{
#ifdef USE_OPENSSL_AEAD_CHACHA20POLY1305
	Aead_ChaCha20Poly1305_Ietf_Encrypt_OpenSSL(dst, src, src_size, key, nonce, aad, aad_size);
#else // USE_OPENSSL_AEAD_CHACHA20POLY1305
	Aead_ChaCha20Poly1305_Ietf_Encrypt_Embedded(dst, src, src_size, key, nonce, aad, aad_size);
#endif // USE_OPENSSL_AEAD_CHACHA20POLY1305
}
void Aead_ChaCha20Poly1305_Ietf_Encrypt_OpenSSL(void *dst, void *src, UINT src_size,
												 void *key, void *nonce, void *aad, UINT aad_size)
{
#ifdef USE_OPENSSL_AEAD_CHACHA20POLY1305
	EVP_CIPHER_CTX *ctx;
	int outlen = 0;

	if ((src_size != 0 && (dst == NULL || src == NULL)) ||
		key == NULL || nonce == NULL ||
		(aad_size != 0 && aad == NULL))
	{
		Zero(dst, src_size);
		return;
	}

	ctx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), 0, 0, 0);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_CHACHA20_POLY1305_NONCE_SIZE, 0);
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
	EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_size);
	EVP_EncryptUpdate(ctx, dst, &outlen, src, src_size);
	EVP_EncryptFinal_ex(ctx, dst, &outlen);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_CHACHA20_POLY1305_MAC_SIZE,
		((UCHAR *)dst) + src_size);

	EVP_CIPHER_CTX_free(ctx);
#endif	// USE_OPENSSL_AEAD_CHACHA20POLY1305
}
void Aead_ChaCha20Poly1305_Ietf_Encrypt_Embedded(void *dst, void *src, UINT src_size,
										void *key, void *nonce, void *aad, UINT aad_size)
{
	if ((src_size != 0 && (dst == NULL || src == NULL)) ||
		key == NULL || nonce == NULL ||
		(aad_size != 0 && aad == NULL))
	{
		Zero(dst, src_size);
		return;
	}
	crypto_aead_chacha20poly1305_ietf_encrypt(dst, NULL, src, src_size, aad, aad_size,
		NULL, nonce, key);
}

// RFC 8439: ChaCha20-Poly1305-IETF Decryption with AEAD
bool Aead_ChaCha20Poly1305_Ietf_Decrypt(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size)
{
#ifdef USE_OPENSSL_AEAD_CHACHA20POLY1305
	return Aead_ChaCha20Poly1305_Ietf_Decrypt_OpenSSL(dst, src, src_size, key,
		nonce, aad, aad_size);
#else // USE_OPENSSL_AEAD_CHACHA20POLY1305
	return Aead_ChaCha20Poly1305_Ietf_Decrypt_Embedded(dst, src, src_size, key,
		nonce, aad, aad_size);
#endif // USE_OPENSSL_AEAD_CHACHA20POLY1305
}
bool Aead_ChaCha20Poly1305_Ietf_Decrypt_OpenSSL(void *dst, void *src, UINT src_size, void *key,
												 void *nonce, void *aad, UINT aad_size)
{
#ifdef USE_OPENSSL_AEAD_CHACHA20POLY1305
	EVP_CIPHER_CTX *ctx;
	int outlen = 0;
	bool ret = false;

	if ((src_size != 0 && (dst == NULL || src == NULL)) ||
		key == NULL || nonce == NULL ||
		(aad_size != 0 && aad == NULL) ||
		(src_size < AEAD_CHACHA20_POLY1305_MAC_SIZE))
	{
		Zero(dst, src_size);
		return false;
	}

	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), 0, 0, 0);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_CHACHA20_POLY1305_NONCE_SIZE, 0);
	
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1)
	{
		if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_size) == 1)
		{
			if (EVP_DecryptUpdate(ctx, dst, &outlen, src, src_size - AEAD_CHACHA20_POLY1305_MAC_SIZE) == 1)
			{
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_CHACHA20_POLY1305_MAC_SIZE,
					((UCHAR *)src) + (src_size - AEAD_CHACHA20_POLY1305_MAC_SIZE));

				if (EVP_DecryptFinal_ex(ctx, dst, &outlen))
				{
					ret = true;
				}
			}
		}
	}

	EVP_CIPHER_CTX_free(ctx);

	return ret;
#else	// USE_OPENSSL_AEAD_CHACHA20POLY1305
	return false;
#endif	// USE_OPENSSL_AEAD_CHACHA20POLY1305
}
bool Aead_ChaCha20Poly1305_Ietf_Decrypt_Embedded(void *dst, void *src, UINT src_size, void *key,
										void *nonce, void *aad, UINT aad_size)
{
	int ret;
	if ((src_size != 0 && (dst == NULL || src == NULL)) ||
		key == NULL || nonce == NULL ||
		(aad_size != 0 && aad == NULL) ||
		(src_size < AEAD_CHACHA20_POLY1305_MAC_SIZE))
	{
		Zero(dst, src_size);
		return false;
	}

	ret = crypto_aead_chacha20poly1305_ietf_decrypt(
		dst, NULL, NULL, src, src_size, aad, aad_size, nonce, key);

	if (ret == -1)
	{
		return false;
	}

	return true;
}

bool Aead_ChaCha20Poly1305_Ietf_IsOpenSSL()
{
#ifdef USE_OPENSSL_AEAD_CHACHA20POLY1305
	return true;
#else	// USE_OPENSSL_AEAD_CHACHA20POLY1305
	return false;
#endif	// USE_OPENSSL_AEAD_CHACHA20POLY1305
}

// RFC 8439: ChaCha20-Poly1305-IETF AEAD Test
void Aead_ChaCha20Poly1305_Ietf_Test()
{
	char *nonce_hex = "07 00 00 00 40 41 42 43 44 45 46 47";
	char *plaintext_hex =
		"4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c "
		"65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73 "
		"73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63 "
		"6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f "
		"6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20 "
		"74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73 "
		"63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69 "
		"74 2e";
	char *aad_hex = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7";
	char *key_hex =
		"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f "
		"90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f";
	BUF *nonce = StrToBin(nonce_hex);
	BUF *plaintext = StrToBin(plaintext_hex);
	BUF *aad = StrToBin(aad_hex);
	BUF *key = StrToBin(key_hex);
	UINT plaintext_size = plaintext->Size;
	UCHAR *encrypted = Malloc(plaintext_size + AEAD_CHACHA20_POLY1305_MAC_SIZE);
	UCHAR *decrypted = Malloc(plaintext_size);
	char encrypted_hex[MAX_SIZE];
	char mac_hex[MAX_SIZE];

	Print("Aead_ChaCha20Poly1305_Ietf_Test()\n\n");

	Aead_ChaCha20Poly1305_Ietf_Encrypt(encrypted, plaintext->Buf, plaintext_size,
		key->Buf, nonce->Buf, aad->Buf, aad->Size);

	BinToStrEx(encrypted_hex, sizeof(encrypted_hex), encrypted, plaintext_size);

	BinToStrEx(mac_hex, sizeof(mac_hex), encrypted + plaintext_size, AEAD_CHACHA20_POLY1305_MAC_SIZE);

	Print("Encrypted:\n%s\n\n", encrypted_hex);

	Print("MAC:\n%s\n\n", mac_hex);

	Print("Please check the results with https://tools.ietf.org/html/rfc8439#section-2.8.2 by your great eyes.\n\n");

	if (Aead_ChaCha20Poly1305_Ietf_Decrypt(decrypted, encrypted, plaintext_size + AEAD_CHACHA20_POLY1305_MAC_SIZE,
		key->Buf, nonce->Buf, aad->Buf, aad->Size) == false)
	{
		Print("Decrypt failed.\n");
	}
	else
	{
		Print("Decrypt OK.\n");
		if (Cmp(plaintext->Buf, decrypted, plaintext_size) == 0)
		{
			Print("Same OK.\n");
		}
		else
		{
			Print("Different !!!\n");
		}
	}

	FreeBuf(nonce);
	FreeBuf(plaintext);
	FreeBuf(aad);
	FreeBuf(key);
	Free(encrypted);
	Free(decrypted);
}
