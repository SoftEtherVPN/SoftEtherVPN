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


// Encrypt.h
// Header of Encrypt.c

#ifndef	ENCRYPT_H
#define	ENCRYPT_H

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define USE_OPENSSL_AEAD_CHACHA20POLY1305
#endif

// Function of OpenSSL
void RAND_Init_For_SoftEther();
void RAND_Free_For_SoftEther();



// Constant
#define	MIN_SIGN_HASH_SIZE		(15 + SHA1_SIZE)
#define	SIGN_HASH_SIZE			(MIN_SIGN_HASH_SIZE)

#define DES_KEY_SIZE				8			// DES key size
#define	DES_IV_SIZE					8			// DES IV size
#define DES_BLOCK_SIZE				8			// DES block size
#define DES3_KEY_SIZE				(8 * 3)		// 3DES key size
#define RSA_KEY_SIZE				128			// RSA key size
#define DH_KEY_SIZE					128			// DH key size
#define	RSA_MIN_SIGN_HASH_SIZE		(15 + SHA1_HASH_SIZE)	// Minimum RSA hash size
#define	RSA_SIGN_HASH_SIZE			(RSA_MIN_SIGN_HASH_SIZE)	// RSA hash size
#define MD5_HASH_SIZE				16			// MD5 hash size
#define SHA1_HASH_SIZE				20			// SHA-1 hash size
#define SHA1_BLOCK_SIZE				64			// SHA-1 block size
#define HMAC_SHA1_96_KEY_SIZE		20			// HMAC-SHA-1-96 key size
#define HMAC_SHA1_96_HASH_SIZE		12			// HMAC-SHA-1-96 hash size
#define HMAC_SHA1_SIZE				(SHA1_HASH_SIZE)	// HMAC-SHA-1 hash size
#define	AES_IV_SIZE					16			// AES IV size
#define	AES_MAX_KEY_SIZE			32			// Maximum AES key size

// RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
#define AEAD_CHACHA20_POLY1305_MAC_SIZE		16	// MAC size
#define AEAD_CHACHA20_POLY1305_NONCE_SIZE	12	// Nonce size
#define AEAD_CHACHA20_POLY1305_KEY_SIZE		32	// Key size

// OpenSSL default cipher algorithms
#define	OPENSSL_DEFAULT_CIPHER_LIST "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2"

// OpenSSL 3.x has a bug. https://github.com/openssl/openssl/issues/13363 https://github.com/openssl/openssl/pull/13378
// At 2021-09-08 this bug is reported as fixed on Github, but actually still exists on RC4-MD5.
// So, with OpenSSL 3.0 we manually disable RC4-MD5 by default on both SSL server and SSL client.
#define	OPENSSL_DEFAULT_CIPHER_LIST_NO_RC4_MD5  (OPENSSL_DEFAULT_CIPHER_LIST ":!RC4-MD5")

// IANA definitions taken from IKEv1 Phase 1
#define SHA1_160						2
#define SHA2_256						4
#define SHA2_384						5
#define SHA2_512						6

// HMAC block size
#define	HMAC_BLOCK_SIZE					64
// The block size for sha-384 and sha-512 as defined by rfc4868
#define HMAC_BLOCK_SIZE_1024			128
#define HMAC_BLOCK_SIZE_MAX				512

#define DH_GROUP1_PRIME_768 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

#define DH_GROUP2_PRIME_1024 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
	"FFFFFFFFFFFFFFFF"

#define DH_GROUP5_PRIME_1536 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"

#define	DH_SIMPLE_160	"AEE7561459353C95DDA966AE1FD25D95CD46E935"

#define	DH_SET_2048 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

#define	DH_SET_3072	\
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"\
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"\
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"\
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"\
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"\
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"\
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"\
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"\
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"\
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

#define	DH_SET_4096 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" \
	"FFFFFFFFFFFFFFFF"

// Macro
#define	HASHED_DATA(p)			(((UCHAR *)p) + 15)

// OpenSSL <1.1 Shims
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#	define EVP_PKEY_get0_RSA(obj) ((obj)->pkey.rsa)
#	define EVP_PKEY_base_id(pkey) ((pkey)->type)
#	define X509_get0_notBefore(x509) ((x509)->cert_info->validity->notBefore)
#	define X509_get0_notAfter(x509) ((x509)->cert_info->validity->notAfter)
#	define X509_get_serialNumber(x509) ((x509)->cert_info->serialNumber)
#endif

// Crypt context
struct CRYPT
{
	struct rc4_key_st *Rc4Key;
};

// Name in the certificate
struct NAME
{
	wchar_t *CommonName;		// CN
	wchar_t *Organization;		// O
	wchar_t *Unit;				// OU
	wchar_t *Country;			// C
	wchar_t *State;				// ST
	wchar_t *Local;				// L
};

// Serial number
struct X_SERIAL
{
	UINT size;
	UCHAR *data;
};

// Certificate
struct X
{
	X509 *x509;
	NAME *issuer_name;
	NAME *subject_name;
	bool root_cert;
	UINT64 notBefore;
	UINT64 notAfter;
	X_SERIAL *serial;
	bool do_not_free;
	bool is_compatible_bit;
	UINT bits;
	bool has_basic_constraints;
	char issuer_url[256];
};

// Key
struct K
{
	EVP_PKEY *pkey;
	bool private_key;
};

// PKCS#12
struct P12
{
	PKCS12 *pkcs12;
};

// CEL
struct X_CRL
{
	X509_CRL *Crl;
};

// Constant
#define	MD5_SIZE	16
#define	SHA1_SIZE	20
#define	SHA256_SIZE	32
#define	SHA384_SIZE	48
#define	SHA512_SIZE	64

// Key element of DES
struct DES_KEY_VALUE
{
	struct DES_ks *KeySchedule;
	UCHAR KeyValue[DES_KEY_SIZE];
};

// DES key
struct DES_KEY
{
	DES_KEY_VALUE *k1, *k2, *k3;
};

// AES key
struct AES_KEY_VALUE
{
	struct aes_key_st *EncryptKey;
	struct aes_key_st *DecryptKey;
	UCHAR KeyValue[AES_MAX_KEY_SIZE];
	UINT KeySize;
};

// DH
struct DH_CTX
{
	struct dh_st *dh;
	BUF *MyPublicKey;
	BUF *MyPrivateKey;
	UINT Size;
};

// Cipher object
struct CIPHER
{
	char Name[MAX_PATH];
	bool IsNullCipher;
	const struct evp_cipher_st *Cipher;
	struct evp_cipher_ctx_st *Ctx;
	bool Encrypt;
	UINT BlockSize, IvSize, KeySize;
};

// Message digest object
struct MD
{
	char Name[MAX_PATH];
	const struct evp_md_st *Md;
	struct hmac_ctx_st *Ctx;
	UINT Size;
};

// Seed based rand
struct SEEDRAND
{
	UCHAR InitialSeed[SHA1_SIZE];
	UINT64 CurrentCounter;
};

// X.509 cert list and key
struct CERTS_AND_KEY
{
	REF* Ref;
	LIST* CertList;
	K* Key;
	UINT64 HashCache;
	bool HasValidPrivateKey;

	bool (*DetermineUseCallback)(char*, void*);
};

// Lock of the OpenSSL
extern LOCK **ssl_lock_obj;

// Function prototype
CRYPT *NewCrypt(void *key, UINT size);
void FreeCrypt(CRYPT *c);
void Encrypt(CRYPT *c, void *dst, void *src, UINT size);
void Hash(void *dst, void *src, UINT size, bool sha);
void HashSha1(void *dst, void *src, UINT size);
void HashSha256(void *dst, void *src, UINT size);
void HashMd4(void *dst, void *src, UINT size);
void HashMd4(void *dst, void *src, UINT size);
void InitCryptLibrary();
void Rand(void *buf, UINT size);
void Rand128(void *buf);
UINT HashToUINT(void *data, UINT size);
UINT64 Rand64();
UINT Rand32();
USHORT Rand16();
UCHAR Rand8();
bool Rand1();
UINT HashPtrToUINT(void *p);

SEEDRAND *NewSeedRand(void *seed, UINT seed_size);
void FreeSeedRand(SEEDRAND *r);
UCHAR SeedRand8(SEEDRAND *r);
void SeedRand(SEEDRAND *r, void *buf, UINT size);
USHORT SeedRand16(SEEDRAND *r);
UINT SeedRand32(SEEDRAND *r);
UINT64 SeedRand64(SEEDRAND* r);


CERTS_AND_KEY* NewCertsAndKeyFromMemory(LIST* cert_buf_list, BUF* key_buf);
CERTS_AND_KEY* NewCertsAndKeyFromObjects(LIST* cert_list, K* key, bool fast);
CERTS_AND_KEY* NewCertsAndKeyFromObjectSingle(X *cert, K* key, bool fast);
CERTS_AND_KEY* NewCertsAndKeyFromDir(wchar_t* dir_name);
bool SaveCertsAndKeyToDir(CERTS_AND_KEY *c, wchar_t* dir);
void ReleaseCertsAndKey(CERTS_AND_KEY* c);
void CleanupCertsAndKey(CERTS_AND_KEY* c);
CERTS_AND_KEY* CloneCertsAndKey(CERTS_AND_KEY* c);
void FreeCertsAndKeyList(LIST* o);
LIST* CloneCertsAndKeyList(LIST* o);
void UpdateCertsAndKeyHashCacheAndCheckedState(CERTS_AND_KEY* c);
UINT64 CalcCertsAndKeyHashCache(CERTS_AND_KEY* c);
UINT64 GetCertsAndKeyHash(CERTS_AND_KEY* c);
UINT64 GetCertsAndKeyListHash(LIST* o);
bool CheckCertsAndKey(CERTS_AND_KEY* c);
bool CertsAndKeyAlwaysUseCallback(char* sni_name, void* param);

LIST* BufToXList(BUF* b);
void FreeXList(LIST* o);

void CertTest();
BIO *BufToBio(BUF *b);
BUF *BioToBuf(BIO *bio);
BIO *NewBio();
void FreeBio(BIO *bio);
X *BioToX(BIO *bio, bool text);
X *BufToX(BUF *b, bool text);
BUF *SkipBufBeforeString(BUF *b, char *str);
void FreeX509(X509 *x509);
void FreeX(X *x);
BIO *XToBio(X *x, bool text);
BUF *XToBuf(X *x, bool text);
K *BioToK(BIO *bio, bool private_key, bool text, char *password);
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param);
void FreePKey(EVP_PKEY *pkey);
void FreeK(K *k);
K *BufToK(BUF *b, bool private_key, bool text, char *password);
bool IsEncryptedK(BUF *b, bool private_key);
bool IsBase64(BUF *b);
BIO *KToBio(K *k, bool text, char *password);
BUF *KToBuf(K *k, bool text, char *password);
X *FileToX(char *filename);
X *FileToXW(wchar_t *filename);
bool XToFile(X *x, char *filename, bool text);
bool XToFileW(X *x, wchar_t *filename, bool text);
K *FileToK(char *filename, bool private_key, char *password);
K *FileToKW(wchar_t *filename, bool private_key, char *password);
bool KToFile(K *k, char *filename, bool text, char *password);
bool KToFileW(K *k, wchar_t *filename, bool text, char *password);
bool CheckXandK(X *x, K *k);
bool CompareX(X *x1, X *x2);
NAME *X509NameToName(void *xn);
wchar_t *GetUniStrFromX509Name(void *xn, int nid);
void LoadXNames(X *x);
void FreeXNames(X *x);
void FreeName(NAME *n);
bool CompareName(NAME *n1, NAME *n2);
K *GetKFromX(X *x);
bool CheckSignature(X *x, K *k);
X *X509ToX(X509 *x509);
bool CheckX(X *x, X *x_issuer);
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date);
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time);
bool StrToSystem(SYSTEMTIME *s, char *str);
UINT64 Asn1TimeToUINT64(void *asn1_time);
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s);
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t);
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s);
void LoadXDates(X *x);
bool CheckXDate(X *x, UINT64 current_system_time);
bool CheckXDateNow(X *x);
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local);
void *NameToX509Name(NAME *nm);
void FreeX509Name(void *xn);
bool AddX509Name(void *xn, int nid, wchar_t *str);
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X509 *NewX509Ex(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial, NAME *name_issuer);
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X *NewXEx(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial, NAME *name_issuer);
UINT GetDaysUntil2038();
UINT GetDaysUntil2038Ex();
X_SERIAL *NewXSerial(void *data, UINT size);
void FreeXSerial(X_SERIAL *serial);
char *ByteToStr(BYTE *src, UINT src_size);
P12 *BioToP12(BIO *bio);
P12 *PKCS12ToP12(PKCS12 *pkcs12);
P12 *BufToP12(BUF *b);
BIO *P12ToBio(P12 *p12);
BUF *P12ToBuf(P12 *p12);
void FreePKCS12(PKCS12 *pkcs12);
void FreeP12(P12 *p12);
P12 *FileToP12(char *filename);
P12 *FileToP12W(wchar_t *filename);
bool P12ToFile(P12 *p12, char *filename);
bool P12ToFileW(P12 *p12, wchar_t *filename);
bool ParseP12(P12 *p12, X **x, K **k, char *password);
bool IsEncryptedP12(P12 *p12);
P12 *NewP12(X *x, K *k, char *password);
X *CloneX(X *x);
K *CloneK(K *k);
X* CloneXFast(X* x);
K* CloneKFast(K* k);
void FreeCryptLibrary();
void GetPrintNameFromX(wchar_t *str, UINT size, X *x);
void GetPrintNameFromXA(char *str, UINT size, X *x);
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromX(wchar_t *str, UINT size, X *x);
void GetAllNameFromA(char *str, UINT size, X *x);
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromXEx(wchar_t *str, UINT size, X *x);
void GetAllNameFromXExA(char *str, UINT size, X *x);
BUF *BigNumToBuf(const BIGNUM *bn);
BIGNUM *BinToBigNum(void *data, UINT size);
BIGNUM *BufToBigNum(BUF *b);
char *BigNumToStr(BIGNUM *bn);
X_SERIAL *CloneXSerial(X_SERIAL *src);
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2);
void GetXDigest(X *x, UCHAR *buf, bool sha1);
NAME *CopyName(NAME *n);


bool RsaGen(K **priv, K **pub, UINT bit);
bool RsaCheck();
bool RsaCheckEx();
bool RsaPublicEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPublicDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaSign(void *dst, void *src, UINT size, K *k);
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits);
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size);
bool RsaVerify(void *data, UINT data_size, void *sign, K *k);
bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits);
UINT RsaPublicSize(K *k);
void RsaPublicToBin(K *k, void *data);
BUF *RsaPublicToBuf(K *k);
K *RsaBinToPublic(void *data, UINT size);

X_CRL *FileToXCrl(char *filename);
X_CRL *FileToXCrlW(wchar_t *filename);
X_CRL *BufToXCrl(BUF *b);
void FreeXCrl(X_CRL *r);
bool IsXRevokedByXCrl(X *x, X_CRL *r);
bool IsXRevoked(X *x);

DES_KEY_VALUE *DesNewKeyValue(void *value);
DES_KEY_VALUE *DesRandKeyValue();
void DesFreeKeyValue(DES_KEY_VALUE *v);
DES_KEY *Des3NewKey(void *k1, void *k2, void *k3);
void Des3FreeKey(DES_KEY *k);
DES_KEY *DesNewKey(void *k1);
void DesFreeKey(DES_KEY *k);
DES_KEY *Des3RandKey();
DES_KEY *DesRandKey();
void Des3Encrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec);
void Des3Encrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec);
void Des3Decrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec);
void Des3Decrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec);
void Sha(UINT sha_type, void *dst, void *src, UINT size);
void Sha1(void *dst, void *src, UINT size);
void Sha2_256(void *dst, void *src, UINT size);
void Sha2_384(void *dst, void *src, UINT size);
void Sha2_512(void *dst, void *src, UINT size);

void Md5(void *dst, void *src, UINT size);
void MacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size);
void MacSha196(void *dst, void *key, void *data, UINT data_size);
void DesEncrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec);
void DesDecrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec);
void DesEcbEncrypt(void *dst, void *src, void *key_7bytes);

bool DhCompute(DH_CTX *dh, void *dst_priv_key, void *src_pub_key, UINT key_size);
DH_CTX *DhNewGroup1();
DH_CTX *DhNewGroup2();
DH_CTX *DhNewGroup5();
DH_CTX *DhNewSimple160();
DH_CTX *DhNew2048();
DH_CTX *DhNew3072();
DH_CTX *DhNew4096();
DH_CTX *DhNew(char *prime, UINT g);
void DhFree(DH_CTX *dh);
BUF *DhToBuf(DH_CTX *dh);

AES_KEY_VALUE *AesNewKey(void *data, UINT size);
void AesFreeKey(AES_KEY_VALUE *k);
void AesEncrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
void AesDecrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);

bool IsIntelAesNiSupported();
void CheckIfIntelAesNiSupportedInit();

#ifdef	USE_INTEL_AESNI_LIBRARY
void AesEncryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
void AesDecryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
#endif	// USE_INTEL_AESNI_LIBRARY

void OpenSSL_InitLock();
void OpenSSL_FreeLock();
void OpenSSL_Lock(int mode, int n, const char *file, int line);
unsigned long OpenSSL_Id(void);
void FreeOpenSSLThreadState();

CIPHER *NewCipher(char *name);
void FreeCipher(CIPHER *c);
void SetCipherKey(CIPHER *c, void *key, bool enc);
UINT CipherProcess(CIPHER *c, void *iv, void *dest, void *src, UINT size);

MD *NewMd(char *name);
void FreeMd(MD *md);
void SetMdKey(MD *md, void *key, UINT key_size);
void MdProcess(MD *md, void *dest, void *src, UINT size);
void Enc_tls1_PRF(unsigned char *label, int label_len, const unsigned char *sec,
				  int slen, unsigned char *out1, int olen);

void HMacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size);
void HMacMd5(void *dst, void *key, UINT key_size, void *data, UINT data_size);

BUF *EasyEncrypt(BUF *src_buf);
BUF *EasyDecrypt(BUF *src_buf);

void DisableIntelAesAccel();

int GetSslClientCertIndex();

void Aead_ChaCha20Poly1305_Ietf_Encrypt_Embedded(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);
bool Aead_ChaCha20Poly1305_Ietf_Decrypt_Embedded(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);

void Aead_ChaCha20Poly1305_Ietf_Encrypt_OpenSSL(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);
bool Aead_ChaCha20Poly1305_Ietf_Decrypt_OpenSSL(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);

void Aead_ChaCha20Poly1305_Ietf_Encrypt(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);
bool Aead_ChaCha20Poly1305_Ietf_Decrypt(void *dst, void *src, UINT src_size, void *key, void *nonce, void *aad, UINT aad_size);

bool Aead_ChaCha20Poly1305_Ietf_IsOpenSSL();

void Aead_ChaCha20Poly1305_Ietf_Test();





#ifdef	ENCRYPT_C
// Inner function


#endif	// ENCRYPT_C

#endif	// ENCRYPT_H

