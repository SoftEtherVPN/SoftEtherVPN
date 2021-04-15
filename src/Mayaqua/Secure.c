// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Secure.c
// Security token management module

#include "Secure.h"

#include "Encrypt.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cryptoki.h>

#define	MAX_OBJ				1024		// Maximum number of objects in the hardware (assumed)

#define	A_SIZE(a, i)		(a[(i)].ulValueLen)
#define	A_SET(a, i, value, size)	(a[i].pValue = value;a[i].ulValueLen = size;)

// Internal data structure
// The list of supported secure devices
static LIST *SecureDeviceList = NULL;

// Supported hardware list
const SECURE_DEVICE SupportedList[] =
{
	{1,		SECURE_IC_CARD,		"Standard-9 IC Card",	"Dai Nippon Printing",	"DNPS9P11.DLL"},
	{2,		SECURE_USB_TOKEN,	"ePass 1000",			"Feitian Technologies",	"EP1PK111.DLL"},
	{3,		SECURE_IC_CARD,		"DNP Felica",			"Dai Nippon Printing",	"DNPFP11.DLL"},
	{4,		SECURE_USB_TOKEN,	"eToken",				"Aladdin",				"ETPKCS11.DLL"},
	{5,		SECURE_IC_CARD,		"Standard-9 IC Card",	"Fujitsu",				"F3EZSCL2.DLL"},
	{6,		SECURE_IC_CARD,		"ASECard",				"Athena",				"ASEPKCS.DLL"},
	{7,		SECURE_IC_CARD,		"Gemplus IC Card",		"Gemplus",				"PK2PRIV.DLL"},
	{8,		SECURE_IC_CARD,		"1-Wire & iButton",		"DALLAS SEMICONDUCTOR",	"DSPKCS.DLL"},
	{9,		SECURE_IC_CARD,		"JPKI IC Card",			"Japanese Government",	"JPKIPKCS11.DLL"},
	{10,	SECURE_IC_CARD,		"LGWAN IC Card",		"Japanese Government",	"P11STD9.DLL"},
	{11,	SECURE_IC_CARD,		"LGWAN IC Card",		"Japanese Government",	"P11STD9A.DLL"},
	{12,	SECURE_USB_TOKEN,	"iKey 1000",			"Rainbow Technologies",	"K1PK112.DLL"},
	{13,	SECURE_IC_CARD,		"JPKI IC Card #2",		"Japanese Government",	"libmusclepkcs11.dll"},
	{14,	SECURE_USB_TOKEN,	"SafeSign",				"A.E.T.",				"aetpkss1.dll"},
	{15,	SECURE_USB_TOKEN,	"LOCK STAR-PKI",		"Logicaltech Co.,LTD",	"LTPKCS11.dll"},
	{16,	SECURE_USB_TOKEN,	"ePass 2000",			"Feitian Technologies",	"ep2pk11.dll"},
	{17,	SECURE_IC_CARD,		"myuToken",				"iCanal Inc.",			"icardmodpk.dll"},
	{18,	SECURE_IC_CARD,		"Gemalto .NET",			"Gemalto",				"gtop11dotnet.dll"},
	{19,	SECURE_IC_CARD,		"Gemalto .NET 64bit",	"Gemalto",				"gtop11dotnet64.dll"},
	{20,	SECURE_USB_TOKEN,	"ePass 2003",			"Feitian Technologies",	"eps2003csp11.dll"},
	{21,	SECURE_USB_TOKEN,	"ePass 1000ND/2000/3000",			"Feitian Technologies",	"ngp11v211.dll"},
	{22,	SECURE_USB_TOKEN,	"CryptoID",				"Longmai Technology",	"cryptoide_pkcs11.dll"},
	{23,	SECURE_USB_TOKEN,	"RuToken",				"Aktiv Co.",			"rtPKCS11.dll"},
};

#ifdef	OS_WIN32
// Win32 internal data
typedef struct SEC_DATA_WIN32
{
	HINSTANCE hInst;
} SEC_DATA_WIN32;

// DLL reading for Win32
HINSTANCE Win32SecureLoadLibraryEx(char *dllname, DWORD flags)
{
	char tmp1[MAX_PATH];
	char tmp2[MAX_PATH];
	char tmp3[MAX_PATH];
	HINSTANCE h;
	// Validate arguments
	if (dllname == NULL)
	{
		return NULL;
	}

	Format(tmp1, sizeof(tmp1), "%s\\%s", MsGetSystem32Dir(), dllname);
	Format(tmp2, sizeof(tmp2), "%s\\JPKI\\%s", MsGetProgramFilesDir(), dllname);
	Format(tmp3, sizeof(tmp3), "%s\\LGWAN\\%s", MsGetProgramFilesDir(), dllname);

	h = LoadLibraryEx(dllname, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp1, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp2, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	h = LoadLibraryEx(tmp3, NULL, flags);
	if (h != NULL)
	{
		return h;
	}

	return NULL;
}

// Examine whether the specified device is installed
bool Win32IsDeviceSupported(SECURE_DEVICE *dev)
{
	HINSTANCE hInst;
	// Validate arguments
	if (dev == NULL)
	{
		return false;
	}

	// Check whether the DLL is readable
	hInst = Win32SecureLoadLibraryEx(dev->ModuleName, DONT_RESOLVE_DLL_REFERENCES);
	if (hInst == NULL)
	{
		return false;
	}

	FreeLibrary(hInst);

	return true;
}

// Load the device module
bool Win32LoadSecModule(SECURE *sec)
{
	SEC_DATA_WIN32 *w;
	HINSTANCE hInst;
	CK_FUNCTION_LIST_PTR api = NULL;
	CK_RV (*get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}

	if (sec->Dev->Id == 9)
	{
		char username[MAX_SIZE];
		DWORD size;
		// Because the device driver of Juki-Net needs the contents 
		// of the Software\JPKI registry key on HKLU of SYSTEM,
		// if there is no key, copy the key from the value of other user
//		if (MsRegIsValue(REG_CURRENT_USER, "Software\\JPKI", "Name") == false ||
//			MsRegIsValue(REG_CURRENT_USER, "Software\\JPKI", "RWType") == false)
		size = sizeof(username);
		GetUserName(username, &size);
		if (StrCmpi(username, "System") == 0)
		{
			TOKEN_LIST *t = MsRegEnumKey(REG_USERS, NULL);

			if (t != NULL)
			{
				UINT i;

				for (i = 0;i < t->NumTokens;i++)
				{
					char tmp[MAX_PATH];

					if (StrCmpi(t->Token[i], ".DEFAULT") != 0 && StrCmpi(t->Token[i], "S-1-5-18") != 0)
					{
						Format(tmp, sizeof(tmp), "%s\\Software\\JPKI", t->Token[i]);

						if (MsRegIsValue(REG_USERS, tmp, "Name") && MsRegIsValue(REG_USERS, tmp, "RWType"))
						{
							char *name = MsRegReadStr(REG_USERS, tmp, "Name");
							char *port = MsRegReadStr(REG_USERS, tmp, "Port");
							UINT type = MsRegReadInt(REG_USERS, tmp, "RWType");

							MsRegWriteStr(REG_CURRENT_USER, "Software\\JPKI", "Name", name);
							MsRegWriteStr(REG_CURRENT_USER, "Software\\JPKI", "Port", port);
							MsRegWriteInt(REG_CURRENT_USER, "Software\\JPKI", "RWType", type);

							Free(name);
							Free(port);
							break;
						}
					}
				}

				FreeToken(t);
			}
		}
	}

	// Load the Library
	hInst = Win32SecureLoadLibraryEx(sec->Dev->ModuleName, 0);
	if (hInst == NULL)
	{
		// Failure
		return false;
	}

	// Get the API
	get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
		GetProcAddress(hInst, "C_GetFunctionList");

	if (get_function_list == NULL)
	{
		// Failure
		FreeLibrary(hInst);
		return false;
	}

	get_function_list(&api);
	if (api == NULL)
	{
		// Failure
		FreeLibrary(hInst);
		return false;
	}

	sec->Data = ZeroMalloc(sizeof(SEC_DATA_WIN32));
	w = sec->Data;

	w->hInst = hInst;
	sec->Api = api;

	return true;
}

// Unload the device module
void Win32FreeSecModule(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}
	if (sec->Data == NULL)
	{
		return;
	}

	// Unload
	FreeLibrary(sec->Data->hInst);
	Free(sec->Data);

	sec->Data = NULL;
}

#endif	// OS_WIN32


// Whether the specified device is a JPKI
bool IsJPKI(bool id)
{
	if (id == 9 || id == 13)
	{
		return true;
	}

	return false;
}

// Sign with the private key which is specified by the name in the secure device
bool SignSec(SECURE *sec, char *name, void *dst, void *src, UINT size)
{
	SEC_OBJ *obj;
	UINT ret;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL || dst == NULL || src == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	obj = FindSecObject(sec, name, SEC_K);
	if (obj == NULL)
	{
		return false;
	}

	ret = SignSecByObject(sec, obj, dst, src, size);

	FreeSecObject(obj);

	return ret;
}

// Sign with the private key of the secure device
bool SignSecByObject(SECURE *sec, SEC_OBJ *obj, void *dst, void *src, UINT size)
{
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
	UINT ret;
	UCHAR hash[SIGN_HASH_SIZE];
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (obj == NULL || dst == NULL || src == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (obj->Type != SEC_K)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	// Hash
	HashForSign(hash, sizeof(hash), src, size);

	// Signature initialization
	ret = sec->Api->C_SignInit(sec->SessionId, &mechanism, obj->Object);
	if (ret != CKR_OK)
	{
		// Failure
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("C_SignInit Error: 0x%x\n", ret);
		return false;
	}

	// Perform Signing
	size = 128;
	// First try with 1024 bit
	ret = sec->Api->C_Sign(sec->SessionId, hash, sizeof(hash), dst, &size);
	if (ret != CKR_OK && 128 < size && size <= 4096/8)
	{
		// Retry with expanded bits
		ret = sec->Api->C_Sign(sec->SessionId, hash, sizeof(hash), dst, &size);
	}
	if (ret != CKR_OK || size == 0 || size > 4096/8)
	{
		// Failure
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("C_Sign Error: 0x%x  size:%d\n", ret, size);
		return false;
	}

	return true;
}

// Changing the PIN code
bool ChangePin(SECURE *sec, char *old_pin, char *new_pin)
{
	// Validate arguments
	if (sec == NULL || old_pin == NULL || new_pin == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (sec->IsReadOnly)
	{
		sec->Error = SEC_ERROR_OPEN_SESSION;
		return false;
	}

	// Change then PIN
	if (sec->Api->C_SetPIN(sec->SessionId, old_pin, StrLen(old_pin),
		new_pin, StrLen(new_pin)) != CKR_OK)
	{
		return false;
	}

	return true;
}

// Write the private key object
bool WriteSecKey(SECURE *sec, bool private_obj, char *name, K *k)
{
	UINT key_type = CKK_RSA;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT obj_class = CKO_PRIVATE_KEY;
	UINT object;
	UINT ret;
	BUF *b;
	RSA *rsa;
	UCHAR modules[MAX_SIZE], pub[MAX_SIZE], pri[MAX_SIZE], prime1[MAX_SIZE], prime2[MAX_SIZE];
	UCHAR exp1[MAX_SIZE], exp2[MAX_SIZE], coeff[MAX_SIZE];
	const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	CK_ATTRIBUTE a[] =
	{
		{CKA_MODULUS,			modules,		0},		// 0
		{CKA_PUBLIC_EXPONENT,	pub,			0},		// 1
		{CKA_PRIVATE_EXPONENT,	pri,			0},		// 2
		{CKA_PRIME_1,			prime1,			0},		// 3
		{CKA_PRIME_2,			prime2,			0},		// 4
		{CKA_EXPONENT_1,		exp1,			0},		// 5
		{CKA_EXPONENT_2,		exp2,			0},		// 6
		{CKA_COEFFICIENT,		coeff,			0},		// 7

		{CKA_CLASS,				&obj_class,		sizeof(obj_class)},
		{CKA_TOKEN,				&b_true,		sizeof(b_true)},
		{CKA_PRIVATE,			&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,				name,			StrLen(name)},
		{CKA_KEY_TYPE,			&key_type,		sizeof(key_type)},
		{CKA_DERIVE,			&b_false,		sizeof(b_false)},
		{CKA_SUBJECT,			name,			StrLen(name)},
		{CKA_SENSITIVE,			&b_true,		sizeof(b_true)},
		{CKA_DECRYPT,			&b_true,		sizeof(b_true)},
		{CKA_SIGN,				&b_true,		sizeof(b_true)},
		{CKA_SIGN_RECOVER,		&b_false,		sizeof(b_false)},
		{CKA_EXTRACTABLE,		&b_false,		sizeof(b_false)},
		{CKA_MODIFIABLE,		&b_false,		sizeof(b_false)},
	};

	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL || k == NULL || k->private_key == false)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && private_obj)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// Numeric data generation
	rsa = EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RSA_get0_key(rsa, &n, &e, &d);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
#else
	n = rsa->n;
	e = rsa->e;
	d = rsa->d;
	p = rsa->p;
	q = rsa->q;
	dmp1 = rsa->dmp1;
	dmq1 = rsa->dmq1;
	iqmp = rsa->iqmp;
#endif

	b = BigNumToBuf(n);
	ReadBuf(b, modules, sizeof(modules));
	A_SIZE(a, 0) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(e);
	ReadBuf(b, pub, sizeof(pub));
	A_SIZE(a, 1) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(d);
	ReadBuf(b, pri, sizeof(pri));
	A_SIZE(a, 2) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(p);
	ReadBuf(b, prime1, sizeof(prime1));
	A_SIZE(a, 3) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(q);
	ReadBuf(b, prime2, sizeof(prime2));
	A_SIZE(a, 4) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(dmp1);
	ReadBuf(b, exp1, sizeof(exp1));
	A_SIZE(a, 5) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(dmq1);
	ReadBuf(b, exp2, sizeof(exp2));
	A_SIZE(a, 6) = b->Size;
	FreeBuf(b);

	b = BigNumToBuf(iqmp);
	ReadBuf(b, coeff, sizeof(coeff));
	A_SIZE(a, 7) = b->Size;
	FreeBuf(b);

	// Delete the old key if it exists
	if (CheckSecObject(sec, name, SEC_K))
	{
		DeleteSecKey(sec, name);
	}

	// Creating
	if ((ret = sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object)) != CKR_OK)
	{
		// Failure
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("ret: 0x%x\n", ret);
		return false;
	}

	// Clear Cache
	EraseEnumSecObjectCache(sec);

	return true;
}

// Read the certificate object by specifying the name
X *ReadSecCert(SECURE *sec, char *name)
{
	SEC_OBJ *obj;
	X *x;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}

	// Search
	obj = FindSecObject(sec, name, SEC_X);
	if (obj == NULL)
	{
		return false;
	}

	// Acquisition
	x = ReadSecCertFromObject(sec, obj);

	FreeSecObject(obj);

	return x;
}

// Read the certificate object
X *ReadSecCertFromObject(SECURE *sec, SEC_OBJ *obj)
{
	UINT size;
	X *x;
	UCHAR value[4096];
	BUF *b;
	CK_ATTRIBUTE get[] =
	{
		{CKA_VALUE,		value,		sizeof(value)},
	};
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (obj->Type != SEC_X)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	// Acquisition
	if (sec->Api->C_GetAttributeValue(
		sec->SessionId, obj->Object, get, sizeof(get) / sizeof(get[0])) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return 0;
	}

	size = A_SIZE(get, 0);

	// Conversion
	b = NewBuf();
	WriteBuf(b, value, size);
	SeekBuf(b, 0, 0);

	x = BufToX(b, false);
	if (x == NULL)
	{
		sec->Error = SEC_ERROR_INVALID_CERT;
	}

	FreeBuf(b);

	return x;
}

// Write the certificate object
bool WriteSecCert(SECURE *sec, bool private_obj, char *name, X *x)
{
	UINT obj_class = CKO_CERTIFICATE;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT cert_type = CKC_X_509;
	CK_DATE start_date, end_date;
	UCHAR subject[MAX_SIZE];
	UCHAR issuer[MAX_SIZE];
	wchar_t w_subject[MAX_SIZE];
	wchar_t w_issuer[MAX_SIZE];
	UCHAR serial_number[MAX_SIZE];
	UCHAR value[4096];
	UINT ret;
	BUF *b;
	UINT object;
	CK_ATTRIBUTE a[] =
	{
		{CKA_SUBJECT,			subject,		0},			// 0
		{CKA_ISSUER,			issuer,			0},			// 1
		{CKA_SERIAL_NUMBER,		serial_number,	0},			// 2
		{CKA_VALUE,				value,			0},			// 3
		{CKA_CLASS,				&obj_class,		sizeof(obj_class)},
		{CKA_TOKEN,				&b_true,		sizeof(b_true)},
		{CKA_PRIVATE,			&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,				name,			StrLen(name)},
		{CKA_CERTIFICATE_TYPE,	&cert_type,		sizeof(cert_type)},
#if	0		// Don't use these because some tokens fail
		{CKA_START_DATE,		&start_date,	sizeof(start_date)},
		{CKA_END_DATE,			&end_date,		sizeof(end_date)},
#endif
	};
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && private_obj)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// Copy the certificate to the buffer
	b = XToBuf(x, false);
	if (b == NULL)
	{
		sec->Error = SEC_ERROR_INVALID_CERT;
		return false;
	}
	if (b->Size > sizeof(value))
	{
		// Size is too large
		FreeBuf(b);
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return false;
	}
	Copy(value, b->Buf, b->Size);
	A_SIZE(a, 3) = b->Size;
	FreeBuf(b);

	// Store the Subject and the Issuer by encoding into UTF-8
	GetPrintNameFromName(w_subject, sizeof(w_subject), x->subject_name);
	UniToUtf8(subject, sizeof(subject), w_subject);
	A_SIZE(a, 0) = StrLen(subject);
	if (x->root_cert == false)
	{
		GetPrintNameFromName(w_issuer, sizeof(w_issuer), x->issuer_name);
		UniToUtf8(issuer, sizeof(issuer), w_issuer);
		A_SIZE(a, 1) = StrLen(issuer);
	}

	// Copy the serial number
	Copy(serial_number, x->serial->data, MIN(x->serial->size, sizeof(serial_number)));
	A_SIZE(a, 2) = MIN(x->serial->size, sizeof(serial_number));

	// Expiration date information
	UINT64ToCkDate(&start_date, SystemToLocal64(x->notBefore));
	UINT64ToCkDate(&end_date, SystemToLocal64(x->notAfter));

	// Workaround for Gemalto PKCS#11 API. It rejects a private certificate.
	if(sec->Dev->Id == 18 || sec->Dev->Id == 19)
	{
		b_private_obj = false;
	}

	// Remove objects which have the same name
	if (CheckSecObject(sec, name, SEC_X))
	{
		DeleteSecCert(sec, name);
	}

	// Creating
	if ((ret = sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object)) != CKR_OK)
	{
		// Failure
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		Debug("Error: 0x%02x\n", ret);
		return false;
	}

	// Clear Cache
	EraseEnumSecObjectCache(sec);

	return true;
}

// Delete the private key object
bool DeleteSecKey(SECURE *sec, char *name)
{
	return DeleteSecObjectByName(sec, name, SEC_K);
}

// Delete the certificate object
bool DeleteSecCert(SECURE *sec, char *name)
{
	return DeleteSecObjectByName(sec, name, SEC_X);
}

// Convert the the CK_DATE to the 64 bit time
UINT64 CkDateToUINT64(struct CK_DATE *ck_date)
{
	SYSTEMTIME st;
	char year[32], month[32], day[32];
	// Validate arguments
	if (ck_date == NULL)
	{
		return 0;
	}

	Zero(year, sizeof(year));
	Zero(month, sizeof(month));
	Zero(day, sizeof(day));

	Copy(year, ck_date->year, 4);
	Copy(month, ck_date->month, 2);
	Copy(day, ck_date->day, 2);

	st.wYear = ToInt(year);
	st.wMonth = ToInt(month);
	st.wDay = ToInt(day);

	return SystemToUINT64(&st);
}

// Convert the 64 bit time to the CK_DATE
void UINT64ToCkDate(void *p_ck_date, UINT64 time64)
{
	SYSTEMTIME st;
	char year[32], month[32], day[32];
	struct CK_DATE *ck_date = (CK_DATE *)p_ck_date;
	// Validate arguments
	if (ck_date == NULL)
	{
		return;
	}

	UINT64ToSystem(&st, time64);

	Format(year, sizeof(year), "%04u", st.wYear);
	Format(month, sizeof(month), "%04u", st.wMonth);
	Format(day, sizeof(day), "%04u", st.wDay);

	Zero(ck_date, sizeof(CK_DATE));

	Copy(ck_date->year, year, 4);
	Copy(ck_date->month, month, 2);
	Copy(ck_date->day, day, 2);
}

// Delete the object by specifying the name
bool DeleteSecObjectByName(SECURE *sec, char *name, UINT type)
{
	bool ret;
	SEC_OBJ *obj;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}

	// Get the Object
	obj = FindSecObject(sec, name, type);
	if (obj == NULL)
	{
		// Failure
		return false;
	}

	// Delete the Object 
	ret = DeleteSecObject(sec, obj);

	// Memory release
	FreeSecObject(obj);

	return ret;
}

// Delete the Data
bool DeleteSecData(SECURE *sec, char *name)
{
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}

	return DeleteSecObjectByName(sec, name, SEC_DATA);
}

// Delete the secure object
bool DeleteSecObject(SECURE *sec, SEC_OBJ *obj)
{
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (obj == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}

	// Delete the Object
	if (sec->Api->C_DestroyObject(sec->SessionId, obj->Object) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return false;
	}

	// Clear the Cache
	DeleteSecObjFromEnumCache(sec, obj->Name, obj->Type);

	return true;
}

// Remove the object which have the specified name from the cache
void DeleteSecObjFromEnumCache(SECURE *sec, char *name, UINT type)
{
	UINT i;
	// Validate arguments
	if (sec == NULL || name == NULL || sec->EnumCache == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(sec->EnumCache);i++)
	{
		SEC_OBJ *obj = LIST_DATA(sec->EnumCache, i);

		if (StrCmpi(obj->Name, name) == 0)
		{
			if (obj->Type == type)
			{
				Delete(sec->EnumCache, obj);
				FreeSecObject(obj);
				break;
			}
		}
	}
}

// Read by searching a secure object by name
int ReadSecData(SECURE *sec, char *name, void *data, UINT size)
{
	UINT ret = 0;
	SEC_OBJ *obj;
	// Validate arguments
	if (sec == NULL || name == NULL || data == NULL)
	{
		return 0;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	// Read
	obj = FindSecObject(sec, name, SEC_DATA);
	if (obj == NULL)
	{
		// Not found
		return 0;
	}

	// Read
	ret = ReadSecDataFromObject(sec, obj, data, size);

	FreeSecObject(obj);

	return ret;
}

// Clear the cache
void EraseEnumSecObjectCache(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL || sec->EnumCache == NULL)
	{
		return;
	}

	FreeEnumSecObject(sec->EnumCache);
	sec->EnumCache = NULL;
}

// Check for the existence of a secure object
bool CheckSecObject(SECURE *sec, char *name, UINT type)
{
	SEC_OBJ *obj;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	obj = FindSecObject(sec, name, type);

	if (obj == NULL)
	{
		return false;
	}
	else
	{
		FreeSecObject(obj);
		return true;
	}
}

// Cloning a secure object structure
SEC_OBJ *CloneSecObject(SEC_OBJ *obj)
{
	SEC_OBJ *ret;
	// Validate arguments
	if (obj == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(SEC_OBJ));
	ret->Name = CopyStr(obj->Name);
	ret->Object = obj->Object;
	ret->Private = obj->Private;
	ret->Type = obj->Type;

	return ret;
}

// Search a secure object by the name
SEC_OBJ *FindSecObject(SECURE *sec, char *name, UINT type)
{
	LIST *o;
	UINT i;
	SEC_OBJ *ret = NULL;
	// Validate arguments
	if (sec == NULL)
	{
		return NULL;
	}
	if (name == NULL)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return NULL;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}

	// Enumeration
	o = EnumSecObject(sec);
	if (o == NULL)
	{
		return NULL;
	}
	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		if (obj->Type == type || type == INFINITE)
		{
			if (StrCmpi(obj->Name, name) == 0)
			{
				ret = CloneSecObject(obj);
				break;
			}
		}
	}
	FreeEnumSecObject(o);

	if (ret == NULL)
	{
		sec->Error = SEC_ERROR_OBJ_NOT_FOUND;
	}

	return ret;
}

// Reading a secure object
int ReadSecDataFromObject(SECURE *sec, SEC_OBJ *obj, void *data, UINT size)
{
	UCHAR buf[MAX_SEC_DATA_SIZE];
	UINT i;
	CK_ATTRIBUTE get[] =
	{
		{CKA_VALUE,	 buf,	sizeof(buf)},
	};
	// Validate arguments
	if (sec == NULL)
	{
		return 0;
	}
	if (obj == NULL || data == NULL || size == 0)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return 0;
	}
	if (obj->Type != SEC_DATA)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return 0;
	}
	if (sec->LoginFlag == false && obj->Private)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return 0;
	}

	// Acquisition
	if (sec->Api->C_GetAttributeValue(
		sec->SessionId, obj->Object, get, sizeof(get) / sizeof(get[0])) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return 0;
	}

	// Return the result
	i = get[0].ulValueLen;
	if (i > MAX_SEC_DATA_SIZE || i > size)
	{
		// Data is too large
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return 0;
	}

	// Memory copy
	Copy(data, buf, i);

	return i;
}

// Release of enumeration results of the secure object
void FreeEnumSecObject(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		FreeSecObject(obj);
	}

	ReleaseList(o);
}

// Release the secure object
void FreeSecObject(SEC_OBJ *obj)
{
	// Validate arguments
	if (obj == NULL)
	{
		return;
	}

	Free(obj->Name);
	Free(obj);
}

// Clone the secure object enumeration results
LIST *CloneEnumSecObject(LIST *o)
{
	LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(NULL);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		SEC_OBJ *obj = LIST_DATA(o, i);

		Add(ret, CloneSecObject(obj));
	}

	return ret;
}

// Enumeration of the secure objects
LIST *EnumSecObject(SECURE *sec)
{
	CK_BBOOL b_true = true, b_false = false;
	UINT objects[MAX_OBJ];
	UINT i;
	UINT ret;
	LIST *o;
	CK_ATTRIBUTE dummy[1];
	CK_ATTRIBUTE a[] =
	{
		{CKA_TOKEN,		&b_true,		sizeof(b_true)},
	};
	UINT num_objects = MAX_OBJ;
	// Validate arguments
	if (sec == NULL)
	{
		return NULL;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return NULL;
	}

	Zero(dummy, sizeof(dummy));

	// If there is a cache, return it
	if (sec->EnumCache != NULL)
	{
		return CloneEnumSecObject(sec->EnumCache);
	}

	// Enumerate
//	if (sec->Dev->Id != 2 && sec->Dev->Id != 14)
//	{
		// Normal tokens
		ret = sec->Api->C_FindObjectsInit(sec->SessionId, a, sizeof(a) / sizeof(a[0]));
//	}
//	else
//	{
		// ePass and SafeSign
//		ret = sec->Api->C_FindObjectsInit(sec->SessionId, dummy, 0);
//	}

	if (ret != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return NULL;
	}
	if (sec->Api->C_FindObjects(sec->SessionId, objects, sizeof(objects) / sizeof(objects[0]), &num_objects) != CKR_OK)
	{
		sec->Api->C_FindObjectsFinal(sec->SessionId);
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return NULL;
	}
	sec->Api->C_FindObjectsFinal(sec->SessionId);

	o = NewListFast(NULL);

	for (i = 0;i < num_objects;i++)
	{
		char label[MAX_SIZE];
		UINT obj_class = 0;
		bool priv = false;
		CK_ATTRIBUTE get[] =
		{
			{CKA_LABEL, label, sizeof(label) - 1},
			{CKA_CLASS, &obj_class, sizeof(obj_class)},
			{CKA_PRIVATE, &priv, sizeof(priv)},
		};

		Zero(label, sizeof(label));

		if (sec->Api->C_GetAttributeValue(sec->SessionId, objects[i],
			get, sizeof(get) / sizeof(get[0])) == CKR_OK)
		{
			UINT type = INFINITE;

			switch (obj_class)
			{
			case CKO_DATA:
				// Data
				type = SEC_DATA;
				break;

			case CKO_CERTIFICATE:
				// Certificate
				type = SEC_X;
				break;

			case CKO_PUBLIC_KEY:
				// Public key
				type = SEC_P;
				break;

			case CKO_PRIVATE_KEY:
				// Secret key
				type = SEC_K;
				break;
			}

			if (type != INFINITE)
			{
				SEC_OBJ *obj = ZeroMalloc(sizeof(SEC_OBJ));

				obj->Type = type;
				obj->Object = objects[i];
				obj->Private = (priv == false) ? false : true;
				EnSafeStr(label, '?');
				TruncateCharFromStr(label, '?');
				obj->Name = CopyStr(label);

				Add(o, obj);
			}
		}
	}

	// Creating a cache
	sec->EnumCache = CloneEnumSecObject(o);

	return o;
}

// Write the data
bool WriteSecData(SECURE *sec, bool private_obj, char *name, void *data, UINT size)
{
	UINT object_class = CKO_DATA;
	CK_BBOOL b_true = true, b_false = false, b_private_obj = private_obj;
	UINT object;
	CK_ATTRIBUTE a[] =
	{
		{CKA_TOKEN,		&b_true,		sizeof(b_true)},
		{CKA_CLASS,		&object_class,	sizeof(object_class)},
		{CKA_PRIVATE,	&b_private_obj,	sizeof(b_private_obj)},
		{CKA_LABEL,		name,			StrLen(name)},
		{CKA_VALUE,		data,			size},
	};
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;
	}
	if (private_obj && sec->LoginFlag == false)
	{
		sec->Error = SEC_ERROR_NOT_LOGIN;
		return false;
	}
	if (name == NULL || data == NULL || size == 0)
	{
		sec->Error = SEC_ERROR_BAD_PARAMETER;
		return false;
	}
	if (size > MAX_SEC_DATA_SIZE)
	{
		sec->Error = SEC_ERROR_DATA_TOO_BIG;
		return false;
	}

	// Delete any objects with the same name
	if (CheckSecObject(sec, name, SEC_DATA))
	{
		DeleteSecData(sec, name);
	}

	// Object creation
	if (sec->Api->C_CreateObject(sec->SessionId, a, sizeof(a) / sizeof(a[0]), &object) != CKR_OK)
	{
		sec->Error = SEC_ERROR_HARDWARE_ERROR;
		return false;
	}

	// Clear the cache
	EraseEnumSecObjectCache(sec);

	return true;
}

// Display the token information
void PrintSecInfo(SECURE *sec)
{
	SEC_INFO *s;
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}

	s = sec->Info;
	if (s == NULL)
	{
		Print("No Token Info.\n");
		return;
	}

	Print(
		"               Label: %S\n"
		"      ManufacturerId: %S\n"
		"               Model: %S\n"
		"        SerialNumber: %S\n"
		"          MaxSession: %u\n"
		"        MaxRWSession: %u\n"
		"           MinPinLen: %u\n"
		"           MaxPinLen: %u\n"
		"   TotalPublicMemory: %u\n"
		"    FreePublicMemory: %u\n"
		"  TotalPrivateMemory: %u\n"
		"   FreePrivateMemory: %u\n"
		"     HardwareVersion: %s\n"
		"     FirmwareVersion: %s\n",
		s->Label, s->ManufacturerId, s->Model, s->SerialNumber,
		s->MaxSession, s->MaxRWSession, s->MinPinLen, s->MaxPinLen,
		s->TotalPublicMemory, s->FreePublicMemory, s->TotalPrivateMemory,
		s->FreePrivateMemory, s->HardwareVersion, s->FirmwareVersion
		);
}

// Get the token information
void GetSecInfo(SECURE *sec)
{
	CK_TOKEN_INFO token_info;
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}
	if (sec->Info != NULL)
	{
		return;
	}

	// Acquisition
	Zero(&token_info, sizeof(token_info));
	if (sec->Api->C_GetTokenInfo(sec->SlotIdList[sec->SessionSlotNumber], &token_info) != CKR_OK)
	{
		// Failure
		return;
	}

	sec->Info = TokenInfoToSecInfo(&token_info);
}

// Release the token information
void FreeSecInfo(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}
	if (sec->Info == NULL)
	{
		return;
	}

	FreeSecInfoMemory(sec->Info);
	sec->Info = NULL;
}

// Convert the token information to the SEC_INFO
SEC_INFO *TokenInfoToSecInfo(void *p_t)
{
	SEC_INFO *s;
	char buf[MAX_SIZE];
	CK_TOKEN_INFO *t = (CK_TOKEN_INFO *)p_t;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SEC_INFO));

	// Label
	Zero(buf, sizeof(buf));
	Copy(buf, t->label, sizeof(t->label));
	s->Label = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->Label, 0, buf, 0);

	// ManufacturerId
	Zero(buf, sizeof(buf));
	Copy(buf, t->manufacturerID, sizeof(t->manufacturerID));
	s->ManufacturerId = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->ManufacturerId, 0, buf, 0);

	// Model
	Zero(buf, sizeof(buf));
	Copy(buf, t->model, sizeof(t->model));
	s->Model = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->Model, 0, buf, 0);

	// SerialNumber
	Zero(buf, sizeof(buf));
	Copy(buf, t->serialNumber, sizeof(t->serialNumber));
	s->SerialNumber = ZeroMalloc(CalcUtf8ToUni(buf, 0));
	Utf8ToUni(s->SerialNumber, 0, buf, 0);

	// Numeric value
	s->MaxSession = t->ulMaxSessionCount;
	s->MaxRWSession = t->ulMaxRwSessionCount;
	s->MinPinLen = t->ulMinPinLen;
	s->MaxPinLen = t->ulMaxPinLen;
	s->TotalPublicMemory = t->ulTotalPublicMemory;
	s->FreePublicMemory = t->ulFreePublicMemory;
	s->TotalPrivateMemory = t->ulTotalPrivateMemory;
	s->FreePrivateMemory = t->ulFreePrivateMemory;

	// Hardware version
	Format(buf, sizeof(buf), "%u.%02u", t->hardwareVersion.major, t->hardwareVersion.minor);
	s->HardwareVersion = CopyStr(buf);

	// Firmware version
	Format(buf, sizeof(buf), "%u.%02u", t->firmwareVersion.major, t->firmwareVersion.minor);
	s->FirmwareVersion = CopyStr(buf);

	return s;
}

// Release the memory of the SEC_INFO
void FreeSecInfoMemory(SEC_INFO *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Free(s->Label);
	Free(s->ManufacturerId);
	Free(s->Model);
	Free(s->SerialNumber);
	Free(s->HardwareVersion);
	Free(s->FirmwareVersion);
	Free(s);
}

// Log-out
void LogoutSec(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}
	if (sec->LoginFlag == false)
	{
		return;
	}

	// Log-out
	sec->Api->C_Logout(sec->SessionId);

	// Clear Cache
	EraseEnumSecObjectCache(sec);

	sec->LoginFlag = false;
}

// Log-in
bool LoginSec(SECURE *sec, char *pin)
{
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated == false)
	{
		sec->Error = SEC_ERROR_NO_SESSION;
		return false;

	}
	if (sec->LoginFlag)
	{
		sec->Error = SEC_ERROR_ALREADY_LOGIN;
		return false;
	}
	if (pin == NULL)
	{
		sec->Error = SEC_ERROR_NO_PIN_STR;
		return false;
	}

	// Log-in
	if (sec->Api->C_Login(sec->SessionId, CKU_USER, pin, StrLen(pin)) != CKR_OK)
	{
		// Login failure
		sec->Error = SEC_ERROR_BAD_PIN_CODE;
		return false;
	}

	// Clear the cache
	EraseEnumSecObjectCache(sec);

	sec->LoginFlag = true;

	return true;
}

// Close the session
void CloseSecSession(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}
	if (sec->SessionCreated == false)
	{
		return;
	}

	// Close the session
	sec->Api->C_CloseSession(sec->SessionId);

	sec->SessionCreated = false;
	sec->SessionId = 0;
	sec->SessionSlotNumber = 0;

	FreeSecInfo(sec);

	// Clear the cache
	EraseEnumSecObjectCache(sec);
}

// Open the session
bool OpenSecSession(SECURE *sec, UINT slot_number)
{
	UINT err = 0;
	UINT session;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}
	if (sec->SessionCreated)
	{
		// Already been created
		sec->Error = SEC_ERROR_SESSION_EXISTS;
		return false;
	}
	if (slot_number >= sec->NumSlot)
	{
		// Slot number is invalid
		sec->Error = SEC_ERROR_INVALID_SLOT_NUMBER;
		return false;
	}

	// Create a session
	if ((err = sec->Api->C_OpenSession(sec->SlotIdList[slot_number],
		CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session)) != CKR_OK)
	{
		// Failed to initialize session in read / write mode
		// Read-only mode?
		if ((err = sec->Api->C_OpenSession(sec->SlotIdList[slot_number],
			CKF_SERIAL_SESSION, NULL, NULL, &session)) != CKR_OK)
		{
			// Failure to create
			sec->Error = SEC_ERROR_OPEN_SESSION;
			return false;
		}
		else
		{
			sec->IsReadOnly = true;
		}
	}

	sec->SessionCreated = true;
	sec->SessionId = session;
	sec->SessionSlotNumber = slot_number;

	// Get the token information
	GetSecInfo(sec);

	return true;
}

// Close the secure device
void CloseSec(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}

	// Log out
	LogoutSec(sec);

	// Close the session
	CloseSecSession(sec);

	// Release the token information
	FreeSecInfo(sec);

	// Release of the slot list memory
	if (sec->SlotIdList != NULL)
	{
		Free(sec->SlotIdList);
		sec->SlotIdList = NULL;
	}

	// Unload the module
	FreeSecModule(sec);

	// Memory release
	DeleteLock(sec->lock);
	Free(sec);
}

// Open a secure device
SECURE *OpenSec(UINT id)
{
	SECURE_DEVICE *dev = GetSecureDevice(id);
	SECURE *sec;
	UINT err;

	if (dev == NULL)
	{
		return NULL;
	}

	sec = ZeroMalloc(sizeof(SECURE));

	sec->lock = NewLock();
	sec->Error = SEC_ERROR_NOERROR;
	sec->Dev = dev;

	// Get whether it's a ePass or not
	if (SearchStrEx(dev->DeviceName, "epass", 0, false) != INFINITE)
	{
		sec->IsEPass1000 = true;
	}

	// Load the module
	if (LoadSecModule(sec) == false)
	{
		CloseSec(sec);
		return NULL;
	}

	// Get the slot list
	sec->NumSlot = 0;
	if ((err = sec->Api->C_GetSlotList(true, NULL, &sec->NumSlot)) != CKR_OK || sec->NumSlot == 0)
	{
		// Failure
		FreeSecModule(sec);
		CloseSec(sec);
		return NULL;
	}

	sec->SlotIdList = (UINT *)ZeroMalloc(sizeof(UINT) * sec->NumSlot);

	if (sec->Api->C_GetSlotList(TRUE, sec->SlotIdList, &sec->NumSlot) != CKR_OK)
	{
		// Failure
		Free(sec->SlotIdList);
		sec->SlotIdList = NULL;
		FreeSecModule(sec);
		CloseSec(sec);
		return NULL;
	}

	return sec;
}

// Load the module of the secure device
bool LoadSecModule(SECURE *sec)
{
	bool ret = false;
	// Validate arguments
	if (sec == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	ret = Win32LoadSecModule(sec);
#endif	// OS_WIN32

	// Initialization
	if (sec->Api->C_Initialize(NULL) != CKR_OK)
	{
		// Initialization Failed
		FreeSecModule(sec);
		return false;
	}

	sec->Initialized = true;

	return ret;
}

// Unload the module of the secure device
void FreeSecModule(SECURE *sec)
{
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}

	if (sec->Initialized)
	{
		// Release because it is initialized
		sec->Api->C_Finalize(NULL);
		sec->Initialized = false;
	}

#ifdef	OS_WIN32
	Win32FreeSecModule(sec);
#endif	// OS_WIN32

}


// Get a secure device
SECURE_DEVICE *GetSecureDevice(UINT id)
{
	UINT i;

	if (id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(SecureDeviceList);i++)
	{
		SECURE_DEVICE *dev = LIST_DATA(SecureDeviceList, i);

		if (dev->Id == id)
		{
			return dev;
		}
	}

	return NULL;
}

// Confirm the ID of the secure device
bool CheckSecureDeviceId(UINT id)
{
	UINT i;

	for (i = 0;i < LIST_NUM(SecureDeviceList);i++)
	{
		SECURE_DEVICE *dev = LIST_DATA(SecureDeviceList, i);

		if (dev->Id == id)
		{
			return true;
		}
	}

	return false;
}

// Get a list of supported devices
LIST *GetSecureDeviceList()
{
	return GetSupportedDeviceList();
}

// Get a list of supported devices
LIST *GetSupportedDeviceList()
{
	// Increase the reference count
	AddRef(SecureDeviceList->ref);

	return SecureDeviceList;
}

// Examine whether the specified device is installed and available
bool IsDeviceSupported(SECURE_DEVICE *dev)
{
	bool b = false;
#ifdef	OS_WIN32
	b = Win32IsDeviceSupported(dev);
#endif	// OS_WIN32
	return b;
}

// Initialization of the secure device list
void InitSecureDeviceList()
{
	UINT i, num_supported_list;
	SecureDeviceList = NewList(NULL);

	num_supported_list = sizeof(SupportedList) / sizeof(SECURE_DEVICE);
	for (i = 0; i < num_supported_list;i++)
	{
		SECURE_DEVICE *dev = &SupportedList[i];

		// Support Checking
		if (IsDeviceSupported(dev))
		{
			// Add the device to the list because it is supported
			Add(SecureDeviceList, dev);
		}
	}
}

// Test main procedure
void TestSecMain(SECURE *sec)
{
	char *test_str = CEDAR_PRODUCT_STR " VPN";
	K *public_key, *private_key;
	// Validate arguments
	if (sec == NULL)
	{
		return;
	}

	Print("test_str: \"%s\"\n", test_str);

	Print("Writing Data...\n");
	if (WriteSecData(sec, true, "test_str", test_str, StrLen(test_str)) == false)
	{
		Print("WriteSecData() Failed.\n");
	}
	else
	{
		char data[MAX_SIZE];
		Zero(data, sizeof(data));
		Print("Reading Data...\n");
		if (ReadSecData(sec, "test_str", data, sizeof(data)) == false)
		{
			Print("ReadSecData() Failed.\n");
		}
		else
		{
			Print("test_str: \"%s\"\n", data);
		}
		Print("Deleting Data...\n");
		DeleteSecData(sec, "test_str");
	}

	Print("Generating Key...\n");
	if (RsaGen(&private_key, &public_key, 2048) == false)
	{
		Print("RsaGen() Failed.\n");
	}
	else
	{
		X *cert;
		NAME *name;
		X_SERIAL *serial;
		UINT num = 0x11220000;

		Print("Creating Cert...\n");
		serial = NewXSerial(&num, sizeof(UINT));
		name = NewName(L"Test", L"Test", L"Test", L"JP", L"Test", L"Test");
		cert = NewRootX(public_key, private_key, name, 365, NULL);
		FreeXSerial(serial);
		if (cert == NULL)
		{
			Print("NewRootX() Failed.\n");
		}
		else
		{
			Print("Writing Cert...\n");
			DeleteSecData(sec, "test_cer");
			if (WriteSecCert(sec, true, "test_cer", cert) == false)
			{
				Print("WriteSecCert() Failed.\n");
			}
			else
			{
				X *x;
				Print("Reading Cert...\n");
				x = ReadSecCert(sec, "test_cer");
				if (x == NULL)
				{
					Print("ReadSecCert() Failed.\n");
				}
				else
				{
					Print("Checking two Certs... ");
					if (CompareX(x, cert) == false)
					{
						Print("[FAILED]\n");
					}
					else
					{
						Print("Ok.\n");
					}
					FreeX(x);
				}
				if (cert != NULL)
				{
					X *x;
					XToFile(cert, "cert_tmp.cer", true);
					x = FileToX("cert_tmp.cer");
					if (CompareX(x, cert) == false)
					{
						Print("[FAILED]\n");
					}
					else
					{
						Print("Ok.\n");
						Print("Writing Private Key...\n");
						DeleteSecKey(sec, "test_key");
						if (WriteSecKey(sec, false, "test_key", private_key) == false)
						{
							Print("WriteSecKey() Failed.\n");
						}
						else
						{
							UCHAR sign_cpu[512];
							UCHAR sign_sec[512];
							K *pub = GetKFromX(cert);
							UINT keybytes = (cert->bits)/8;
							Print("Ok.\n");
							Print("Signing Data by CPU...\n");
							if (RsaSign(sign_cpu, test_str, StrLen(test_str), private_key) == false)
							{
								Print("RsaSign() Failed.\n");
							}
							else
							{
								Print("Ok.\n");
								Print("sign_cpu: ");
								PrintBin(sign_cpu, keybytes);
								Print("Signing Data by %s..\n", sec->Dev->DeviceName);
								if (SignSec(sec, "test_key", sign_sec, test_str, StrLen(test_str)) == false)
								{
									Print("SignSec() Failed.\n");
								}
								else
								{
									Print("Ok.\n");
									Print("sign_sec: ");
									PrintBin(sign_sec, keybytes);
									Print("Compare...");
									if (Cmp(sign_sec, sign_cpu, keybytes) == 0)
									{
										Print("Ok.\n");
										Print("Verify...");
										if (RsaVerifyEx(test_str, StrLen(test_str),
											sign_sec, pub, cert->bits) == false)
										{
											Print("[FAILED]\n");
										}
										else
										{
											Print("Ok.\n");
										}
									}
									else
									{
										Print("[DIFFERENT]\n");
									}
								}
							}
							Print("Deleting test_key...\n");
//							DeleteSecKey(sec, "test_key");
							FreeK(pub);
						}
					}
					FreeX(x);
				}
			}
			Print("Deleting Cert..\n");
//			DeleteSecCert(sec, "test_cer");
			FreeX(cert);
		}
		FreeName(name);
		FreeK(private_key);
		FreeK(public_key);
	}
}

// Test the security device
void TestSec()
{
	UINT i;
	LIST *secure_device_list;
	Print("Secure Device Test Program\n"
		"Copyright (c) SoftEther Corporation. All Rights Reserved.\n\n");

	// Get the secure device list
	secure_device_list = GetSecureDeviceList();
	if (secure_device_list != NULL)
	{
		UINT use_device_id;
		char tmp[MAX_SIZE];
		Print("--- Secure Device List ---\n");
		for (i = 0;i < LIST_NUM(secure_device_list);i++)
		{
			SECURE_DEVICE *dev = LIST_DATA(secure_device_list, i);
			Print("%2u - %s\n", dev->Id, dev->DeviceName);
		}
		Print("\n");
		Print("Device ID >");
		GetLine(tmp, sizeof(tmp));
		use_device_id = ToInt(tmp);
		if (use_device_id == 0)
		{
			Print("Canceled.\n");
		}
		else
		{
			SECURE *sec = OpenSec(use_device_id);
			Print("Opening Device...\n");
			if (sec == NULL)
			{
				Print("OpenSec() Failed.\n");
			}
			else
			{
				Print("Opening Session...\n");
				if (OpenSecSession(sec, 0) == false)
				{
					Print("OpenSecSession() Failed.\n");
				}
				else
				{
					while (true)
					{
						char pin[MAX_SIZE];
						Print("PIN Code >");
						GetLine(pin, sizeof(pin));
						Trim(pin);
						if (StrLen(pin) == 0)
						{
							Print("Canceled.\n");
							break;
						}
						else
						{
							Print("Login...\n");
							if (LoginSec(sec, pin))
							{
								TestSecMain(sec);
								Print("Logout...\n");
								LogoutSec(sec);
								break;
							}
							else
							{
								Print("Login Failed. Please Try Again.\n");
							}
						}
					}
					Print("Closing Session...\n");
					CloseSecSession(sec);
				}
				Print("Closing Device...\n");
				CloseSec(sec);
			}
		}
		ReleaseList(secure_device_list);
	}
	else
	{
		Print("GetSecureDeviceList() Error.\n");
	}
}

// Release of the secure device list
void FreeSecureDeviceList()
{
	ReleaseList(SecureDeviceList);
}

// Initialization of the security token module
void InitSecure()
{
	// Initialization of the secure device list
	InitSecureDeviceList();
}

// Release of the security token module
void FreeSecure()
{
	// Release of the secure device list
	FreeSecureDeviceList();
}


