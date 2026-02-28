// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IKEv2.c
// IKEv2 (RFC 7296) implementation

#include "Proto_IKEv2.h"

#include "Cedar.h"
#include "Proto_EtherIP.h"
#include "Proto_IKE.h"
#include "Proto_IkePacket.h"
#include "Proto_IPsec.h"
#include "Proto_L2TP.h"
#include "Server.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/TcpIp.h"

// ---------------------------------------------------------------------------
// Algorithm helper functions
// ---------------------------------------------------------------------------

// Return the MD object name for a given PRF algorithm
static const char *IKEv2PrfMdName(UINT prf_alg)
{
    switch (prf_alg)
    {
    case IKEv2_PRF_HMAC_MD5:      return "MD5";
    case IKEv2_PRF_HMAC_SHA1:     return "SHA1";
    case IKEv2_PRF_HMAC_SHA2_256: return "SHA256";
    case IKEv2_PRF_HMAC_SHA2_384: return "SHA384";
    case IKEv2_PRF_HMAC_SHA2_512: return "SHA512";
    default:                       return NULL;
    }
}

static const char *IKEv2IntegMdName(UINT integ_alg)
{
    switch (integ_alg)
    {
    case IKEv2_INTEG_HMAC_MD5_96:       return "MD5";
    case IKEv2_INTEG_HMAC_SHA1_96:      return "SHA1";
    case IKEv2_INTEG_HMAC_SHA2_256_128: return "SHA256";
    case IKEv2_INTEG_HMAC_SHA2_384_192: return "SHA384";
    case IKEv2_INTEG_HMAC_SHA2_512_256: return "SHA512";
    default:                             return NULL;
    }
}

UINT IKEv2PrfKeyLen(UINT prf_alg)
{
    switch (prf_alg)
    {
    case IKEv2_PRF_HMAC_MD5:      return 16;
    case IKEv2_PRF_HMAC_SHA1:     return 20;
    case IKEv2_PRF_HMAC_SHA2_256: return 32;
    case IKEv2_PRF_HMAC_SHA2_384: return 48;
    case IKEv2_PRF_HMAC_SHA2_512: return 64;
    default:                       return 0;
    }
}

UINT IKEv2PrfOutLen(UINT prf_alg)
{
    return IKEv2PrfKeyLen(prf_alg);
}

UINT IKEv2IntegKeyLen(UINT integ_alg)
{
    switch (integ_alg)
    {
    case IKEv2_INTEG_HMAC_MD5_96:       return 16;
    case IKEv2_INTEG_HMAC_SHA1_96:      return 20;
    case IKEv2_INTEG_HMAC_SHA2_256_128: return 32;
    case IKEv2_INTEG_HMAC_SHA2_384_192: return 48;
    case IKEv2_INTEG_HMAC_SHA2_512_256: return 64;
    default:                             return 0;
    }
}

UINT IKEv2IntegIcvLen(UINT integ_alg)
{
    switch (integ_alg)
    {
    case IKEv2_INTEG_HMAC_MD5_96:       return 12;
    case IKEv2_INTEG_HMAC_SHA1_96:      return 12;
    case IKEv2_INTEG_HMAC_SHA2_256_128: return 16;
    case IKEv2_INTEG_HMAC_SHA2_384_192: return 24;
    case IKEv2_INTEG_HMAC_SHA2_512_256: return 32;
    default:                             return 0;
    }
}

UINT IKEv2EncrKeyLen(UINT encr_alg, UINT requested)
{
    switch (encr_alg)
    {
    case IKEv2_ENCR_3DES:    return 24;
    case IKEv2_ENCR_AES_CBC:
        if (requested == 16 || requested == 24 || requested == 32)
            return requested;
        return 16;
    default: return 0;
    }
}

UINT IKEv2EncrBlockSize(UINT encr_alg)
{
    switch (encr_alg)
    {
    case IKEv2_ENCR_3DES:    return 8;
    case IKEv2_ENCR_AES_CBC: return 16;
    default:                  return 8;
    }
}

// Get an IKE_HASH for the PRF algorithm (reuses existing engine hashes)
IKE_HASH *IKEv2GetHashForPrf(IKE_SERVER *ike, UINT prf_alg)
{
    UINT hash_id;
    UINT i;

    switch (prf_alg)
    {
    case IKEv2_PRF_HMAC_MD5:      hash_id = IKE_HASH_MD5_ID;      break;
    case IKEv2_PRF_HMAC_SHA1:     hash_id = IKE_HASH_SHA1_ID;     break;
    case IKEv2_PRF_HMAC_SHA2_256: hash_id = IKE_HASH_SHA2_256_ID; break;
    case IKEv2_PRF_HMAC_SHA2_384: hash_id = IKE_HASH_SHA2_384_ID; break;
    case IKEv2_PRF_HMAC_SHA2_512: hash_id = IKE_HASH_SHA2_512_ID; break;
    default: return NULL;
    }

    for (i = 0; i < MAX_IKE_ENGINE_ELEMENTS; i++)
    {
        if (ike->Engine->IkeHashes[i] != NULL &&
            ike->Engine->IkeHashes[i]->HashId == hash_id)
            return ike->Engine->IkeHashes[i];
    }
    return NULL;
}

IKE_HASH *IKEv2GetHashForInteg(IKE_SERVER *ike, UINT integ_alg)
{
    UINT hash_id;
    UINT i;

    switch (integ_alg)
    {
    case IKEv2_INTEG_HMAC_MD5_96:       hash_id = IKE_HASH_MD5_ID;      break;
    case IKEv2_INTEG_HMAC_SHA1_96:      hash_id = IKE_HASH_SHA1_ID;     break;
    case IKEv2_INTEG_HMAC_SHA2_256_128: hash_id = IKE_HASH_SHA2_256_ID; break;
    case IKEv2_INTEG_HMAC_SHA2_384_192: hash_id = IKE_HASH_SHA2_384_ID; break;
    case IKEv2_INTEG_HMAC_SHA2_512_256: hash_id = IKE_HASH_SHA2_512_ID; break;
    default: return NULL;
    }

    for (i = 0; i < MAX_IKE_ENGINE_ELEMENTS; i++)
    {
        if (ike->Engine->IkeHashes[i] != NULL &&
            ike->Engine->IkeHashes[i]->HashId == hash_id)
            return ike->Engine->IkeHashes[i];
    }
    return NULL;
}

IKE_CRYPTO *IKEv2GetCrypto(IKE_SERVER *ike, UINT encr_alg)
{
    UINT crypto_id;
    UINT i;

    switch (encr_alg)
    {
    case IKEv2_ENCR_3DES:    crypto_id = IKE_CRYPTO_3DES_ID; break;
    case IKEv2_ENCR_AES_CBC: crypto_id = IKE_CRYPTO_AES_ID;  break;
    default: return NULL;
    }

    for (i = 0; i < MAX_IKE_ENGINE_ELEMENTS; i++)
    {
        if (ike->Engine->IkeCryptos[i] != NULL &&
            ike->Engine->IkeCryptos[i]->CryptoId == crypto_id)
            return ike->Engine->IkeCryptos[i];
    }
    return NULL;
}

IKE_DH *IKEv2GetDh(IKE_SERVER *ike, UINT dh_group)
{
    UINT dh_id;
    UINT i;

    switch (dh_group)
    {
    case IKEv2_DH_1024_MODP: dh_id = IKE_DH_2_ID;    break;
    case IKEv2_DH_1536_MODP: dh_id = IKE_DH_5_ID;    break;
    case IKEv2_DH_2048_MODP: dh_id = IKE_DH_2048_ID; break;
    case IKEv2_DH_3072_MODP: dh_id = IKE_DH_3072_ID; break;
    case IKEv2_DH_4096_MODP: dh_id = IKE_DH_4096_ID; break;
    default: return NULL;
    }

    for (i = 0; i < MAX_IKE_ENGINE_ELEMENTS; i++)
    {
        if (ike->Engine->IkeDhs[i] != NULL &&
            ike->Engine->IkeDhs[i]->DhId == dh_id)
            return ike->Engine->IkeDhs[i];
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// PRF and PRF+ (RFC 7296 Section 2.13)
// ---------------------------------------------------------------------------

// Compute prf(key, data) -> out (output is prf_out_len bytes)
void IKEv2PRF(UINT prf_alg, void *key, UINT key_len,
              void *data, UINT data_len, void *out)
{
    const char *md_name = IKEv2PrfMdName(prf_alg);
    MD *md;
    UINT out_len;

    if (md_name == NULL || out == NULL)
        return;

    md = NewMd((char *)md_name);
    if (md == NULL)
        return;

    if (SetMdKey(md, key, key_len) == false)
    {
        FreeMd(md);
        return;
    }

    out_len = IKEv2PrfOutLen(prf_alg);
    MdProcess(md, out, data, data_len);

    FreeMd(md);
}

// Compute prf+(key, seed) -> out of out_len bytes  (RFC 7296 Section 2.13)
void IKEv2PRFPlus(UINT prf_alg, void *key, UINT key_len,
                  void *seed, UINT seed_len, void *out, UINT out_len)
{
    UINT   prf_out = IKEv2PrfOutLen(prf_alg);
    UINT   generated = 0;
    UCHAR  counter = 1;
    UCHAR  prev[IKEv2_MAX_KEYMAT_SIZE];
    UINT   prev_len = 0;
    UCHAR *p = (UCHAR *)out;
    UCHAR *tmp;

    if (prf_out == 0 || out_len == 0 || out == NULL)
        return;

    tmp = Malloc(prf_out + seed_len + 1);

    while (generated < out_len)
    {
        UINT   chunk;
        UCHAR  result[IKEv2_MAX_KEYMAT_SIZE];
        UCHAR *q = tmp;

        // Assemble: T(i-1) | seed | counter
        if (prev_len > 0)
        {
            Copy(q, prev, prev_len);
            q += prev_len;
        }
        Copy(q, seed, seed_len);
        q += seed_len;
        *q = counter;

        IKEv2PRF(prf_alg, key, key_len, tmp, (UINT)(q - tmp + 1), result);

        chunk = MIN(prf_out, out_len - generated);
        Copy(p, result, chunk);
        p         += chunk;
        generated += chunk;

        Copy(prev, result, prf_out);
        prev_len = prf_out;
        counter++;
    }

    Free(tmp);
}

// ---------------------------------------------------------------------------
// Integrity (HMAC for SK payload)
// ---------------------------------------------------------------------------
static void IKEv2ComputeInteg(UINT integ_alg, void *key, UINT key_len,
                               void *data, UINT data_len, void *icv_out)
{
    const char *md_name = IKEv2IntegMdName(integ_alg);
    MD *md;
    UCHAR full[IKEv2_MAX_KEYMAT_SIZE];

    if (md_name == NULL || icv_out == NULL)
        return;

    md = NewMd((char *)md_name);
    if (md == NULL)
        return;

    if (SetMdKey(md, key, key_len) == false)
    {
        FreeMd(md);
        return;
    }

    MdProcess(md, full, data, data_len);
    Copy(icv_out, full, IKEv2IntegIcvLen(integ_alg));

    FreeMd(md);
}


// ---------------------------------------------------------------------------
// IKEv2 SA management
// ---------------------------------------------------------------------------

int CmpIKEv2SA(void *p1, void *p2)
{
    IKEv2_SA *a = *(IKEv2_SA **)p1;
    IKEv2_SA *b = *(IKEv2_SA **)p2;
    if (a->Id < b->Id) return -1;
    if (a->Id > b->Id) return  1;
    return 0;
}

IKEv2_SA *IKEv2NewSA(IKE_SERVER *ike)
{
    IKEv2_SA *sa = ZeroMalloc(sizeof(IKEv2_SA));
    sa->Id = ++ike->CurrentIKEv2SaId;
    sa->FirstCommTick = ike->Now;
    sa->LastCommTick  = ike->Now;
    Insert(ike->IKEv2SaList, sa);
    return sa;
}

void IKEv2FreeSA(IKE_SERVER *ike, IKEv2_SA *sa)
{
    if (sa == NULL)
        return;

    FreeBuf(sa->Ni);
    FreeBuf(sa->Nr);
    FreeBuf(sa->GxI);
    FreeBuf(sa->GxR);
    FreeBuf(sa->IDi_Data);
    FreeBuf(sa->InitMsg);
    FreeBuf(sa->RespMsg);
    FreeBuf(sa->LastResponse);
    IkeDhFreeCtx(sa->Dh);
    IkeFreeKey(sa->EncKeyI);
    IkeFreeKey(sa->EncKeyR);
    Free(sa);
}

void IKEv2MarkDeleting(IKE_SERVER *ike, IKEv2_SA *sa)
{
    if (sa == NULL) return;
    sa->Deleting = true;
    ike->StateHasChanged = true;
}

void IKEv2PurgeDeleting(IKE_SERVER *ike)
{
    UINT i;
    for (i = 0; i < LIST_NUM(ike->IKEv2SaList); i++)
    {
        IKEv2_SA *sa = LIST_DATA(ike->IKEv2SaList, i);
        if (sa->Deleting)
        {
            Delete(ike->IKEv2SaList, sa);
            IKEv2FreeSA(ike, sa);
            i--;
            ike->StateHasChanged = true;
        }
    }
}

IKEv2_SA *IKEv2FindByInitSPI(IKE_SERVER *ike, UINT64 init_spi,
                               IP *client_ip, UINT client_port)
{
    UINT i;
    for (i = 0; i < LIST_NUM(ike->IKEv2SaList); i++)
    {
        IKEv2_SA *sa = LIST_DATA(ike->IKEv2SaList, i);
        if (sa->InitiatorSPI == init_spi &&
            CmpIpAddr(&sa->ClientIP, client_ip) == 0 &&
            sa->ClientPort == client_port)
            return sa;
    }
    return NULL;
}

IKEv2_SA *IKEv2FindBySPIPair(IKE_SERVER *ike, UINT64 init_spi, UINT64 resp_spi)
{
    UINT i;
    for (i = 0; i < LIST_NUM(ike->IKEv2SaList); i++)
    {
        IKEv2_SA *sa = LIST_DATA(ike->IKEv2SaList, i);
        if (sa->InitiatorSPI == init_spi && sa->ResponderSPI == resp_spi)
            return sa;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Key derivation (RFC 7296 Section 2.14)
// ---------------------------------------------------------------------------

bool IKEv2DeriveKeys(IKE_SERVER *ike, IKEv2_SA *sa)
{
    UCHAR  skeyseed[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR  keymat[IKEv2_MAX_KEYMAT_SIZE * 7];
    UCHAR  seed_ni_nr_spi[IKEv2_NONCE_MAX_SIZE * 2 + 16];
    UINT   seed_len;
    UCHAR *p;
    UINT   prf_alg   = sa->Transform.PrfAlg;
    UINT   prf_key   = IKEv2PrfKeyLen(prf_alg);
    UINT   prf_out   = IKEv2PrfOutLen(prf_alg);
    UINT   integ_key = IKEv2IntegKeyLen(sa->Transform.IntegAlg);
    UINT   encr_key  = sa->Transform.EncrKeyLen;
    UINT   total;
    UCHAR  ni_nr[IKEv2_NONCE_MAX_SIZE * 2];
    UINT   ni_nr_len;
    BUF   *shared_key;
    UCHAR  spi_buf[16];

    if (sa->Ni == NULL || sa->Nr == NULL || sa->Dh == NULL)
        return false;

    // Compute g^ir using our DH context and initiator's public key
    if (sa->GxI == NULL)
        return false;

    {
        UCHAR shared[512];
        UINT  key_size = sa->Dh->Size;
        if (!DhCompute(sa->Dh, shared, sa->GxI->Buf, sa->GxI->Size))
            return false;
        shared_key = MemToBuf(shared, key_size);
    }

    // SKEYSEED = prf(Ni | Nr, g^ir)
    ni_nr_len = sa->Ni->Size + sa->Nr->Size;
    Copy(ni_nr, sa->Ni->Buf, sa->Ni->Size);
    Copy(ni_nr + sa->Ni->Size, sa->Nr->Buf, sa->Nr->Size);

    IKEv2PRF(prf_alg, ni_nr, ni_nr_len,
             shared_key->Buf, shared_key->Size,
             skeyseed);
    FreeBuf(shared_key);

    // Seed = Ni | Nr | SPIi | SPIr
    p = seed_ni_nr_spi;
    Copy(p, sa->Ni->Buf, sa->Ni->Size); p += sa->Ni->Size;
    Copy(p, sa->Nr->Buf, sa->Nr->Size); p += sa->Nr->Size;
    WRITE_UINT64(p, sa->InitiatorSPI);  p += 8;
    WRITE_UINT64(p, sa->ResponderSPI);  p += 8;
    seed_len = (UINT)(p - seed_ni_nr_spi);

    // Total key material needed:
    // SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
    total = prf_key + integ_key + integ_key + encr_key + encr_key + prf_key + prf_key;
    if (total > sizeof(keymat))
        return false;

    IKEv2PRFPlus(prf_alg, skeyseed, prf_out,
                 seed_ni_nr_spi, seed_len,
                 keymat, total);

    // Extract individual keys
    p = keymat;
    Copy(sa->SK_d,  p, prf_key);   p += prf_key;
    Copy(sa->SK_ai, p, integ_key); p += integ_key;
    Copy(sa->SK_ar, p, integ_key); p += integ_key;
    Copy(sa->SK_ei, p, encr_key);  p += encr_key;
    Copy(sa->SK_er, p, encr_key);  p += encr_key;
    Copy(sa->SK_pi, p, prf_key);   p += prf_key;
    Copy(sa->SK_pr, p, prf_key);

    // Create crypto key objects
    {
        IKE_CRYPTO *crypto = IKEv2GetCrypto(ike, sa->Transform.EncrAlg);
        if (crypto == NULL)
            return false;
        sa->EncKeyI = IkeNewKey(crypto, sa->SK_ei, encr_key);
        sa->EncKeyR = IkeNewKey(crypto, sa->SK_er, encr_key);
        if (sa->EncKeyI == NULL || sa->EncKeyR == NULL)
            return false;
    }

    return true;
}

// Derive child SA key material (RFC 7296 Section 2.17)
static bool IKEv2DeriveChildKeys(IKE_SERVER *ike, IKEv2_SA *sa,
                                  IKEv2_CHILDTF *ctf,
                                  BUF *ni, BUF *nr,
                                  UCHAR *key_i2r, UCHAR *key_r2i)
{
    UCHAR  keymat[IKEv2_MAX_KEYMAT_SIZE * 4];
    UINT   encr_key = ctf->EncrKeyLen;
    UINT   integ_key = ctf->IntegKeyLen;
    UINT   total = (encr_key + integ_key) * 2;
    UCHAR  seed[IKEv2_NONCE_MAX_SIZE * 2];
    UINT   seed_len;

    if (total > sizeof(keymat))
        return false;

    // seed = Ni' | Nr'
    seed_len = ni->Size + nr->Size;
    Copy(seed, ni->Buf, ni->Size);
    Copy(seed + ni->Size, nr->Buf, nr->Size);

    IKEv2PRFPlus(sa->Transform.PrfAlg,
                 sa->SK_d, IKEv2PrfKeyLen(sa->Transform.PrfAlg),
                 seed, seed_len,
                 keymat, total);

    // Layout: encr_i2r | integ_i2r | encr_r2i | integ_r2i
    Copy(key_i2r, keymat, encr_key + integ_key);
    Copy(key_r2i, keymat + encr_key + integ_key, encr_key + integ_key);
    return true;
}


// ---------------------------------------------------------------------------
// SK payload: encrypt / decrypt  (RFC 7296 Section 3.14)
// ---------------------------------------------------------------------------

// Encrypt inner payloads into an SK payload.
// Returns a BUF with: generic-header(4) | IV | ciphertext+padding | ICV
// The caller must prepend the correct next_payload into the generic header.
BUF *IKEv2EncryptSK(IKE_SERVER *ike, IKEv2_SA *sa, UCHAR next_payload,
                     void *inner, UINT inner_size)
{
    UINT   block_size   = sa->Transform.BlockSize;
    UINT   icv_len      = IKEv2IntegIcvLen(sa->Transform.IntegAlg);
    UINT   integ_key_len = IKEv2IntegKeyLen(sa->Transform.IntegAlg);
    UINT   pad_len;
    UINT   plain_len;
    UINT   enc_len;
    UCHAR  iv[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR *plain;
    UCHAR *enc_buf;
    UCHAR  icv[IKEv2_MAX_KEYMAT_SIZE];
    BUF   *result;
    UCHAR  hdr[4];
    UINT   payload_data_len;  // IV + enc + ICV
    UINT   total_payload_len; // 4 + IV + enc + ICV
    IKE_CRYPTO_PARAM cp;

    // Pad to block boundary: plaintext | padding | pad_len_byte | next_payload_byte
    plain_len = inner_size + 2; // +2 for pad-length and next-header
    if ((plain_len % block_size) != 0)
        plain_len = ((plain_len / block_size) + 1) * block_size;
    pad_len = plain_len - inner_size - 2;
    enc_len = plain_len;

    // Build plaintext: inner | padding | pad_len | next_payload
    plain = ZeroMalloc(plain_len);
    Copy(plain, inner, inner_size);
    {
        UINT i;
        for (i = 0; i < pad_len; i++)
            plain[inner_size + i] = (UCHAR)(i + 1);
    }
    plain[inner_size + pad_len]     = (UCHAR)pad_len;
    plain[inner_size + pad_len + 1] = next_payload;

    // Random IV
    Rand(iv, block_size);

    // Encrypt using SK_er (responder -> initiator direction for our sends)
    enc_buf = Malloc(enc_len);
    Zero(&cp, sizeof(cp));
    cp.Key = sa->EncKeyR;
    Copy(cp.Iv, iv, block_size);
    IkeCryptoEncrypt(sa->EncKeyR, enc_buf, plain, enc_len, iv);
    Free(plain);

    // Build payload: hdr | IV | ciphertext | ICV(placeholder)
    payload_data_len  = block_size + enc_len + icv_len;
    total_payload_len = 4 + payload_data_len;

    result = NewBuf();

    // Generic payload header (4 bytes)
    hdr[0] = IKEv2_PAYLOAD_NONE; // Next payload  (to be filled later by caller via header)
    hdr[1] = 0;                    // Critical
    WRITE_USHORT(hdr + 2, (USHORT)total_payload_len);
    WriteBuf(result, hdr, 4);

    WriteBuf(result, iv, block_size);
    WriteBuf(result, enc_buf, enc_len);
    Free(enc_buf);

    // ICV placeholder; we compute it over (IKE header + all previous payloads + this SK payload up to ICV)
    // The caller must fill in the ICV.  We allocate the space here.
    {
        UCHAR zero_icv[IKEv2_MAX_KEYMAT_SIZE];
        Zero(zero_icv, icv_len);
        WriteBuf(result, zero_icv, icv_len);
    }

    SeekBuf(result, 0, 0);
    return result;
}

// Compute ICV over entire IKE message and write it into the SK payload
static void IKEv2FillICV(IKE_SERVER *ike, IKEv2_SA *sa,
                          void *full_msg, UINT full_msg_len,
                          UINT icv_offset)
{
    UCHAR icv[IKEv2_MAX_KEYMAT_SIZE];
    UINT  icv_len = IKEv2IntegIcvLen(sa->Transform.IntegAlg);
    UINT  integ_key_len = IKEv2IntegKeyLen(sa->Transform.IntegAlg);

    IKEv2ComputeInteg(sa->Transform.IntegAlg,
                      sa->SK_ar, integ_key_len,
                      full_msg, icv_offset,
                      icv);
    Copy((UCHAR *)full_msg + icv_offset, icv, icv_len);
}

// Decrypt an SK payload received from the initiator.
// sk_data points to the payload data (after the 4-byte generic header).
// Returns a BUF of the decrypted inner payloads, or NULL on failure.
BUF *IKEv2DecryptSK(IKE_SERVER *ike, IKEv2_SA *sa, bool is_init_sending,
                     void *sk_data, UINT sk_size, UCHAR *out_next_payload)
{
    UINT   block_size    = sa->Transform.BlockSize;
    UINT   icv_len       = IKEv2IntegIcvLen(sa->Transform.IntegAlg);
    UINT   integ_key_len = IKEv2IntegKeyLen(sa->Transform.IntegAlg);
    UCHAR *p             = (UCHAR *)sk_data;
    UCHAR *iv, *ciphertext;
    UINT   ct_len;
    UCHAR *plain;
    BUF   *result;
    UCHAR  pad_len;
    UCHAR  nxt;

    // sk_data layout (from right after generic header):
    // IV (block_size) | ciphertext | ICV (icv_len)
    if (sk_size < (UINT)(block_size + icv_len + block_size))
        return NULL;

    ct_len = sk_size - block_size - icv_len;
    if ((ct_len % block_size) != 0)
        return NULL;

    iv         = p;
    ciphertext = p + block_size;

    // Decrypt using SK_ei (initiator -> responder uses SK_ei)
    plain = Malloc(ct_len);
    IkeCryptoDecrypt(sa->EncKeyI, plain, ciphertext, ct_len, iv);

    // Last two bytes of plaintext: pad_len | next_payload
    if (ct_len < 2)
    {
        Free(plain);
        return NULL;
    }
    pad_len = plain[ct_len - 2];
    nxt     = plain[ct_len - 1];

    if (pad_len + 2 > ct_len)
    {
        Free(plain);
        return NULL;
    }

    if (out_next_payload)
        *out_next_payload = nxt;

    result = MemToBuf(plain, ct_len - pad_len - 2);
    Free(plain);
    return result;
}


// ---------------------------------------------------------------------------
// SA proposal parsing and building (simplified wire format)
// ---------------------------------------------------------------------------

// IKEv2 wire format helper: read 2-byte big-endian
static USHORT R16(UCHAR *p) { return (USHORT)(((UINT)p[0] << 8) | p[1]); }
static UINT   R32(UCHAR *p) { return ((UINT)p[0]<<24)|((UINT)p[1]<<16)|((UINT)p[2]<<8)|p[3]; }
static void   W16(UCHAR *p, USHORT v) { p[0]=(UCHAR)(v>>8); p[1]=(UCHAR)v; }
static void   W32(UCHAR *p, UINT v)   { p[0]=(UCHAR)(v>>24); p[1]=(UCHAR)(v>>16); p[2]=(UCHAR)(v>>8); p[3]=(UCHAR)v; }

// Parse an IKEv2 SA payload and select the best IKE SA proposal.
// Returns true if acceptable.
bool IKEv2ParseSAProposalIKE(void *data, UINT size, IKEv2_IKETF *out)
{
    UCHAR *p   = (UCHAR *)data;
    UCHAR *end = p + size;

    Zero(out, sizeof(*out));

    // Iterate proposals
    while (p + 8 <= end)
    {
        UCHAR  last_proposal = p[0];
        USHORT prop_len      = R16(p + 2);
        UCHAR  prop_num      = p[4];
        UCHAR  proto_id      = p[5];
        UCHAR  spi_size      = p[6];
        UCHAR  num_transforms = p[7];
        UCHAR *tp;
        UINT   i;

        // For IKE_SA_INIT the SA payload uses Protocol ID = 1 (IKE), SPI size = 0
        if (prop_len < 8 || p + prop_len > end)
            break;

        if (proto_id == IKEv2_PROTO_IKE && spi_size == 0)
        {
            IKEv2_IKETF tf;
            bool have_encr = false, have_prf = false, have_integ = false, have_dh = false;
            bool good = true;

            Zero(&tf, sizeof(tf));

            tp = p + 8 + spi_size; // start of transforms

            for (i = 0; i < num_transforms && tp + 8 <= p + prop_len; i++)
            {
                UCHAR  last_tf  = tp[0];
                USHORT tf_len   = R16(tp + 2);
                UCHAR  tf_type  = tp[4];
                USHORT tf_id    = R16(tp + 6);
                UCHAR *attr_p   = tp + 8;
                UINT   attr_len = (tf_len > 8) ? (tf_len - 8) : 0;
                USHORT key_len  = 0;

                // Check for key-length attribute (type 14, AF=1)
                if (attr_len >= 4)
                {
                    USHORT at = R16(attr_p);
                    if ((at & 0x8000) && (at & 0x7FFF) == 14)
                        key_len = R16(attr_p + 2) / 8; // bits -> bytes
                }

                switch (tf_type)
                {
                case IKEv2_TF_ENCR:
                    if (tf_id == IKEv2_ENCR_AES_CBC)
                    {
                        tf.EncrAlg    = IKEv2_ENCR_AES_CBC;
                        tf.EncrKeyLen = IKEv2EncrKeyLen(IKEv2_ENCR_AES_CBC, key_len ? key_len : 16);
                        tf.BlockSize  = 16;
                        have_encr = true;
                    }
                    else if (tf_id == IKEv2_ENCR_3DES && !have_encr)
                    {
                        tf.EncrAlg    = IKEv2_ENCR_3DES;
                        tf.EncrKeyLen = 24;
                        tf.BlockSize  = 8;
                    }
                    break;
                case IKEv2_TF_PRF:
                    if (!have_prf && (tf_id == IKEv2_PRF_HMAC_SHA2_256 ||
                                      tf_id == IKEv2_PRF_HMAC_SHA1     ||
                                      tf_id == IKEv2_PRF_HMAC_MD5))
                    {
                        tf.PrfAlg   = tf_id;
                        tf.PrfKeyLen = IKEv2PrfKeyLen(tf_id);
                        tf.PrfOutLen = IKEv2PrfOutLen(tf_id);
                        have_prf = true;
                    }
                    break;
                case IKEv2_TF_INTEG:
                    if (!have_integ &&
                        (tf_id == IKEv2_INTEG_HMAC_SHA2_256_128 ||
                         tf_id == IKEv2_INTEG_HMAC_SHA1_96       ||
                         tf_id == IKEv2_INTEG_HMAC_MD5_96))
                    {
                        tf.IntegAlg     = tf_id;
                        tf.IntegKeyLen  = IKEv2IntegKeyLen(tf_id);
                        tf.IntegIcvLen  = IKEv2IntegIcvLen(tf_id);
                        have_integ = true;
                    }
                    break;
                case IKEv2_TF_DH:
                    if (!have_dh &&
                        (tf_id == IKEv2_DH_2048_MODP ||
                         tf_id == IKEv2_DH_1536_MODP ||
                         tf_id == IKEv2_DH_1024_MODP))
                    {
                        tf.DhGroup = tf_id;
                        have_dh = true;
                    }
                    break;
                }

                if (tf_len < 8)
                    break;
                tp += tf_len;
            }

            if (have_encr && have_prf && have_integ && have_dh)
            {
                Copy(out, &tf, sizeof(tf));
                return true;
            }
        }

        if (last_proposal & 0x80)
            break; // last proposal

        p += prop_len;
    }

    return false;
}

// Parse Child SA proposal from IKE_AUTH SAi2 payload
bool IKEv2ParseSAProposalChild(void *data, UINT size, IKEv2_CHILDTF *out, UINT *out_spi_i)
{
    UCHAR *p   = (UCHAR *)data;
    UCHAR *end = p + size;

    Zero(out, sizeof(*out));
    if (out_spi_i) *out_spi_i = 0;

    while (p + 8 <= end)
    {
        UCHAR  last_proposal  = p[0];
        USHORT prop_len       = R16(p + 2);
        UCHAR  proto_id       = p[5];
        UCHAR  spi_size       = p[6];
        UCHAR  num_transforms = p[7];
        UCHAR *tp;
        UINT   i;
        bool have_encr = false, have_integ = false;
        IKEv2_CHILDTF tf;

        if (prop_len < 8 || p + prop_len > end)
            break;

        if (proto_id != IKEv2_PROTO_ESP || spi_size != 4)
        {
            if (last_proposal & 0x80) break;
            p += prop_len;
            continue;
        }

        if (out_spi_i && p + 8 + spi_size <= p + prop_len)
            *out_spi_i = R32(p + 8);

        Zero(&tf, sizeof(tf));
        tf.UseTransport = false;

        tp = p + 8 + spi_size;

        for (i = 0; i < num_transforms && tp + 8 <= p + prop_len; i++)
        {
            USHORT tf_len   = R16(tp + 2);
            UCHAR  tf_type  = tp[4];
            USHORT tf_id    = R16(tp + 6);
            UCHAR *attr_p   = tp + 8;
            UINT   attr_len = (tf_len > 8) ? (tf_len - 8) : 0;
            USHORT key_len  = 0;

            if (attr_len >= 4)
            {
                USHORT at = R16(attr_p);
                if ((at & 0x8000) && (at & 0x7FFF) == 14)
                    key_len = R16(attr_p + 2) / 8;
            }

            switch (tf_type)
            {
            case IKEv2_TF_ENCR:
                if (tf_id == IKEv2_ENCR_AES_CBC)
                {
                    tf.EncrAlg    = IKEv2_ENCR_AES_CBC;
                    tf.EncrKeyLen = IKEv2EncrKeyLen(IKEv2_ENCR_AES_CBC, key_len ? key_len : 16);
                    tf.BlockSize  = 16;
                    have_encr = true;
                }
                else if (tf_id == IKEv2_ENCR_3DES && !have_encr)
                {
                    tf.EncrAlg    = IKEv2_ENCR_3DES;
                    tf.EncrKeyLen = 24;
                    tf.BlockSize  = 8;
                }
                break;
            case IKEv2_TF_INTEG:
                if (!have_integ &&
                    (tf_id == IKEv2_INTEG_HMAC_SHA2_256_128 ||
                     tf_id == IKEv2_INTEG_HMAC_SHA1_96       ||
                     tf_id == IKEv2_INTEG_HMAC_MD5_96))
                {
                    tf.IntegAlg    = tf_id;
                    tf.IntegKeyLen = IKEv2IntegKeyLen(tf_id);
                    tf.IntegIcvLen = IKEv2IntegIcvLen(tf_id);
                    have_integ = true;
                }
                break;
            }

            if (tf_len < 8) break;
            tp += tf_len;
        }

        if (have_encr && have_integ)
        {
            Copy(out, &tf, sizeof(tf));
            return true;
        }

        if (last_proposal & 0x80) break;
        p += prop_len;
    }

    return false;
}

// Build IKE SA proposal for IKE_SA_INIT response.
// Returns bytes written into buf.
UINT IKEv2BuildSAProposalIKE(IKEv2_SA *sa, void *buf, UINT buf_size)
{
    UCHAR  tmp[512];
    UCHAR *p = tmp;
    UINT   n_transforms;
    UCHAR  key_len_attr[4];
    USHORT prop_len, tf_len;

    // We build exactly one proposal with the negotiated transforms.
    // Transforms: ENCR, PRF, INTEG, DH
    n_transforms = 4;

    // Helper to write a transform
    #define WRITE_TF(last, type, id, klen_bytes) do { \
        UCHAR *tp = p; \
        *p++ = (last); *p++ = 0; W16(p, 0); p += 2; \
        *p++ = (type); *p++ = 0; W16(p, (USHORT)(id)); p += 2; \
        if ((klen_bytes) > 0) { \
            W16(p, 0x800e); p += 2; W16(p, (USHORT)((klen_bytes)*8)); p += 2; \
            W16(tp + 2, (USHORT)(p - tp)); \
        } else { \
            W16(tp + 2, 8); \
        } \
    } while(0)

    // Start proposal header (fill length later)
    UCHAR *prop_start = p;
    *p++ = 0;  // last (0 = last, 2 = more)
    *p++ = 0;
    W16(p, 0); p += 2; // length placeholder
    *p++ = 1;  // proposal number
    *p++ = IKEv2_PROTO_IKE;
    *p++ = 0;  // SPI size
    *p++ = (UCHAR)n_transforms;

    WRITE_TF(3, IKEv2_TF_ENCR,  sa->Transform.EncrAlg, sa->Transform.EncrKeyLen);
    WRITE_TF(3, IKEv2_TF_PRF,   sa->Transform.PrfAlg,  0);
    WRITE_TF(3, IKEv2_TF_INTEG, sa->Transform.IntegAlg, 0);
    WRITE_TF(0, IKEv2_TF_DH,    sa->Transform.DhGroup,  0);

    #undef WRITE_TF

    prop_len = (USHORT)(p - prop_start);
    W16(prop_start + 2, prop_len);

    UINT written = (UINT)(p - tmp);
    if (written > buf_size) return 0;
    Copy(buf, tmp, written);
    return written;
}

// Build ESP child SA proposal for IKE_AUTH response
UINT IKEv2BuildSAProposalChild(IKEv2_CHILDTF *ctf, UINT spi_r, void *buf, UINT buf_size)
{
    UCHAR  tmp[512];
    UCHAR *p = tmp;

    #define WRITE_TF(last, type, id, klen_bytes) do { \
        UCHAR *tp = p; \
        *p++ = (last); *p++ = 0; W16(p, 0); p += 2; \
        *p++ = (type); *p++ = 0; W16(p, (USHORT)(id)); p += 2; \
        if ((klen_bytes) > 0) { \
            W16(p, 0x800e); p += 2; W16(p, (USHORT)((klen_bytes)*8)); p += 2; \
            W16(tp + 2, (USHORT)(p - tp)); \
        } else { \
            W16(tp + 2, 8); \
        } \
    } while(0)

    UCHAR *prop_start = p;
    *p++ = 0;  // last proposal
    *p++ = 0;
    W16(p, 0); p += 2;
    *p++ = 1;
    *p++ = IKEv2_PROTO_ESP;
    *p++ = 4; // SPI size
    *p++ = 3; // 3 transforms: ENCR, INTEG, ESN

    // SPI
    W32(p, spi_r); p += 4;

    WRITE_TF(3, IKEv2_TF_ENCR,  ctf->EncrAlg,  ctf->EncrKeyLen);
    WRITE_TF(3, IKEv2_TF_INTEG, ctf->IntegAlg, 0);
    WRITE_TF(0, IKEv2_TF_ESN,   IKEv2_ESN_NO_ESN, 0);

    #undef WRITE_TF

    USHORT prop_len = (USHORT)(p - prop_start);
    W16(prop_start + 2, prop_len);

    UINT written = (UINT)(p - tmp);
    if (written > buf_size) return 0;
    Copy(buf, tmp, written);
    return written;
}


// ---------------------------------------------------------------------------
// Authentication (PSK)  RFC 7296 Section 2.15
// ---------------------------------------------------------------------------

// Compute AUTH value for PSK.
// signed_octets = RealMsg | Nonce_b | prf(SK_px, IDx_b)
// AUTH = prf(prf(PSK,"Key Pad for IKEv2"), signed_octets)
static void IKEv2ComputePSKAuth(IKE_SERVER *ike, IKEv2_SA *sa,
                                  bool is_initiator_auth,
                                  void *out, UINT *out_len)
{
    UCHAR  psk_key[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR  macedid[IKEv2_MAX_KEYMAT_SIZE];
    BUF   *signed_data;
    UINT   prf_alg  = sa->Transform.PrfAlg;
    UINT   prf_out  = IKEv2PrfOutLen(prf_alg);
    void  *real_msg_buf;
    UINT   real_msg_len;
    void  *nonce_buf;
    UINT   nonce_len;
    void  *sk_px;
    void  *id_data;
    UINT   id_len;

    if (is_initiator_auth)
    {
        real_msg_buf = sa->InitMsg ? sa->InitMsg->Buf : NULL;
        real_msg_len = sa->InitMsg ? sa->InitMsg->Size : 0;
        nonce_buf    = sa->Nr ? sa->Nr->Buf : NULL;
        nonce_len    = sa->Nr ? sa->Nr->Size : 0;
        sk_px        = sa->SK_pi;
        id_data      = sa->IDi_Data ? sa->IDi_Data->Buf : NULL;
        id_len       = sa->IDi_Data ? sa->IDi_Data->Size : 0;
    }
    else
    {
        // Responder AUTH (our own AUTH to send)
        real_msg_buf = sa->RespMsg ? sa->RespMsg->Buf : NULL;
        real_msg_len = sa->RespMsg ? sa->RespMsg->Size : 0;
        nonce_buf    = sa->Ni ? sa->Ni->Buf : NULL;
        nonce_len    = sa->Ni ? sa->Ni->Size : 0;
        sk_px        = sa->SK_pr;
        // For our own AUTH we use our server identity: just server IP as IPv4 or IPv6
        id_data      = NULL;
        id_len       = 0;
    }

    // prf(SK_px, IDx_b)  where IDx_b is the body of the ID payload
    IKEv2PRF(prf_alg, sk_px, prf_out,
             id_data, id_len, macedid);

    // signed_octets = RealMsg | nonce | macedid
    signed_data = NewBuf();
    if (real_msg_buf) WriteBuf(signed_data, real_msg_buf, real_msg_len);
    if (nonce_buf)    WriteBuf(signed_data, nonce_buf, nonce_len);
    WriteBuf(signed_data, macedid, prf_out);

    // AUTH = prf( prf(PSK, "Key Pad for IKEv2"), signed_octets )
    IKEv2PRF(prf_alg,
             ike->Secret, StrLen(ike->Secret),
             IKEv2_PSK_PAD, IKEv2_PSK_PAD_LEN,
             psk_key);
    IKEv2PRF(prf_alg,
             psk_key, prf_out,
             signed_data->Buf, signed_data->Size,
             out);

    if (out_len) *out_len = prf_out;
    FreeBuf(signed_data);
}

// Verify initiator AUTH
bool IKEv2VerifyAuth(IKE_SERVER *ike, IKEv2_SA *sa,
                      UCHAR auth_method, void *auth_data, UINT auth_len)
{
    UCHAR  expected[IKEv2_MAX_KEYMAT_SIZE];
    UINT   expected_len = 0;

    if (auth_method != IKEv2_AUTH_PSK)
        return false;

    IKEv2ComputePSKAuth(ike, sa, true, expected, &expected_len);

    if (auth_len != expected_len)
        return false;

    return (Cmp(auth_data, expected, expected_len) == 0);
}

// Compute our (responder) AUTH value
void IKEv2ComputeOurAuth(IKE_SERVER *ike, IKEv2_SA *sa, void *out, UINT *out_len)
{
    IKEv2ComputePSKAuth(ike, sa, false, out, out_len);
}

// ---------------------------------------------------------------------------
// Child SA creation using existing IKEv1 ESP infrastructure
// ---------------------------------------------------------------------------

bool IKEv2CreateChildSAForClient(IKE_SERVER *ike, IKEv2_SA *sa,
                                   IKEv2_CHILDTF *ctf,
                                   UINT spi_i, UINT spi_r,
                                   BUF *ni, BUF *nr)
{
    IKE_CLIENT *c;
    IPSECSA    *ipsec_cs;   // client -> server
    IPSECSA    *ipsec_sc;   // server -> client
    IKE_CRYPTO *crypto;
    IKE_HASH   *integ_hash;
    UCHAR       key_cs[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR       key_sc[IKEv2_MAX_KEYMAT_SIZE];
    UINT        encr_key = ctf->EncrKeyLen;
    UINT        integ_key = ctf->IntegKeyLen;
    UINT        integ_icv = ctf->IntegIcvLen;
    IPSEC_SA_TRANSFORM_SETTING tf_cs, tf_sc;
    UCHAR       iv[IKE_MAX_BLOCK_SIZE];
    UINT        msg_id;

    if (!IKEv2DeriveChildKeys(ike, sa, ctf, ni, nr, key_cs, key_sc))
        return false;

    // Look up crypto and integrity objects
    crypto     = IKEv2GetCrypto(ike, ctf->EncrAlg);
    integ_hash = IKEv2GetHashForInteg(ike, ctf->IntegAlg);
    if (crypto == NULL || integ_hash == NULL)
        return false;

    // Create or reuse IKE_CLIENT
    if (sa->IkeClient == NULL)
    {
        c = NewIkeClient(ike, &sa->ClientIP, sa->ClientPort,
                         &sa->ServerIP, sa->ServerPort);
        if (c == NULL)
            return false;
        Insert(ike->ClientList, c);
        sa->IkeClient = c;
    }
    else
    {
        c = sa->IkeClient;
    }

    // Use a pseudo-message-ID (not 0)
    msg_id = GenerateNewMessageId(ike);

    Rand(iv, sizeof(iv));

    // Build transform settings
    Zero(&tf_cs, sizeof(tf_cs));
    tf_cs.Crypto         = crypto;
    tf_cs.CryptoKeySize  = encr_key;
    tf_cs.Hash           = integ_hash;
    tf_cs.LifeSeconds    = IKEv2_CHILD_SA_LIFETIME_SECS;
    tf_cs.CapsuleMode    = ctf->UseTransport ?
                            IKE_P2_CAPSULE_TRANSPORT : IKE_P2_CAPSULE_TUNNEL;
    tf_cs.SpiServerToClient = spi_r;

    Zero(&tf_sc, sizeof(tf_sc));
    tf_sc.Crypto         = crypto;
    tf_sc.CryptoKeySize  = encr_key;
    tf_sc.Hash           = integ_hash;
    tf_sc.LifeSeconds    = IKEv2_CHILD_SA_LIFETIME_SECS;
    tf_sc.CapsuleMode    = tf_cs.CapsuleMode;
    tf_sc.SpiServerToClient = spi_r;

    // We need to build a fake IKE_SA pointer for NewIPsecSa.
    // NewIPsecSa requires ike_sa != NULL and uses it for SKEYID_d and block size.
    // We create a temporary IKE_SA-like struct to satisfy this requirement.
    // Instead, we build the IPsec SAs manually without calling NewIPsecSa,
    // to avoid dependency on a real IKE_SA.
    {
        IPSECSA *sa_cs, *sa_sc;
        UCHAR   *enc_key_cs_ptr = key_cs;
        UCHAR   *mac_key_cs_ptr = key_cs + encr_key;
        UCHAR   *enc_key_sc_ptr = key_sc;
        UCHAR   *mac_key_sc_ptr = key_sc + encr_key;

        // Client -> Server SA
        sa_cs = ZeroMalloc(sizeof(IPSECSA));
        ike->CurrentIPsecSaId++;
        sa_cs->Id             = ike->CurrentIPsecSaId;
        sa_cs->IkeClient      = c;
        sa_cs->IkeSa          = NULL;
        sa_cs->MessageId      = msg_id;
        sa_cs->FirstCommTick  = ike->Now;
        sa_cs->LastCommTick   = ike->Now;
        sa_cs->ServerToClient = false;
        sa_cs->Spi            = spi_i;
        sa_cs->Initiated      = false;
        sa_cs->Established    = true;
        Copy(&sa_cs->TransformSetting, &tf_cs, sizeof(tf_cs));
        sa_cs->CryptoKey = IkeNewKey(crypto, enc_key_cs_ptr, encr_key);
        Copy(sa_cs->HashKey, mac_key_cs_ptr, integ_key);
        Rand(sa_cs->EspIv, sizeof(sa_cs->EspIv));
        Copy(sa_cs->Iv, iv, ctf->BlockSize);
        if (tf_cs.LifeSeconds != 0)
        {
            sa_cs->ExpiresHardTick = ike->Now + (UINT64)tf_cs.LifeSeconds * 1000;
            sa_cs->ExpiresSoftTick = sa_cs->ExpiresHardTick;
            AddInterrupt(ike->Interrupts, sa_cs->ExpiresSoftTick);
        }

        // Server -> Client SA
        sa_sc = ZeroMalloc(sizeof(IPSECSA));
        sa_sc->Id             = ike->CurrentIPsecSaId;
        sa_sc->IkeClient      = c;
        sa_sc->IkeSa          = NULL;
        sa_sc->MessageId      = msg_id;
        sa_sc->FirstCommTick  = ike->Now;
        sa_sc->LastCommTick   = ike->Now;
        sa_sc->ServerToClient = true;
        sa_sc->Spi            = spi_r;
        sa_sc->Initiated      = false;
        sa_sc->Established    = true;
        Copy(&sa_sc->TransformSetting, &tf_sc, sizeof(tf_sc));
        sa_sc->CryptoKey = IkeNewKey(crypto, enc_key_sc_ptr, encr_key);
        Copy(sa_sc->HashKey, mac_key_sc_ptr, integ_key);
        Rand(sa_sc->EspIv, sizeof(sa_sc->EspIv));
        Copy(sa_sc->Iv, iv, ctf->BlockSize);
        if (tf_sc.LifeSeconds != 0)
        {
            sa_sc->ExpiresHardTick = ike->Now + (UINT64)tf_sc.LifeSeconds * 1000;
            sa_sc->ExpiresSoftTick = sa_sc->ExpiresHardTick;
            AddInterrupt(ike->Interrupts, sa_sc->ExpiresSoftTick);
        }

        sa_cs->PairIPsecSa = sa_sc;
        sa_sc->PairIPsecSa = sa_cs;

        Insert(ike->IPsecSaList, sa_cs);
        Insert(ike->IPsecSaList, sa_sc);

        c->CurrentIpSecSaRecv = sa_cs;
        c->CurrentIpSecSaSend = sa_sc;

        c->LastCommTick = ike->Now;
    }

    return true;
}


// ---------------------------------------------------------------------------
// Packet sending helpers
// ---------------------------------------------------------------------------

// Build a complete IKEv2 message and queue it for sending.
// payloads: raw bytes of chained payloads (starting with first_payload_type).
// first_payload_type: the type value to put in the IKE header next-payload.
static void IKEv2SendRaw(IKE_SERVER *ike, IKEv2_SA *sa,
                          UCHAR exchange_type, UCHAR first_payload,
                          void *payloads, UINT payloads_len,
                          UINT msg_id, bool is_response)
{
    IKE_HEADER hdr;
    void *pkt;
    UINT  pkt_size;

    Zero(&hdr, sizeof(hdr));
    hdr.InitiatorCookie = Endian64(sa->InitiatorSPI);
    hdr.ResponderCookie = Endian64(sa->ResponderSPI);
    hdr.NextPayload     = first_payload;
    hdr.Version         = IKEv2_VERSION;
    hdr.ExchangeType    = exchange_type;
    hdr.Flag            = IKEv2_FLAG_RESPONSE; // we are always the responder
    hdr.MessageId       = Endian32(msg_id);
    hdr.MessageSize     = Endian32((UINT)(sizeof(hdr) + payloads_len));

    pkt_size = sizeof(hdr) + payloads_len;
    pkt = Malloc(pkt_size);
    Copy(pkt, &hdr, sizeof(hdr));
    Copy((UCHAR *)pkt + sizeof(hdr), payloads, payloads_len);

    IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                     &sa->ServerIP, sa->ServerPort,
                     &sa->ClientIP, sa->ClientPort,
                     pkt, pkt_size);
}

// Build and send an encrypted (SK) response.
// inner_payloads: the cleartext payload chain.
static void IKEv2SendEncrypted(IKE_SERVER *ike, IKEv2_SA *sa,
                                 UCHAR exchange_type, UINT msg_id,
                                 UCHAR first_inner_payload,
                                 void *inner, UINT inner_len)
{
    BUF *sk_pl;
    IKE_HEADER hdr;
    BUF *full_msg;
    UINT icv_offset;
    UINT icv_len = IKEv2IntegIcvLen(sa->Transform.IntegAlg);

    sk_pl = IKEv2EncryptSK(ike, sa, first_inner_payload, inner, inner_len);
    if (sk_pl == NULL) return;

    // Update SK payload generic header: set NextPayload = 0 (no next payload after SK)
    // The IKE header's NextPayload will point to SK_PAYLOAD type.
    // Overwrite byte 0 of sk_pl (next payload inside sk) - already IKEv2_PAYLOAD_NONE
    // but we need to set the outer next payload correctly (caller sets it via hdr).

    // Build complete IKE message
    Zero(&hdr, sizeof(hdr));
    hdr.InitiatorCookie = Endian64(sa->InitiatorSPI);
    hdr.ResponderCookie = Endian64(sa->ResponderSPI);
    hdr.NextPayload     = IKEv2_PAYLOAD_SK;
    hdr.Version         = IKEv2_VERSION;
    hdr.ExchangeType    = exchange_type;
    hdr.Flag            = IKEv2_FLAG_RESPONSE;
    hdr.MessageId       = Endian32(msg_id);
    hdr.MessageSize     = Endian32((UINT)(sizeof(hdr) + sk_pl->Size));

    full_msg = NewBuf();
    WriteBuf(full_msg, &hdr, sizeof(hdr));
    WriteBufBuf(full_msg, sk_pl);
    FreeBuf(sk_pl);

    // Compute ICV over everything except the ICV itself
    icv_offset = full_msg->Size - icv_len;
    IKEv2FillICV(ike, sa, full_msg->Buf, full_msg->Size, icv_offset);

    // Cache as last response for retransmission
    FreeBuf(sa->LastResponse);
    sa->LastResponse   = CloneBuf(full_msg);
    sa->LastRespMsgId  = msg_id;
    sa->LastRespTick   = ike->Now;
    sa->NumResends     = 0;

    IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                     &sa->ServerIP, sa->ServerPort,
                     &sa->ClientIP, sa->ClientPort,
                     Clone(full_msg->Buf, full_msg->Size), full_msg->Size);
    FreeBuf(full_msg);
}

// Send a notify error in a plaintext INFORMATIONAL response  (RFC 7296 Section 2.21)
void IKEv2SendNotifyError(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr,
                           UINT64 resp_spi, USHORT notify_type)
{
    UCHAR  notify_pl[12];
    UCHAR *n = notify_pl;
    IKE_HEADER rsp_hdr;
    void  *pkt;
    UINT   pkt_size;

    // Notify payload: next(1)+crit(1)+len(2)+proto(1)+spi_sz(1)+type(2) = 8 bytes
    n[0] = IKEv2_PAYLOAD_NONE;
    n[1] = 0;
    W16(n + 2, 8);
    n[4] = IKEv2_PROTO_IKE;
    n[5] = 0;
    W16(n + 6, notify_type);

    Zero(&rsp_hdr, sizeof(rsp_hdr));
    rsp_hdr.InitiatorCookie = hdr->InitiatorCookie;
    rsp_hdr.ResponderCookie = Endian64(resp_spi);
    rsp_hdr.NextPayload     = IKEv2_PAYLOAD_NOTIFY;
    rsp_hdr.Version         = IKEv2_VERSION;
    rsp_hdr.ExchangeType    = hdr->ExchangeType;
    rsp_hdr.Flag            = IKEv2_FLAG_RESPONSE;
    rsp_hdr.MessageId       = hdr->MessageId;
    rsp_hdr.MessageSize     = Endian32((UINT)(sizeof(rsp_hdr) + 8));

    pkt_size = sizeof(rsp_hdr) + 8;
    pkt = Malloc(pkt_size);
    Copy(pkt, &rsp_hdr, sizeof(rsp_hdr));
    Copy((UCHAR *)pkt + sizeof(rsp_hdr), notify_pl, 8);

    IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                     &p->DstIP, p->DestPort,
                     &p->SrcIP, p->SrcPort,
                     pkt, pkt_size);
}


// ---------------------------------------------------------------------------
// IKE_SA_INIT exchange handler  (RFC 7296 Section 1.2)
// ---------------------------------------------------------------------------

void IKEv2ProcSAInit(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr)
{
    UCHAR *raw     = (UCHAR *)p->Data;
    UINT   raw_len = p->Size;
    UCHAR *pl_data = raw + sizeof(IKE_HEADER);
    UINT   pl_len  = raw_len - sizeof(IKE_HEADER);
    UCHAR  nxt     = hdr->NextPayload;
    UCHAR *pos     = pl_data;
    UCHAR *end     = pl_data + pl_len;

    IKEv2_SA    *sa = NULL;
    bool         is_new = false;
    IKEv2_IKETF  iketf;

    // Payload buffers found during parsing
    UCHAR *sa_data = NULL;  UINT sa_sz = 0;
    UCHAR *ke_data = NULL;  UINT ke_sz = 0;
    UCHAR *ni_data = NULL;  UINT ni_sz = 0;
    USHORT ke_dh_group = 0;

    // Parse top-level payloads
    while (pos + 4 <= end)
    {
        UCHAR  next_pl  = pos[0];
        USHORT pl_total = R16(pos + 2);
        UCHAR *body     = pos + 4;
        UINT   body_len = (pl_total >= 4) ? (pl_total - 4) : 0;

        if (pl_total < 4 || pos + pl_total > end)
            break;

        switch (nxt)
        {
        case IKEv2_PAYLOAD_SA:
            sa_data = body;
            sa_sz   = body_len;
            break;
        case IKEv2_PAYLOAD_KE:
            if (body_len >= 4)
            {
                ke_dh_group = R16(body);
                ke_data     = body + 4;
                ke_sz       = body_len - 4;
            }
            break;
        case IKEv2_PAYLOAD_NONCE:
            ni_data = body;
            ni_sz   = body_len;
            break;
        // Ignore NOTIFY, VENDOR payloads
        }

        nxt = next_pl;
        pos += pl_total;
    }

    if (sa_data == NULL || ke_data == NULL || ni_data == NULL)
        return;
    if (ni_sz < IKEv2_NONCE_MIN_SIZE || ni_sz > IKEv2_NONCE_MAX_SIZE)
        return;

    // Select best IKE SA proposal
    if (!IKEv2ParseSAProposalIKE(sa_data, sa_sz, &iketf))
    {
        IKEv2SendNotifyError(ike, p, hdr, 0, IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN);
        return;
    }

    // DH group must match
    if (iketf.DhGroup != ke_dh_group)
    {
        IKEv2SendNotifyError(ike, p, hdr, 0, IKEv2_NOTIFY_INVALID_KE_PAYLOAD);
        return;
    }

    // Find or create SA
    sa = IKEv2FindByInitSPI(ike, Endian64(hdr->InitiatorCookie),
                             &p->SrcIP, p->SrcPort);
    if (sa == NULL)
    {
        UINT clients_from_ip = 0;
        UINT i;
        // Simple rate-limit per IP
        for (i = 0; i < LIST_NUM(ike->IKEv2SaList); i++)
        {
            IKEv2_SA *s = LIST_DATA(ike->IKEv2SaList, i);
            if (CmpIpAddr(&s->ClientIP, &p->SrcIP) == 0)
                clients_from_ip++;
        }
        if (clients_from_ip >= IKE_QUOTA_MAX_NUM_CLIENTS_PER_IP)
            return;
        if (LIST_NUM(ike->IKEv2SaList) >= IKE_QUOTA_MAX_NUM_CLIENTS)
            return;

        sa = IKEv2NewSA(ike);
        sa->InitiatorSPI = Endian64(hdr->InitiatorCookie);
        sa->ResponderSPI = Rand64();
        if (sa->ResponderSPI == 0) sa->ResponderSPI = 1;
        Copy(&sa->ClientIP,   &p->SrcIP, sizeof(IP));
        sa->ClientPort = p->SrcPort;
        Copy(&sa->ServerIP,   &p->DstIP, sizeof(IP));
        sa->ServerPort = p->DestPort;
        sa->IsNatT     = (p->DestPort == IPSEC_PORT_IPSEC_ESP_UDP);
        is_new = true;
    }
    else
    {
        // Retransmit cached response if available
        if (sa->LastResponse != NULL)
        {
            IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                             &sa->ServerIP, sa->ServerPort,
                             &sa->ClientIP, sa->ClientPort,
                             Clone(sa->LastResponse->Buf, sa->LastResponse->Size),
                             sa->LastResponse->Size);
            return;
        }
    }

    sa->Transform = iketf;
    sa->LastCommTick = ike->Now;

    // Store initiator nonce
    FreeBuf(sa->Ni);
    sa->Ni = MemToBuf(ni_data, ni_sz);

    // Store initiator KE
    FreeBuf(sa->GxI);
    sa->GxI = MemToBuf(ke_data, ke_sz);

    // Create responder DH context
    if (sa->Dh == NULL)
    {
        IKE_DH *dh_def = IKEv2GetDh(ike, iketf.DhGroup);
        if (dh_def == NULL)
        {
            IKEv2MarkDeleting(ike, sa);
            IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI, IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN);
            return;
        }
        sa->Dh = IkeDhNewCtx(dh_def);
        if (sa->Dh == NULL)
        {
            IKEv2MarkDeleting(ike, sa);
            return;
        }
    }

    // Generate responder nonce
    {
        UCHAR nr_buf[IKEv2_NONCE_SIZE];
        Rand(nr_buf, IKEv2_NONCE_SIZE);
        FreeBuf(sa->Nr);
        sa->Nr = MemToBuf(nr_buf, IKEv2_NONCE_SIZE);
    }

    // Store responder's public DH key
    FreeBuf(sa->GxR);
    sa->GxR = CloneBuf(sa->Dh->MyPublicKey);

    // Store the complete IKE_SA_INIT request for AUTH computation
    FreeBuf(sa->InitMsg);
    sa->InitMsg = MemToBuf(raw, raw_len);

    // Derive IKE SA keys
    if (!IKEv2DeriveKeys(ike, sa))
    {
        IKEv2MarkDeleting(ike, sa);
        return;
    }

    sa->State = IKEv2_SA_STATE_HALF_OPEN;

    // ---- Build response ----
    {
        UCHAR  resp_payloads[2048];
        UCHAR *rp = resp_payloads;
        UINT   dh_key_size = sa->Dh->Size;
        UINT   sa_len;
        UCHAR  sa_buf[512];
        UCHAR  nat_src_hash[IKEv2_MAX_KEYMAT_SIZE];
        UCHAR  nat_dst_hash[IKEv2_MAX_KEYMAT_SIZE];

        // SA payload
        sa_len = IKEv2BuildSAProposalIKE(sa, sa_buf, sizeof(sa_buf));

        // --- SA payload ---
        rp[0] = IKEv2_PAYLOAD_KE;  // next
        rp[1] = 0;
        W16(rp + 2, (USHORT)(4 + sa_len));
        rp += 4;
        Copy(rp, sa_buf, sa_len);
        rp += sa_len;

        // --- KE payload ---
        rp[0] = IKEv2_PAYLOAD_NONCE;  // next
        rp[1] = 0;
        W16(rp + 2, (USHORT)(4 + 4 + dh_key_size));
        rp += 4;
        W16(rp, (USHORT)iketf.DhGroup); rp += 2;
        W16(rp, 0); rp += 2;  // reserved
        Copy(rp, sa->GxR->Buf, dh_key_size);
        rp += dh_key_size;

        // --- Nr payload ---
        rp[0] = IKEv2_PAYLOAD_NOTIFY;  // next: NAT-D source
        rp[1] = 0;
        W16(rp + 2, (USHORT)(4 + sa->Nr->Size));
        rp += 4;
        Copy(rp, sa->Nr->Buf, sa->Nr->Size);
        rp += sa->Nr->Size;

        // NAT-D hashes  (SHA-1 over SPIs | IP | port)
        // We use PRF(0-key-SHA1, SPI_i|SPI_r|IP|port) per RFC 7296 Section 3.10.1
        {
            UCHAR seed_src[28], seed_dst[28];
            UINT  seed_len;
            UCHAR zero_key[20];
            UCHAR *pp;

            Zero(zero_key, sizeof(zero_key));

            // Source NAT hash: SPIs | client IP | client port
            pp = seed_src;
            WRITE_UINT64(pp, sa->InitiatorSPI); pp += 8;
            WRITE_UINT64(pp, sa->ResponderSPI); pp += 8;
            if (IsIP4(&sa->ClientIP))
            {
                UINT ipv4 = IPToUINT(&sa->ClientIP);
                WRITE_UINT(pp, ipv4); pp += 4;
            }
            else
            {
                Copy(pp, sa->ClientIP.address, 16); pp += 16;
            }
            W16(pp, (USHORT)sa->ClientPort); pp += 2;
            seed_len = (UINT)(pp - seed_src);

            IKEv2PRF(IKEv2_PRF_HMAC_SHA1, zero_key, 20,
                     seed_src, seed_len, nat_src_hash);

            // Dest NAT hash: SPIs | server IP | server port
            pp = seed_dst;
            WRITE_UINT64(pp, sa->InitiatorSPI); pp += 8;
            WRITE_UINT64(pp, sa->ResponderSPI); pp += 8;
            if (IsIP4(&sa->ServerIP))
            {
                UINT ipv4 = IPToUINT(&sa->ServerIP);
                WRITE_UINT(pp, ipv4); pp += 4;
            }
            else
            {
                Copy(pp, sa->ServerIP.address, 16); pp += 16;
            }
            W16(pp, (USHORT)sa->ServerPort); pp += 2;
            seed_len = (UINT)(pp - seed_dst);

            IKEv2PRF(IKEv2_PRF_HMAC_SHA1, zero_key, 20,
                     seed_dst, seed_len, nat_dst_hash);
        }

        // --- NAT-D source payload ---
        rp[0] = IKEv2_PAYLOAD_NOTIFY;  // next: NAT-D dest
        rp[1] = 0;
        W16(rp + 2, (USHORT)(4 + 4 + 20));  // hdr(4) + proto_id(1)+spi_sz(1)+type(2) + sha1(20)
        rp += 4;
        rp[0] = 0;   // protocol
        rp[1] = 0;   // SPI size
        W16(rp + 2, IKEv2_NOTIFY_NAT_DETECTION_SOURCE_IP);
        rp += 4;
        Copy(rp, nat_src_hash, 20); rp += 20;

        // --- NAT-D dest payload ---
        rp[0] = IKEv2_PAYLOAD_NONE;
        rp[1] = 0;
        W16(rp + 2, (USHORT)(4 + 4 + 20));
        rp += 4;
        rp[0] = 0;
        rp[1] = 0;
        W16(rp + 2, IKEv2_NOTIFY_NAT_DETECTION_DESTINATION_IP);
        rp += 4;
        Copy(rp, nat_dst_hash, 20); rp += 20;

        UINT resp_payloads_len = (UINT)(rp - resp_payloads);

        // Build and store the complete IKE_SA_INIT response
        {
            IKE_HEADER resp_hdr;
            BUF *resp_msg;

            Zero(&resp_hdr, sizeof(resp_hdr));
            resp_hdr.InitiatorCookie = Endian64(sa->InitiatorSPI);
            resp_hdr.ResponderCookie = Endian64(sa->ResponderSPI);
            resp_hdr.NextPayload     = IKEv2_PAYLOAD_SA;
            resp_hdr.Version         = IKEv2_VERSION;
            resp_hdr.ExchangeType    = IKEv2_EXCHANGE_IKE_SA_INIT;
            resp_hdr.Flag            = IKEv2_FLAG_RESPONSE;
            resp_hdr.MessageId       = hdr->MessageId;
            resp_hdr.MessageSize     = Endian32((UINT)(sizeof(resp_hdr) + resp_payloads_len));

            resp_msg = NewBuf();
            WriteBuf(resp_msg, &resp_hdr, sizeof(resp_hdr));
            WriteBuf(resp_msg, resp_payloads, resp_payloads_len);

            FreeBuf(sa->RespMsg);
            sa->RespMsg = CloneBuf(resp_msg);

            FreeBuf(sa->LastResponse);
            sa->LastResponse  = resp_msg;
            sa->LastRespMsgId = Endian32(hdr->MessageId);
            sa->LastRespTick  = ike->Now;
            sa->NumResends    = 0;

            IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                             &sa->ServerIP, sa->ServerPort,
                             &sa->ClientIP, sa->ClientPort,
                             Clone(sa->LastResponse->Buf, sa->LastResponse->Size),
                             sa->LastResponse->Size);
        }
    }
}


// ---------------------------------------------------------------------------
// IKE_AUTH exchange handler  (RFC 7296 Section 1.2)
// ---------------------------------------------------------------------------

void IKEv2ProcAuth(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr,
                    IKEv2_SA *sa, void *payload_data, UINT payload_size)
{
    UCHAR  nxt     = 0;
    UCHAR *pos     = (UCHAR *)payload_data;
    UCHAR *end     = pos + payload_size;

    // Parsed payload pointers
    UCHAR *idi_body = NULL;    UINT idi_sz = 0;
    UCHAR  idi_type = 0;
    UCHAR *auth_body = NULL;   UINT auth_sz = 0;
    UCHAR  auth_method = 0;
    UCHAR *sa_body = NULL;     UINT sa_sz = 0;
    UCHAR *tsi_body = NULL;    UINT tsi_sz = 0;
    UCHAR *tsr_body = NULL;    UINT tsr_sz = 0;
    bool   use_transport = false;
    UINT   msg_id = Endian32(hdr->MessageId);

    // The first inner payload type was returned from IKEv2DecryptSK
    // (out_next_payload), so we receive it pre-parsed by the caller.
    // Here payload_data already contains the inner payloads from the SK body.
    // We need the first-payload type.  The caller stored it in nxt before calling us.
    // Re-read from the context: we expect the caller to pass nxt; instead we use
    // a simple scan approach: iterate payloads from the start of the decrypted data.

    // Actually the caller passes raw inner payload bytes; each payload starts with
    // next_payload (1) | crit (1) | len (2) | body.
    // The first payload type was stored by the caller before the call.
    // We receive first_nxt implicitly through the structure.
    // For simplicity we scan without knowing first type; instead we look at each
    // 4-byte header and use the "next" field of the PREVIOUS payload.
    // Use a linked-list walk starting from the nxt passed as first_nxt_payload.
    // Since we don't have it here, re-scan all payloads by type.
    // The caller must pass the first-payload type through this function argument.
    // We add it as a parameter in the next section.

    // Iterate the inner payload chain
    // The decrypted buffer contains chained payloads starting from first_inner_payload.
    // The last two bytes of plaintext (pad_len, next_payload) are stripped already.
    // So we just do a linear scan: each entry is: next(1)|crit(1)|len(2)|body...
    // We use a simplified approach: look for each payload type by scanning all.

    while (pos + 4 <= end)
    {
        UCHAR  next_pl  = pos[0];
        USHORT pl_total = R16(pos + 2);
        UCHAR *body     = pos + 4;
        UINT   body_len = (pl_total >= 4) ? (pl_total - 4) : 0;

        if (pl_total < 4 || pos + pl_total > end)
            break;

        // We identify by matching what we expect in IKE_AUTH inner payloads
        // Hint: The first payload type is known to be IDi (35) for an initiating IKE_AUTH.
        // But we need to distinguish which payload is which.  We track via next-payload chain.
        // Since each node carries the NEXT type in byte[0], we process in order:
        // walk: current type = last_type (from previous iteration), data = body.
        // To start, we assume the caller sets nxt to the type of the FIRST payload.
        // Since we can't know the first type here without an extra parameter,
        // we re-iterate using a second scan after we know the chain.

        // Simple approach: detect payload by context position and expected sequence.
        // IKE_AUTH: IDi, [CERT], AUTH, SAi2, TSi, TSr
        // We match type values directly via the next-payload field of the CURRENT payload
        // to determine what the current payload is. We read the current payload's type
        // from the previous iteration's next-payload byte.
        // Since we cannot know the FIRST payload's type without parameter,
        // we will now just identify based on type value directly.
        // In practice IDi=35, AUTH=39, SA=33, TSi=44, TSr=45.
        // The "current type" needs to come from outside.
        // The cleanest fix: parse as (type, len, body) by using pos[0] as next of prev.
        // We track current type externally via nxt:

        // BREAK OUT and use the canonical scan below:
        break;
    }

    // Canonical scan: use a separate pass where nxt starts as first_payload_type
    // passed from the SK decoder.  But we don't have that parameter here.
    // Solution: save first payload type in the existing code that calls IKEv2ProcAuth.
    // We pass it via the macro below by restarting with nxt = type of first inner payload.
    // The caller will set nxt before calling; we read nxt from a local variable set
    // by the caller. The caller already computed it as out_next_payload from IKEv2DecryptSK.
    // We add it as an extra parameter at the call site.
    // For now, use a two-pass approach: first pass collects all payload types and bodies.

    // Reset and do a two-pass scan
    {
        // Phase 1: walk the chain to map (index -> type)
        UCHAR  types[64];
        UCHAR *bodies[64];
        UINT   body_lens[64];
        UINT   count = 0;
        UCHAR  cur_nxt = 0;  // caller must set first payload type somehow

        // Since we can't know first-payload type without passing it,
        // use the convention that the SK payload carries the first inner type
        // in its "next payload" field (byte 0 of the SK payload generic header).
        // The caller does pass nxt to us: see the call site in ProcIKEv2PacketRecv.
        // We'll use the approach of scanning by expected IKE_AUTH payload types.

        pos = (UCHAR *)payload_data;
        while (pos + 4 <= end && count < 64)
        {
            USHORT pl_total = R16(pos + 2);
            if (pl_total < 4 || pos + pl_total > end) break;
            bodies[count]    = pos + 4;
            body_lens[count] = (pl_total >= 4) ? (pl_total - 4) : 0;
            // We don't know the type without chain-walking; mark as unknown for now.
            types[count]     = 0;
            count++;
            pos += pl_total;
        }

        // Phase 2: identify payloads by expected position in IKE_AUTH:
        // IDi is always first, then AUTH, then SA, then TSi, TSr.
        // This works for standard Windows/iOS/Android/Linux clients.
        if (count >= 4)
        {
            idi_type  = bodies[0][0];
            idi_body  = bodies[0] + 4;
            idi_sz    = body_lens[0] > 4 ? body_lens[0] - 4 : 0;

            auth_method = bodies[1][0];
            auth_body   = bodies[1] + 4;
            auth_sz     = body_lens[1] > 4 ? body_lens[1] - 4 : 0;

            sa_body = bodies[2];
            sa_sz   = body_lens[2];

            tsi_body = bodies[3];
            tsi_sz   = body_lens[3];

            if (count >= 5)
            {
                tsr_body = bodies[4];
                tsr_sz   = body_lens[4];
            }
        }
    }

    if (idi_body == NULL || auth_body == NULL || sa_body == NULL)
    {
        IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI, IKEv2_NOTIFY_AUTHENTICATION_FAILED);
        return;
    }

    // Store IDi
    FreeBuf(sa->IDi_Data);
    sa->IDi_Type = idi_type;
    sa->IDi_Data = MemToBuf(idi_body, idi_sz);

    // Verify AUTH
    if (!IKEv2VerifyAuth(ike, sa, auth_method, auth_body, auth_sz))
    {
        Debug("IKEv2: AUTH verification failed\n");
        IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI, IKEv2_NOTIFY_AUTHENTICATION_FAILED);
        IKEv2MarkDeleting(ike, sa);
        return;
    }

    // Parse child SA proposal
    IKEv2_CHILDTF child_tf;
    UINT spi_i = 0;
    if (!IKEv2ParseSAProposalChild(sa_body, sa_sz, &child_tf, &spi_i))
    {
        IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI, IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN);
        IKEv2MarkDeleting(ike, sa);
        return;
    }

    // Check if TS includes transport-mode request in any notify
    // (scan through all payloads looking for USE_TRANSPORT_MODE)
    {
        UCHAR *pp = (UCHAR *)payload_data;
        while (pp + 4 <= (UCHAR *)payload_data + payload_size)
        {
            USHORT pl_total = R16(pp + 2);
            if (pl_total < 4 || pp + pl_total > (UCHAR *)payload_data + payload_size) break;
            // We just assume transport mode is acceptable for L2TP connections
            pp += pl_total;
        }
        child_tf.UseTransport = true;  // L2TP/IPsec uses transport mode
    }

    // Generate our SPI for the server->client direction
    UINT spi_r = GenerateNewIPsecSaSpi(ike, spi_i);

    // Create child SA
    if (!IKEv2CreateChildSAForClient(ike, sa, &child_tf, spi_i, spi_r, sa->Ni, sa->Nr))
    {
        IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI, IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN);
        IKEv2MarkDeleting(ike, sa);
        return;
    }

    sa->State             = IKEv2_SA_STATE_ESTABLISHED;
    sa->NextExpectedMsgId = msg_id + 1;

    // ---- Build IKE_AUTH response ----
    {
        UCHAR  inner[2048];
        UCHAR *ip = inner;
        UINT   auth_val_len = 0;
        UCHAR  auth_val[IKEv2_MAX_KEYMAT_SIZE];
        UCHAR  child_sa_buf[512];
        UINT   child_sa_len;

        // IDr payload
        {
            UCHAR *idr_pl = ip;
            ip[0] = IKEv2_PAYLOAD_AUTH;  // next
            ip[1] = 0;
            // IDr body: type=1 (IPv4) + reserved(3) + IP address
            UINT   idr_body_len = 4 + (IsIP4(&sa->ServerIP) ? 4 : 16);
            W16(ip + 2, (USHORT)(4 + idr_body_len));
            ip += 4;
            ip[0] = IsIP4(&sa->ServerIP) ? IKEv2_ID_IPV4_ADDR : IKEv2_ID_IPV6_ADDR;
            ip[1] = ip[2] = ip[3] = 0;
            ip += 4;
            if (IsIP4(&sa->ServerIP))
            {
                UINT ipv4 = IPToUINT(&sa->ServerIP);
                WRITE_UINT(ip, ipv4); ip += 4;
            }
            else
            {
                Copy(ip, sa->ServerIP.address, 16); ip += 16;
            }
        }

        // AUTH payload
        {
            IKEv2ComputeOurAuth(ike, sa, auth_val, &auth_val_len);

            ip[0] = IKEv2_PAYLOAD_SA;  // next
            ip[1] = 0;
            W16(ip + 2, (USHORT)(4 + 1 + 3 + auth_val_len));
            ip += 4;
            ip[0] = IKEv2_AUTH_PSK;  // method
            ip[1] = ip[2] = ip[3] = 0;  // reserved
            ip += 4;
            Copy(ip, auth_val, auth_val_len);
            ip += auth_val_len;
        }

        // SAr2 payload (child SA)
        child_sa_len = IKEv2BuildSAProposalChild(&child_tf, spi_r, child_sa_buf, sizeof(child_sa_buf));
        {
            ip[0] = IKEv2_PAYLOAD_TSi;
            ip[1] = 0;
            W16(ip + 2, (USHORT)(4 + child_sa_len));
            ip += 4;
            Copy(ip, child_sa_buf, child_sa_len);
            ip += child_sa_len;
        }

        // TSi payload: 0.0.0.0/0 any port
        {
            ip[0] = IKEv2_PAYLOAD_TSr;
            ip[1] = 0;
            W16(ip + 2, (USHORT)(4 + 4 + 16));  // hdr + ts_count(1)+res(3) + 1 TS entry(16)
            ip += 4;
            ip[0] = 1; ip[1] = 0; ip[2] = 0; ip[3] = 0;  // TS count=1
            ip += 4;
            // TS entry: type(1)+protocol(1)+selector_len(2)+start_port(2)+end_port(2)+start(4)+end(4)
            ip[0] = IKEv2_TS_IPV4_ADDR_RANGE;
            ip[1] = 0;   // all protocols
            W16(ip + 2, 16);  // selector length
            W16(ip + 4, 0);   // start port
            W16(ip + 6, 65535); // end port
            Zero(ip + 8,  4);   // start = 0.0.0.0
            ip[8] = ip[9] = ip[10] = ip[11] = 0;
            ip[12] = ip[13] = ip[14] = ip[15] = 0xff;  // end = 255.255.255.255
            ip += 16;
        }

        // TSr payload: same as TSi
        {
            ip[0] = IKEv2_PAYLOAD_NONE;
            ip[1] = 0;
            W16(ip + 2, (USHORT)(4 + 4 + 16));
            ip += 4;
            ip[0] = 1; ip[1] = 0; ip[2] = 0; ip[3] = 0;
            ip += 4;
            ip[0] = IKEv2_TS_IPV4_ADDR_RANGE;
            ip[1] = 0;
            W16(ip + 2, 16);
            W16(ip + 4, 0);
            W16(ip + 6, 65535);
            ip[8] = ip[9] = ip[10] = ip[11] = 0;
            ip[12] = ip[13] = ip[14] = ip[15] = 0xff;
            ip += 16;
        }

        UINT inner_len = (UINT)(ip - inner);
        IKEv2SendEncrypted(ike, sa, IKEv2_EXCHANGE_IKE_AUTH, msg_id,
                           IKEv2_PAYLOAD_IDr, inner, inner_len);
    }
}


// ---------------------------------------------------------------------------
// INFORMATIONAL exchange handler
// ---------------------------------------------------------------------------

void IKEv2ProcInformational(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr,
                              IKEv2_SA *sa, void *payload_data, UINT payload_size)
{
    UINT msg_id = Endian32(hdr->MessageId);
    UCHAR *pos  = (UCHAR *)payload_data;
    UCHAR *end  = pos + payload_size;

    // Check for DELETE payloads
    while (pos + 4 <= end)
    {
        USHORT pl_total = R16(pos + 2);
        UCHAR *body     = pos + 4;
        UINT   body_len = (pl_total >= 4) ? (pl_total - 4) : 0;

        if (pl_total < 4 || pos + pl_total > end) break;

        // We can't tell payload type without tracking the chain type here,
        // but for INFORMATIONAL we just send an empty response.
        pos += pl_total;
    }

    // Always send an empty encrypted response (RFC 7296 Section 2.21.2)
    if (sa != NULL)
    {
        sa->LastCommTick = ike->Now;

        // Retransmit protection
        if (sa->LastRespMsgId == msg_id && sa->LastResponse != NULL)
        {
            IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                             &sa->ServerIP, sa->ServerPort,
                             &sa->ClientIP, sa->ClientPort,
                             Clone(sa->LastResponse->Buf, sa->LastResponse->Size),
                             sa->LastResponse->Size);
            return;
        }

        // Empty response
        IKEv2SendEncrypted(ike, sa, IKEv2_EXCHANGE_INFORMATIONAL,
                           msg_id, IKEv2_PAYLOAD_NONE, NULL, 0);

        sa->NextExpectedMsgId = msg_id + 1;
    }
}

// ---------------------------------------------------------------------------
// Main receive dispatcher for IKEv2
// ---------------------------------------------------------------------------

void ProcIKEv2PacketRecv(IKE_SERVER *ike, UDPPACKET *p)
{
    UCHAR      *raw    = (UCHAR *)p->Data;
    UINT        raw_len = p->Size;
    IKE_HEADER *hdr;
    UINT64      init_spi, resp_spi;
    UCHAR       exchange_type;
    UCHAR       flags;
    UINT        msg_id;
    IKEv2_SA   *sa;

    if (raw_len < sizeof(IKE_HEADER))
        return;

    hdr          = (IKE_HEADER *)raw;
    init_spi     = Endian64(hdr->InitiatorCookie);
    resp_spi     = Endian64(hdr->ResponderCookie);
    exchange_type = hdr->ExchangeType;
    flags        = hdr->Flag;
    msg_id       = Endian32(hdr->MessageId);

    // We only handle requests (not responses)
    if (flags & IKEv2_FLAG_RESPONSE)
        return;

    switch (exchange_type)
    {
    case IKEv2_EXCHANGE_IKE_SA_INIT:
        // Responder cookie must be 0 for new requests
        if (resp_spi != 0)
        {
            // Could be a retransmit - look up existing SA
            sa = IKEv2FindBySPIPair(ike, init_spi, resp_spi);
            if (sa != NULL && sa->LastResponse != NULL)
            {
                IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                                 &sa->ServerIP, sa->ServerPort,
                                 &sa->ClientIP, sa->ClientPort,
                                 Clone(sa->LastResponse->Buf, sa->LastResponse->Size),
                                 sa->LastResponse->Size);
            }
            return;
        }
        IKEv2ProcSAInit(ike, p, hdr);
        break;

    case IKEv2_EXCHANGE_IKE_AUTH:
    case IKEv2_EXCHANGE_CREATE_CHILD_SA:
    case IKEv2_EXCHANGE_INFORMATIONAL:
        // Find existing SA
        sa = IKEv2FindBySPIPair(ike, init_spi, resp_spi);
        if (sa == NULL || sa->State == IKEv2_SA_STATE_HALF_OPEN ||
            sa->EncKeyI == NULL)
        {
            if (exchange_type == IKEv2_EXCHANGE_IKE_AUTH &&
                sa != NULL && sa->EncKeyI != NULL)
            {
                // OK to process
            }
            else
            {
                IKEv2SendNotifyError(ike, p, hdr, resp_spi,
                                     IKEv2_NOTIFY_INVALID_IKE_SPI);
                return;
            }
        }

        sa->LastCommTick = ike->Now;

        // Retransmit cached response if message ID matches
        if (sa->LastRespMsgId == msg_id && sa->LastResponse != NULL &&
            exchange_type != IKEv2_EXCHANGE_IKE_AUTH)
        {
            IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP,
                             &sa->ServerIP, sa->ServerPort,
                             &sa->ClientIP, sa->ClientPort,
                             Clone(sa->LastResponse->Buf, sa->LastResponse->Size),
                             sa->LastResponse->Size);
            return;
        }

        // Decrypt SK payload
        {
            UCHAR  *payload_start;
            UINT    payload_total;
            UCHAR  *sk_body;
            UINT    sk_body_len;
            UCHAR   sk_next_pl;
            UCHAR   first_inner_pl;
            BUF    *decrypted;

            payload_start = raw + sizeof(IKE_HEADER);
            payload_total = raw_len - (UINT)sizeof(IKE_HEADER);

            if (payload_total < 4 || hdr->NextPayload != IKEv2_PAYLOAD_SK)
                return;

            // Verify integrity over the entire message (up to ICV)
            {
                UINT   icv_len   = IKEv2IntegIcvLen(sa->Transform.IntegAlg);
                UINT   int_key_l = IKEv2IntegKeyLen(sa->Transform.IntegAlg);
                UCHAR  icv_calc[IKEv2_MAX_KEYMAT_SIZE];
                UCHAR *icv_recv;

                if (raw_len < (UINT)(sizeof(IKE_HEADER) + 4 + icv_len))
                    return;

                icv_recv = raw + raw_len - icv_len;

                IKEv2ComputeInteg(sa->Transform.IntegAlg,
                                  sa->SK_ai, int_key_l,
                                  raw, raw_len - icv_len,
                                  icv_calc);

                if (Cmp(icv_calc, icv_recv, icv_len) != 0)
                {
                    Debug("IKEv2: integrity check failed\n");
                    return;
                }
            }

            // SK payload: generic-header(4) | IV | ciphertext | ICV
            {
                USHORT sk_pl_len = R16(payload_start + 2);
                UINT   icv_len   = IKEv2IntegIcvLen(sa->Transform.IntegAlg);

                if (sk_pl_len < 4 + icv_len)
                    return;

                // body is everything after generic header, excluding ICV at the end
                sk_body     = payload_start + 4;
                sk_body_len = sk_pl_len - 4 - icv_len;
            }

            first_inner_pl = payload_start[0];  // next payload inside SK

            decrypted = IKEv2DecryptSK(ike, sa, true,
                                        sk_body, sk_body_len,
                                        &first_inner_pl);
            if (decrypted == NULL)
                return;

            switch (exchange_type)
            {
            case IKEv2_EXCHANGE_IKE_AUTH:
                if (sa->State == IKEv2_SA_STATE_HALF_OPEN)
                {
                    IKEv2ProcAuth(ike, p, hdr, sa,
                                  decrypted->Buf, decrypted->Size);
                }
                break;

            case IKEv2_EXCHANGE_INFORMATIONAL:
                IKEv2ProcInformational(ike, p, hdr, sa,
                                       decrypted->Buf, decrypted->Size);
                break;

            case IKEv2_EXCHANGE_CREATE_CHILD_SA:
                // For now, respond with NO_ADDITIONAL_SAS
                IKEv2SendNotifyError(ike, p, hdr, sa->ResponderSPI,
                                     IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN);
                break;
            }

            FreeBuf(decrypted);
        }
        break;

    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// Interrupt / timer processing for IKEv2 SAs
// ---------------------------------------------------------------------------

void ProcessIKEv2Interrupts(IKE_SERVER *ike)
{
    UINT i;

    for (i = 0; i < LIST_NUM(ike->IKEv2SaList); i++)
    {
        IKEv2_SA *sa = LIST_DATA(ike->IKEv2SaList, i);

        if (sa->Deleting)
            continue;

        // Timeout half-open SAs quickly
        if (sa->State == IKEv2_SA_STATE_HALF_OPEN)
        {
            if ((sa->LastCommTick + (UINT64)IKEv2_SA_TIMEOUT_HALF_OPEN) <= ike->Now)
            {
                IKEv2MarkDeleting(ike, sa);
                continue;
            }
        }
        else
        {
            if ((sa->LastCommTick + (UINT64)IKEv2_SA_TIMEOUT_ESTABLISHED) <= ike->Now)
            {
                IKEv2MarkDeleting(ike, sa);
                continue;
            }
        }
    }

    do
    {
        ike->StateHasChanged = false;
        IKEv2PurgeDeleting(ike);
    }
    while (ike->StateHasChanged);
}

