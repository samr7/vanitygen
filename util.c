/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(_WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(_WIN32) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "pattern.h"
#include "util.h"

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const signed char vg_b58_reverse_map[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void
fdumphex(FILE *fp, const unsigned char *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x", src[i]);
	}
	printf("\n");
}

void
fdumpbn(FILE *fp, const BIGNUM *bn)
{
	char *buf;
	buf = BN_bn2hex(bn);
	fprintf(fp, "%s\n", buf ? buf : "0");
	if (buf)
		OPENSSL_free(buf);
}

void
dumphex(const unsigned char *src, size_t len)
{
	fdumphex(stdout, src, len);
}

void
dumpbn(const BIGNUM *bn)
{
	fdumpbn(stdout, bn);
}

/*
 * Key format encode/decode
 */

void
vg_b58_encode_check(void *buf, size_t len, char *result)
{
	unsigned char hash1[32];
	unsigned char hash2[32];

	int d, p;

	BN_CTX *bnctx;
	BIGNUM *bn, *bndiv, *bntmp;
	BIGNUM bna, bnb, bnbase, bnrem;
	unsigned char *binres;
	int brlen, zpfx;

	bnctx = BN_CTX_new();
	BN_init(&bna);
	BN_init(&bnb);
	BN_init(&bnbase);
	BN_init(&bnrem);
	BN_set_word(&bnbase, 58);

	bn = &bna;
	bndiv = &bnb;

	brlen = (2 * len) + 4;
	binres = (unsigned char*) malloc(brlen);
	memcpy(binres, buf, len);

	SHA256(binres, len, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&binres[len], hash2, 4);

	BN_bin2bn(binres, len + 4, bn);

	for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

	p = brlen;
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
		bntmp = bn;
		bn = bndiv;
		bndiv = bntmp;
		d = BN_get_word(&bnrem);
		binres[--p] = vg_b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = vg_b58_alphabet[0];
	}

	memcpy(result, &binres[p], brlen - p);
	result[brlen - p] = '\0';

	free(binres);
	BN_clear_free(&bna);
	BN_clear_free(&bnb);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnrem);
	BN_CTX_free(bnctx);
}

#define skip_char(c) \
	(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int
vg_b58_decode_check(const char *input, void *buf, size_t len)
{
	int i, l, c;
	unsigned char *xbuf = NULL;
	BIGNUM bn, bnw, bnbase;
	BN_CTX *bnctx;
	unsigned char hash1[32], hash2[32];
	int zpfx;
	int res = 0;

	BN_init(&bn);
	BN_init(&bnw);
	BN_init(&bnbase);
	BN_set_word(&bnbase, 58);
	bnctx = BN_CTX_new();

	/* Build a bignum from the encoded value */
	l = strlen(input);
	for (i = 0; i < l; i++) {
		if (skip_char(input[i]))
			continue;
		c = vg_b58_reverse_map[(int)input[i]];
		if (c < 0)
			goto out;
		BN_clear(&bnw);
		BN_set_word(&bnw, c);
		BN_mul(&bn, &bn, &bnbase, bnctx);
		BN_add(&bn, &bn, &bnw);
	}

	/* Copy the bignum to a byte buffer */
	for (i = 0, zpfx = 0; input[i]; i++) {
		if (skip_char(input[i]))
			continue;
		if (input[i] != vg_b58_alphabet[0])
			break;
		zpfx++;
	}
	c = BN_num_bytes(&bn);
	l = zpfx + c;
	if (l < 5)
		goto out;
	xbuf = (unsigned char *) malloc(l);
	if (!xbuf)
		goto out;
	if (zpfx)
		memset(xbuf, 0, zpfx);
	if (c)
		BN_bn2bin(&bn, xbuf + zpfx);

	/* Check the hash code */
	l -= 4;
	SHA256(xbuf, l, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	if (memcmp(hash2, xbuf + l, 4))
		goto out;

	/* Buffer verified */
	if (len) {
		if (len > l)
			len = l;
		memcpy(buf, xbuf, len);
	}
	res = l;

out:
	if (xbuf)
		free(xbuf);
	BN_clear_free(&bn);
	BN_clear_free(&bnw);
	BN_clear_free(&bnbase);
	BN_CTX_free(bnctx);
	return res;
}

void
vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
		  int addrtype, char *result)
{
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   sizeof(eckey_buf),
			   NULL);
	pend = eckey_buf + 0x41;
	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_script_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			 int addrtype, char *result)
{
	unsigned char script_buf[69];
	unsigned char *eckey_buf = script_buf + 2;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	script_buf[ 0] = 0x51;  // OP_1
	script_buf[ 1] = 0x41;  // pubkey length
	// gap for pubkey
	script_buf[67] = 0x51;  // OP_1
	script_buf[68] = 0xae;  // OP_CHECKMULTISIG

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   65,
			   NULL);
	binres[0] = addrtype;
	SHA256(script_buf, 69, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result)
{
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = addrtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32)
		memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);

	vg_b58_encode_check(eckey_buf, 33, result);
}

int
vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey)
{
	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt &&
	       EC_KEY_set_private_key(pkey, bnpriv) &&
	       EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
	       EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt)
		EC_POINT_free(ppnt);

	if (!res)
		return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}

int
vg_decode_privkey(const char *b58encoded, EC_KEY *pkey, int *addrtype)
{
	BIGNUM bnpriv;
	unsigned char ecpriv[48];
	int res;

	res = vg_b58_decode_check(b58encoded, ecpriv, sizeof(ecpriv));
	if (res != 33)
		return 0;

	BN_init(&bnpriv);
	BN_bin2bn(ecpriv + 1, res - 1, &bnpriv);
	res = vg_set_privkey(&bnpriv, pkey);
	BN_clear_free(&bnpriv);
	*addrtype = ecpriv[0];
	return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
/* The generic PBKDF2 function first appeared in OpenSSL 1.0 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
int
PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
		  const unsigned char *salt, int saltlen, int iter,
		  const EVP_MD *digest,
		  int keylen, unsigned char *out)
{
	unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
	int cplen, j, k, tkeylen, mdlen;
	unsigned long i = 1;
	HMAC_CTX hctx;

	mdlen = EVP_MD_size(digest);
	if (mdlen < 0)
		return 0;

	HMAC_CTX_init(&hctx);
	p = out;
	tkeylen = keylen;
	if(!pass)
		passlen = 0;
	else if(passlen == -1)
		passlen = strlen(pass);
	while(tkeylen)
		{
		if(tkeylen > mdlen)
			cplen = mdlen;
		else
			cplen = tkeylen;
		/* We are unlikely to ever use more than 256 blocks (5120 bits!)
		 * but just in case...
		 */
		itmp[0] = (unsigned char)((i >> 24) & 0xff);
		itmp[1] = (unsigned char)((i >> 16) & 0xff);
		itmp[2] = (unsigned char)((i >> 8) & 0xff);
		itmp[3] = (unsigned char)(i & 0xff);
		HMAC_Init_ex(&hctx, pass, passlen, digest, NULL);
		HMAC_Update(&hctx, salt, saltlen);
		HMAC_Update(&hctx, itmp, 4);
		HMAC_Final(&hctx, digtmp, NULL);
		memcpy(p, digtmp, cplen);
		for(j = 1; j < iter; j++)
			{
			HMAC(digest, pass, passlen,
				 digtmp, mdlen, digtmp, NULL);
			for(k = 0; k < cplen; k++)
				p[k] ^= digtmp[k];
			}
		tkeylen-= cplen;
		i++;
		p+= cplen;
		}
	HMAC_CTX_cleanup(&hctx);
	return 1;
}
#endif  /* OPENSSL_VERSION_NUMBER < 0x10000000L */


typedef struct {
	int mode;
	int iterations;
	const EVP_MD *(*pbkdf_hash_getter)(void);
	const EVP_CIPHER *(*cipher_getter)(void);
} vg_protkey_parameters_t;

static const vg_protkey_parameters_t protkey_parameters[] = {
	{ 0, 4096,  EVP_sha256, EVP_aes_256_cbc },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 1, 4096,  EVP_sha256, EVP_aes_256_cbc },
};

static int
vg_protect_crypt(int parameter_group,
		 unsigned char *data_in, int data_in_len,
		 unsigned char *data_out,
		 const char *pass, int enc)
{
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *salt;
	unsigned char keymaterial[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + 
				  EVP_MAX_MD_SIZE];
	unsigned char hmac[EVP_MAX_MD_SIZE];
	int hmac_len = 0, hmac_keylen = 0;
	int salt_len;
	int plaintext_len = 32;
	int ciphertext_len;
	int pkcs7_padding = 1;
	const vg_protkey_parameters_t *params;
	const EVP_CIPHER *cipher;
	const EVP_MD *pbkdf_digest;
	const EVP_MD *hmac_digest;
	unsigned int hlen;
	int opos, olen, oincr, nbytes;
	int ipos;
	int ret = 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto out;

	if (parameter_group < 0) {
		if (enc)
			parameter_group = 0;
		else
			parameter_group = data_in[0];
	} else {
		if (!enc && (parameter_group != data_in[0]))
			goto out;
	}

	if (parameter_group > (sizeof(protkey_parameters) / 
			       sizeof(protkey_parameters[0])))
		goto out;
	params = &protkey_parameters[parameter_group];

	if (!params->iterations || !params->pbkdf_hash_getter)
		goto out;

	pbkdf_digest = params->pbkdf_hash_getter();
	cipher = params->cipher_getter();

	if (params->mode == 0) {
		/* Brief encoding */
		salt_len = 4;
		hmac_len = 8;
		hmac_keylen = 16;
		ciphertext_len = ((plaintext_len + cipher->block_size - 1) /
				  cipher->block_size) * cipher->block_size;
		pkcs7_padding = 0;
		hmac_digest = EVP_sha256();
	} else {
		/* PKCS-compliant encoding */
		salt_len = 8;
		ciphertext_len = ((plaintext_len + cipher->block_size) /
				  cipher->block_size) * cipher->block_size;
		hmac_digest = NULL;
	}

	if (!enc && (data_in_len != (1 + ciphertext_len + hmac_len + salt_len)))
		goto out;

	if (!pass || !data_out) {
		/* Format check mode */
		ret = plaintext_len;
		goto out;
	}

	if (!enc) {
		salt = data_in + 1 + ciphertext_len + hmac_len;
	} else if (salt_len) {
		salt = data_out + 1 + ciphertext_len + hmac_len;
		RAND_bytes(salt, salt_len);
	} else {
		salt = NULL;
	}

	PKCS5_PBKDF2_HMAC((const char *) pass, strlen(pass) + 1,
			  salt, salt_len,
			  params->iterations,
			  pbkdf_digest,
			  cipher->key_len + cipher->iv_len + hmac_keylen,
			  keymaterial);

	if (!EVP_CipherInit(ctx, cipher,
			    keymaterial,
			    keymaterial + cipher->key_len,
			    enc)) {
		fprintf(stderr, "ERROR: could not configure cipher\n");
		goto out;
	}

	if (!pkcs7_padding)
		EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (!enc) {
		opos = 0;
		olen = plaintext_len;
		nbytes = ciphertext_len;
		ipos = 1;
	} else {
		data_out[0] = parameter_group;
		opos = 1;
		olen = 1 + ciphertext_len + hmac_len + salt_len - opos;
		nbytes = plaintext_len;
		ipos = 0;
	}

	oincr = olen;
	if (!EVP_CipherUpdate(ctx, data_out + opos, &oincr,
			      data_in + ipos, nbytes))
		goto invalid_pass;
	opos += oincr;
	olen -= oincr;
	oincr = olen;
	if (!EVP_CipherFinal(ctx, data_out + opos, &oincr))
		goto invalid_pass;
	opos += oincr;

	if (hmac_len) {
		hlen = sizeof(hmac);
		HMAC(hmac_digest,
		     keymaterial + cipher->key_len + cipher->iv_len,
		     hmac_keylen,
		     enc ? data_in : data_out, plaintext_len,
		     hmac, &hlen);
		if (enc) {
			memcpy(data_out + 1 + ciphertext_len, hmac, hmac_len);
		} else if (memcmp(hmac,
				  data_in + 1 + ciphertext_len,
				  hmac_len))
			goto invalid_pass;
	}

	if (enc) {
		if (opos != (1 + ciphertext_len)) {
			fprintf(stderr, "ERROR: plaintext size mismatch\n");
			goto out;
		}
		opos += hmac_len + salt_len;
	} else if (opos != plaintext_len) {
		fprintf(stderr, "ERROR: plaintext size mismatch\n");
		goto out;
	}

	ret = opos;

	if (0) {
	invalid_pass:
		fprintf(stderr, "ERROR: Invalid password\n");
	}

out:
	OPENSSL_cleanse(hmac, sizeof(hmac));
	OPENSSL_cleanse(keymaterial, sizeof(keymaterial));
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int
vg_protect_encode_privkey(char *out,
			  const EC_KEY *pkey, int keytype,
			  int parameter_group,
			  const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[128];
	const BIGNUM *privkey;
	int nbytes;
	int restype;

	restype = (keytype & 1) ? 79 : 32;

	privkey = EC_KEY_get0_private_key(pkey);
	nbytes = BN_num_bytes(privkey);
	if (nbytes < 32)
		memset(ecpriv, 0, 32 - nbytes);
	BN_bn2bin(privkey, ecpriv + 32 - nbytes);

	nbytes = vg_protect_crypt(parameter_group,
				  ecpriv, 32,
				  &ecenc[1], pass, 1);
	if (nbytes <= 0)
		return 0;

	OPENSSL_cleanse(ecpriv, sizeof(ecpriv));

	ecenc[0] = restype;
	vg_b58_encode_check(ecenc, nbytes + 1, out);
	nbytes = strlen(out);
	return nbytes;
}


int
vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
			  const char *encoded, const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[128];
	BIGNUM bn;
	int restype;
	int res;

	res = vg_b58_decode_check(encoded, ecenc, sizeof(ecenc));

	if ((res < 2) || (res > sizeof(ecenc)))
		return 0;

	switch (ecenc[0]) {
	case 32:  restype = 128; break;
	case 79:  restype = 239; break;
	default:
		return 0;
	}

	if (!vg_protect_crypt(-1,
			      ecenc + 1, res - 1,
			      pkey ? ecpriv : NULL,
			      pass, 0))
		return 0;

	res = 1;
	if (pkey) {
		BN_init(&bn);
		BN_bin2bn(ecpriv, 32, &bn);
		res = vg_set_privkey(&bn, pkey);
		BN_clear_free(&bn);
		OPENSSL_cleanse(ecpriv, sizeof(ecpriv));
	}

	*keytype = restype;
	return res;
}

/*
 * Besides the bitcoin-adapted formats, we also support PKCS#8.
 */
int
vg_pkcs8_encode_privkey(char *out, int outlen,
			const EC_KEY *pkey, const char *pass)
{
	EC_KEY *pkey_copy = NULL;
	EVP_PKEY *evp_key = NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
	X509_SIG *pkcs8_enc = NULL;
	BUF_MEM *memptr;
	BIO *bio = NULL;
	int res = 0;

	pkey_copy = EC_KEY_dup(pkey);
	if (!pkey_copy)
		goto out;
	evp_key = EVP_PKEY_new();
	if (!evp_key || !EVP_PKEY_set1_EC_KEY(evp_key, pkey_copy))
		goto out;
	pkcs8 = EVP_PKEY2PKCS8(evp_key);
	if (!pkcs8)
		goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto out;

	if (!pass) {
		res = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, pkcs8);

	} else {
		pkcs8_enc = PKCS8_encrypt(-1,
					  EVP_aes_256_cbc(),
					  pass, strlen(pass),
					  NULL, 0,
					  4096,
					  pkcs8);
		if (!pkcs8_enc)
			goto out;
		res = PEM_write_bio_PKCS8(bio, pkcs8_enc);
	}

	BIO_get_mem_ptr(bio, &memptr);
	res = memptr->length;
	if (res < outlen) {
		memcpy(out, memptr->data, res);
		out[res] = '\0';
	} else {
		memcpy(out, memptr->data, outlen - 1);
		out[outlen-1] = '\0';
	}

out:
	if (bio)
		BIO_free(bio);
	if (pkey_copy)
		EC_KEY_free(pkey_copy);
	if (evp_key)
		EVP_PKEY_free(evp_key);
	if (pkcs8)
		PKCS8_PRIV_KEY_INFO_free(pkcs8);
	if (pkcs8_enc)
		X509_SIG_free(pkcs8_enc);
	return res;
}

int
vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in, const char *pass)
{
	EC_KEY *pkey_in = NULL;
	EC_KEY *test_key = NULL;
	EVP_PKEY *evp_key = NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
	X509_SIG *pkcs8_enc = NULL;
	BIO *bio = NULL;
	int res = 0;

	bio = BIO_new_mem_buf((char *)pem_in, strlen(pem_in));
	if (!bio)
		goto out;

	pkcs8_enc = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL);
	if (pkcs8_enc) {
		if (!pass)
			return -1;
		pkcs8 = PKCS8_decrypt(pkcs8_enc, pass, strlen(pass));

	} else {
		(void) BIO_reset(bio);
		pkcs8 = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio, NULL, NULL, NULL);
	}

	if (!pkcs8)
		goto out;
	evp_key = EVP_PKCS82PKEY(pkcs8);
	if (!evp_key)
		goto out;
	pkey_in = EVP_PKEY_get1_EC_KEY(evp_key);
	if (!pkey_in)
		goto out;

	/* Expect a specific curve */
	test_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!test_key ||
	    EC_GROUP_cmp(EC_KEY_get0_group(pkey_in),
			 EC_KEY_get0_group(test_key),
			 NULL))
		goto out;

	if (!EC_KEY_copy(pkey, pkey_in))
		goto out;

	res = 1;

out:
	if (bio)
		BIO_free(bio);
	if (test_key)
		EC_KEY_free(pkey_in);
	if (evp_key)
		EVP_PKEY_free(evp_key);
	if (pkcs8)
		PKCS8_PRIV_KEY_INFO_free(pkcs8);
	if (pkcs8_enc)
		X509_SIG_free(pkcs8_enc);
	return res;
}


int
vg_decode_privkey_any(EC_KEY *pkey, int *addrtype, const char *input,
		      const char *pass)
{
	int res;

	if (vg_decode_privkey(input, pkey, addrtype))
		return 1;
	if (vg_protect_decode_privkey(pkey, addrtype, input, NULL)) {
		if (!pass)
			return -1;
		return vg_protect_decode_privkey(pkey, addrtype, input, pass);
	}
	res = vg_pkcs8_decode_privkey(pkey, input, pass);
	if (res > 0) {
		/* Assume main network address */
		*addrtype = 128;
	}
	return res;
}


int
vg_read_password(char *buf, size_t size)
{
	return !EVP_read_pw_string(buf, size, "Enter new password:", 1);
}


/*
 * Password complexity checker
 * Heavily inspired by, but a simplification of "How Secure Is My Password?",
 * http://howsecureismypassword.net/
 */
static unsigned char ascii_class[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	5, 4, 5, 4, 4, 4, 4, 5, 4, 4, 4, 4, 5, 4, 5, 5,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 5, 5, 5, 4, 5, 5,
	4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 4, 4,
	5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 5, 5, 5, 0,
};

int
vg_check_password_complexity(const char *pass, int verbose)
{
	int i, len;
	int classes[6] = { 0, };
	const char *crackunit = "seconds";
	int char_complexity = 0;
	double crackops, cracktime;
	int weak;

	/*
	 * This number reflects a resourceful attacker with
	 * USD >$20K in 2011 hardware
	 */
	const int rate = 250000000;

	/* Consider the password weak if it can be cracked in <1 year */
	const int weak_threshold = (60*60*24*365);

	len = strlen(pass);
	for (i = 0; i < len; i++) {
		if (pass[i] > sizeof(ascii_class))
			/* FIXME: skip the rest of the UTF8 char */
			classes[5]++;
		else if (!ascii_class[(int)pass[i]])
			continue;
		else
			classes[(int)ascii_class[(int)pass[i]] - 1]++;
	}

	if (classes[0])
		char_complexity += 26;
	if (classes[1])
		char_complexity += 26;
	if (classes[2])
		char_complexity += 10;
	if (classes[3])
		char_complexity += 14;
	if (classes[4])
		char_complexity += 19;
	if (classes[5])
		char_complexity += 32;  /* oversimplified */

	/* This assumes brute-force and oversimplifies the problem */
	crackops = pow((double)char_complexity, (double)len);
	cracktime = (crackops * (1 - (1/M_E))) / rate;
	weak = (cracktime < weak_threshold);

	if (cracktime > 60.0) {
		cracktime /= 60.0;
		crackunit = "minutes";
		if (cracktime > 60.0) {
			cracktime /= 60.0;
			crackunit = "hours";
			if (cracktime > 24.0) {
				cracktime /= 24;
				crackunit = "days";
				if (cracktime > 365.0) {
					cracktime /= 365.0;
					crackunit = "years";
				}
			}
		}
	}

	/* Complain by default about weak passwords */
	if ((weak && (verbose > 0)) || (verbose > 1)) {
		if (cracktime < 1.0) {
			fprintf(stderr,
				"Estimated password crack time: >1 %s\n",
			       crackunit);
		} else if (cracktime < 1000000) {
			fprintf(stderr,
				"Estimated password crack time: %.1f %s\n",
				cracktime, crackunit);
		} else {
			fprintf(stderr,
				"Estimated password crack time: %e %s\n",
				cracktime, crackunit);
		}
		if (!classes[0] && !classes[1] && classes[2] &&
		    !classes[3] && !classes[4] && !classes[5]) {
			fprintf(stderr,
				"WARNING: Password contains only numbers\n");
		}
		else if (!classes[2] && !classes[3] && !classes[4] &&
			 !classes[5]) {
			if (!classes[0] || !classes[1]) {
				fprintf(stderr,
					"WARNING: Password contains "
					"only %scase letters\n",
					classes[0] ? "lower" : "upper");
			} else {
				fprintf(stderr,
					"WARNING: Password contains "
					"only letters\n");
			}
		}
	}

	return !weak;
}


/*
 * Pattern file reader
 * Absolutely disgusting, unable to free the pattern list when it's done
 */

int
vg_read_file(FILE *fp, char ***result, int *rescount)
{
	int ret = 1;

	char **patterns;
	char *buf = NULL, *obuf, *pat;
	const int blksize = 16*1024;
	int nalloc = 16;
	int npatterns = 0;
	int count, pos;

	patterns = (char**) malloc(sizeof(char*) * nalloc);
	count = 0;
	pos = 0;

	while (1) {
		obuf = buf;
		buf = (char *) malloc(blksize);
		if (!buf) {
			ret = 0;
			break;
		}
		if (pos < count) {
			memcpy(buf, &obuf[pos], count - pos);
		}
		pos = count - pos;
		count = fread(&buf[pos], 1, blksize - pos, fp);
		if (count < 0) {
			fprintf(stderr,
				"Error reading file: %s\n", strerror(errno));
			ret = 0;
		}
		if (count <= 0)
			break;
		count += pos;
		pat = buf;

		while (pos < count) {
			if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
				buf[pos] = '\0';
				if (pat) {
					if (npatterns == nalloc) {
						nalloc *= 2;
						patterns = (char**)
							realloc(patterns,
								sizeof(char*) *
								nalloc);
					}
					patterns[npatterns] = pat;
					npatterns++;
					pat = NULL;
				}
			}
			else if (!pat) {
				pat = &buf[pos];
			}
			pos++;
		}

		pos = pat ? (pat - buf) : count;
	}			

	*result = patterns;
	*rescount = npatterns;

	return ret;
}
