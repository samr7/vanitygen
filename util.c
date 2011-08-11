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
dumphex(const unsigned char *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%02x", src[i]);
	}
	printf("\n");
}

void
dumpbn(const BIGNUM *bn)
{
	char *buf;
	buf = BN_bn2hex(bn);
	printf("%s\n", buf ? buf : "0");
	if (buf)
		OPENSSL_free(buf);
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
		c = vg_b58_reverse_map[(int)input[i]];
		if (c < 0)
			goto out;
		BN_clear(&bnw);
		BN_set_word(&bnw, c);
		BN_mul(&bn, &bn, &bnbase, bnctx);
		BN_add(&bn, &bn, &bnw);
	}

	/* Copy the bignum to a byte buffer */
	for (zpfx = 0;
	     input[zpfx] && (input[zpfx] == vg_b58_alphabet[0]);
	     zpfx++);
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
vg_encode_address(const EC_KEY *pkey, int addrtype, char *result)
{
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	i2o_ECPublicKey((EC_KEY*)pkey, &pend);

	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
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

	BN_init(&bnpriv);
	BN_bin2bn(ecpriv + 1, res - 1, &bnpriv);
	res = vg_set_privkey(&bnpriv, pkey);
	BN_clear_free(&bnpriv);

	if (res)
		*addrtype = ecpriv[0];
	return res;
}

#define VG_PROTKEY_SALT_SIZE 4
#define VG_PROTKEY_HMAC_SIZE 8
#define VG_PROTKEY_HMAC_KEY_SIZE 16

static int
vg_protect_setup(EVP_CIPHER_CTX *ctx, unsigned char *hmac_out,
		 const char *pass, const unsigned char *salt, int enc)
{
	unsigned char keymaterial[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + 
				  VG_PROTKEY_HMAC_KEY_SIZE];
	const EVP_CIPHER *cipher;

	cipher = EVP_aes_256_cbc();

	PKCS5_PBKDF2_HMAC((const char *) pass, strlen(pass) + 1,
			  salt, VG_PROTKEY_SALT_SIZE,
			  4096,
			  EVP_sha256(),
			  cipher->key_len + cipher->iv_len +
			  VG_PROTKEY_HMAC_KEY_SIZE,
			  keymaterial);

	if (!EVP_CipherInit(ctx, cipher,
			    keymaterial,
			    keymaterial + cipher->key_len,
			    enc)) {
		OPENSSL_cleanse(keymaterial, sizeof(keymaterial));
		printf("ERROR: could not configure cipher\n");
		return 0;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	memcpy(hmac_out,
	       keymaterial + cipher->key_len + cipher->iv_len, 
	       VG_PROTKEY_HMAC_KEY_SIZE);

	OPENSSL_cleanse(keymaterial, sizeof(keymaterial));
	return 1;
}

int
vg_protect_encode_privkey(char *out,
			  const EC_KEY *pkey, int keytype,
			  const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[64];
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned char salt[VG_PROTKEY_SALT_SIZE];
	unsigned char hmac_key[VG_PROTKEY_HMAC_KEY_SIZE];
	const BIGNUM *privkey;
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned int hlen;
	int opos, olen, oincr, nbytes;

	privkey = EC_KEY_get0_private_key(pkey);
	nbytes = BN_num_bytes(privkey);
	if (nbytes < 32)
		memset(ecpriv, 0, 32 - nbytes);
	BN_bn2bin(privkey, ecpriv + 32 - nbytes);

	ctx = EVP_CIPHER_CTX_new();

	/*
	 * The string representation of this protected key is
	 * ridiculously long.  To save a few bytes, we will only
	 * add four unique random bytes to the salt, out of the
	 * eight mandated by PBKDF.  This should not reduce its
	 * effectiveness.
	 */
	RAND_bytes(salt, VG_PROTKEY_SALT_SIZE);

	if (!vg_protect_setup(ctx, hmac_key, pass, salt, 1)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	hlen = sizeof(hmac);
	HMAC(EVP_sha256(),
	     hmac_key, VG_PROTKEY_HMAC_KEY_SIZE,
	     ecpriv, 32,
	     hmac, &hlen);

	OPENSSL_cleanse(hmac_key, sizeof(hmac_key));

	ecenc[0] = 136;
	opos = 1;
	olen = sizeof(ecenc) - opos;

	oincr = olen;
	EVP_EncryptUpdate(ctx, ecenc + opos, &oincr, ecpriv, 32);
	opos += oincr;
	olen -= oincr;

	oincr = olen;
	EVP_EncryptFinal(ctx, ecenc + opos, &oincr);
	opos += oincr;

	EVP_CIPHER_CTX_free(ctx);

	memcpy(ecenc + opos, hmac, VG_PROTKEY_HMAC_SIZE);
	opos += VG_PROTKEY_HMAC_SIZE;

	memcpy(ecenc + opos, salt, VG_PROTKEY_SALT_SIZE);
	opos += VG_PROTKEY_SALT_SIZE;

	vg_b58_encode_check(ecenc, opos, out);
	nbytes = strlen(out);
	assert(nbytes == 67);
	return nbytes;
}


int
vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
			  const char *encoded, const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[64];
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned char salt[VG_PROTKEY_SALT_SIZE];
	unsigned char hmac_key[VG_PROTKEY_HMAC_KEY_SIZE];
	EVP_CIPHER_CTX *ctx = NULL;
	BIGNUM bn;
	unsigned int hlen;
	int opos, olen, oincr;
	int res;

	res = vg_b58_decode_check(encoded, ecenc, sizeof(ecenc));
	if (res != 45)
		return 0;

	memcpy(salt, ecenc + 41, VG_PROTKEY_SALT_SIZE);

	ctx = EVP_CIPHER_CTX_new();

	if (!vg_protect_setup(ctx, hmac_key, pass, salt, 0)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	opos = 0;
	olen = sizeof(ecenc) - opos;
	oincr = olen;
	EVP_DecryptUpdate(ctx, ecpriv + opos, &oincr, ecenc + 1, 32);
	opos += oincr;
	olen -= oincr;

	oincr = olen;
	EVP_DecryptFinal(ctx, ecpriv + opos, &oincr);
	opos += oincr;

	EVP_CIPHER_CTX_free(ctx);

	hlen = sizeof(hmac);
	HMAC(EVP_sha256(),
	     hmac_key, VG_PROTKEY_HMAC_KEY_SIZE,
	     ecpriv, 32,
	     hmac, &hlen);

	if (memcmp(ecenc + 33, hmac, VG_PROTKEY_HMAC_SIZE)) {
		OPENSSL_cleanse(ecpriv, sizeof(ecpriv));
		printf("ERROR: invalid password\n");
		return 0;
	}

	BN_init(&bn);
	BN_bin2bn(ecpriv, 32, &bn);
	res = vg_set_privkey(&bn, pkey);
	BN_clear_free(&bn);
	OPENSSL_cleanse(ecpriv, sizeof(ecpriv));

	if (res) {
		switch(ecenc[0]) {
		case 136:
			*keytype = 128;
			break;
		default:
			printf("Unrecognized private key type\n");
			res = 0;
			break;
		}
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
			printf("Estimated password crack time: >1 %s\n",
			       crackunit);
		} else if (cracktime < 1000000) {
			printf("Estimated password crack time: %.1f %s\n",
			       cracktime, crackunit);
		} else {
			printf("Estimated password crack time: %e %s\n",
			       cracktime, crackunit);
		}
		if (!classes[0] && !classes[1] && classes[2] &&
		    !classes[3] && !classes[4] && !classes[5]) {
			printf("WARNING: Password contains only numbers\n");
		}
		else if (!classes[2] && !classes[3] && !classes[4] &&
			 !classes[5]) {
			if (!classes[0] || !classes[1]) {
				printf("WARNING: Password contains "
				       "only %scase letters\n",
				       classes[0] ? "lower" : "upper");
			} else {
				printf("WARNING: Password contains "
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
			printf("Error reading file: %s\n", strerror(errno));
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
