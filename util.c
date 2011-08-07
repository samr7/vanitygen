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

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

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
