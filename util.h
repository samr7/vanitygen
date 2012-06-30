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

#if !defined (__VG_UTIL_H__)
#define __VG_UTIL_H__

#include <stdio.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

extern const char *vg_b58_alphabet;
extern const signed char vg_b58_reverse_map[256];

extern void fdumphex(FILE *fp, const unsigned char *src, size_t len);
extern void fdumpbn(FILE *fp, const BIGNUM *bn);
extern void dumphex(const unsigned char *src, size_t len);
extern void dumpbn(const BIGNUM *bn);

extern void vg_b58_encode_check(void *buf, size_t len, char *result);
extern int vg_b58_decode_check(const char *input, void *buf, size_t len);

extern void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			      int addrtype, char *result);
extern void vg_encode_script_address(const EC_POINT *ppoint,
				     const EC_GROUP *pgroup,
				     int addrtype, char *result);
extern void vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result);
extern int vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey);
extern int vg_decode_privkey(const char *b58encoded,
			     EC_KEY *pkey, int *addrtype);

enum {
	VG_PROTKEY_DEFAULT = -1,
	VG_PROTKEY_BRIEF_PBKDF2_4096_HMAC_SHA256_AES_256_CBC = 0,
	VG_PROTKEY_PKCS_PBKDF2_4096_HMAC_SHA256_AES_256_CBC = 16,
};

#define VG_PROTKEY_MAX_B58 128

extern int vg_protect_encode_privkey(char *out,
				     const EC_KEY *pkey, int keytype,
				     int parameter_group,
				     const char *pass);
extern int vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
				     const char *encoded, const char *pass);

extern int vg_pkcs8_encode_privkey(char *out, int outlen,
				   const EC_KEY *pkey,
				   const char *pass);
extern int vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in,
				   const char *pass);

extern int vg_decode_privkey_any(EC_KEY *pkey, int *addrtype,
				 const char *input, const char *pass);

extern int vg_read_password(char *buf, size_t size);
extern int vg_check_password_complexity(const char *pass, int verbose);

extern int vg_read_file(FILE *fp, char ***result, int *rescount);

#endif /* !defined (__VG_UTIL_H__) */
