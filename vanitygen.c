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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <pcre.h>

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>

const int debug = 0;

static const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void
encode_b58_check(void *buf, size_t len, char *result)
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
	binres = malloc(brlen);
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
		binres[--p] = b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = b58_alphabet[0];
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

void
encode_address(EC_KEY *pkey, int addrtype, char *result)
{
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	i2o_ECPublicKey(pkey, &pend);

	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

	encode_b58_check(binres, sizeof(binres), result);
}

void
encode_privkey(EC_KEY *pkey, int addrtype, char *result)
{
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = addrtype;
	nbytes = BN_bn2bin(bn, &eckey_buf[1]);

	encode_b58_check(eckey_buf, nbytes + 1, result);
}


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
	printf("%s\n", buf);
	OPENSSL_free(buf);
}

void
output_match(EC_KEY *pkey, int addrtype, int privtype)
{
	unsigned char key_buf[512], *pend;
	char print_buf[512];
	int len;

	assert(EC_KEY_check_key(pkey));

	/* Hexadecimal OpenSSL notation */
	pend = key_buf;
	len = i2o_ECPublicKey(pkey, &pend);
	printf("Pubkey (hex): ");
	dumphex(key_buf, len);
	pend = key_buf;
	len = i2d_ECPrivateKey(pkey, &pend);
	printf("Privkey (hex): ");
	dumphex(key_buf, len);

	/* Base-58 bitcoin notation public key hash */
	encode_address(pkey, addrtype, print_buf);
	printf("Address: %s\n", print_buf);

	/* Base-58 bitcoin notation private key */
	encode_privkey(pkey, privtype, print_buf);
	printf("Privkey: %s\n", print_buf);
}


/*
 * Search for a key for which the encoded address has a specific prefix.
 * Uses bignum arithmetic to predetermine value ranges.
 * Faster than regular expression searching.
 */
void
generate_address_prefix(int addrtype, int privtype, const char *pfx)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32];
	unsigned char binres[25] = {0,};
	char *dbuf;

	int i, p, c, t;
	int b58pow, b58ceil, b58top = 0;

	BN_ULONG npoints, rekey_at;

	int zero_prefix = 0;
	int check_upper = 0;

	BN_CTX *bnctx;
	BIGNUM *bnap, *bnbp, *bntp;
	BIGNUM bntarg, bnceil, bnfloor;
	BIGNUM bnbase;
	BIGNUM bnhigh, bnlow, bnhigh2, bnlow2;
	BIGNUM bntmp, bntmp2;

	EC_KEY *pkey;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT *ppnt = NULL;

	struct timeval tvstart, tvnow, tv;

	bnctx = BN_CTX_new();

	BN_init(&bntarg);
	BN_init(&bnceil);
	BN_init(&bnfloor);
	BN_init(&bnbase);
	BN_init(&bnhigh);
	BN_init(&bnlow);
	BN_init(&bnhigh2);
	BN_init(&bnlow2);
	BN_init(&bntmp);
	BN_init(&bntmp2);

	BN_set_word(&bnbase, 58);

	/*
	 * Step 1: compute the integer boundaries for accepted addresses
	 * Results are stored in bnlow, bnhigh, bnlow2, bnhigh2.
	 */

	p = strlen(pfx);

	for (i = 0; i < p; i++) {
		for (c = 0; c < 58; c++) {
			if (pfx[i] == b58_alphabet[c])
				break;
		}
		if (c >= 58) {
			printf("Invalid character '%c' in address\n", pfx[i]);
			return;
		}
		if (i == zero_prefix) {
			if (c == 0) {
				/* Add another zero prefix */
				zero_prefix++;
				if (zero_prefix > 19) {
					printf("Prefix is too long\n");
					return;
				}
				continue;
			}

			/* First non-zero character */
			b58top = c;
			BN_set_word(&bntarg, c);

		} else {
			BN_set_word(&bntmp2, c);
			BN_mul(&bntmp, &bntarg, &bnbase, bnctx);
			BN_add(&bntarg, &bntmp, &bntmp2);
		}
	}

	/* Power-of-two ceiling and floor values based on leading 1s */
	BN_clear(&bntmp);
	BN_set_bit(&bntmp, 200 - (zero_prefix * 8));
	BN_set_word(&bntmp2, 1);
	BN_sub(&bnceil, &bntmp, &bntmp2);
	BN_set_bit(&bnfloor, 192 - (zero_prefix * 8));

	if (b58top) {
		/*
		 * If a non-zero was given in the prefix, find the
		 * numeric boundaries of the prefix.
		 */
		BN_copy(&bntmp, &bnceil);
		bnap = &bntmp;
		bnbp = &bntmp2;
		b58pow = 0;
		while (BN_cmp(bnap, &bnbase) > 0) {
			b58pow++;
			BN_div(bnbp, NULL, bnap, &bnbase, bnctx);
			bntp = bnap;
			bnap = bnbp;
			bnbp = bntp;
		}
		b58ceil = BN_get_word(bnap);

		if ((b58pow - (p - zero_prefix)) < 6) {
			/*
			 * Do not allow the prefix to constrain the
			 * check value, this is ridiculous.
			 */
			printf("Prefix is too long\n");
			return;
		}

		BN_set_word(&bntmp2, b58pow - (p - zero_prefix));
		BN_exp(&bntmp, &bnbase, &bntmp2, bnctx);
		BN_mul(&bnlow, &bntmp, &bntarg, bnctx);
		BN_set_word(&bnhigh, 1);
		BN_sub(&bntmp2, &bntmp, &bnhigh);
		BN_add(&bnhigh, &bnlow, &bntmp2);

		if (b58top <= b58ceil) {
			/* Fill out the upper range too */
			check_upper = 1;
			BN_mul(&bnlow2, &bnlow, &bnbase, bnctx);
			BN_mul(&bntmp2, &bnhigh, &bnbase, bnctx);
			BN_set_word(&bntmp, 57);
			BN_add(&bnhigh2, &bntmp2, &bntmp);

			/*
			 * Addresses above the ceiling will have one
			 * fewer "1" prefix in front than we require.
			 */
			if (BN_cmp(&bnceil, &bnlow2) < 0)
				/* High prefix is above the ceiling */
				check_upper = 0;
			else if (BN_cmp(&bnceil, &bnhigh2) < 0)
				/* High prefix is partly above the ceiling */
				BN_copy(&bnhigh2, &bnceil);

			/*
			 * Addresses below the floor will have another
			 * "1" prefix in front instead of our target.
			 */
			if (BN_cmp(&bnfloor, &bnhigh) >= 0) {
				/* Low prefix is completely below the floor */
				check_upper = 0;
				BN_copy(&bnhigh, &bnhigh2);
				BN_copy(&bnlow, &bnlow2);
			}			
			else if (BN_cmp(&bnfloor, &bnlow) > 0) {
				/* Low prefix is partly below the floor */
				BN_copy(&bnlow, &bnfloor);
			}
		}

	} else {
		BN_copy(&bnhigh, &bnceil);
		BN_set_word(&bnlow, 0);
	}

	/* Limit the prefix to the address type */
	BN_clear(&bntmp);
	BN_set_word(&bntmp, addrtype);
	BN_lshift(&bntmp2, &bntmp, 192);

	if (check_upper) {
		if (BN_cmp(&bntmp2, &bnhigh2) > 0)
			check_upper = 0;
		else if (BN_cmp(&bntmp2, &bnlow2) > 0)
			BN_copy(&bnlow2, &bntmp2);
	}

	if (BN_cmp(&bntmp2, &bnhigh) > 0) {
		if (!check_upper) {
			printf("Address prefix not possible\n");
			return;
		}
		check_upper = 0;
		BN_copy(&bnhigh, &bnhigh2);
		BN_copy(&bnlow, &bnlow2);
	}
	else if (BN_cmp(&bntmp2, &bnlow) > 0) {
		BN_copy(&bnlow, &bntmp2);
	}

	BN_set_word(&bntmp, addrtype + 1);
	BN_lshift(&bntmp2, &bntmp, 192);

	if (check_upper) {
		if (BN_cmp(&bntmp2, &bnlow2) < 0)
			check_upper = 0;
		else if (BN_cmp(&bntmp2, &bnhigh2) < 0)
			BN_copy(&bnlow2, &bntmp2);
	}

	if (BN_cmp(&bntmp2, &bnlow) < 0) {
		if (!check_upper) {
			printf("Address prefix not possible\n");
			return;
		}
		check_upper = 0;
		BN_copy(&bnhigh, &bnhigh2);
		BN_copy(&bnlow, &bnlow2);
	}
	else if (BN_cmp(&bntmp2, &bnhigh) < 0) {
		BN_copy(&bnhigh, &bntmp2);
	}

	/* Address ranges are complete */

	if (debug) {
		if (check_upper) {
			printf("Upper Min: ");
			dumpbn(&bnlow2);
			printf("Upper Max: ");
			dumpbn(&bnhigh2);
		}
		printf("Min: ");
		dumpbn(&bnlow);
		printf("Max: ");
		dumpbn(&bnhigh);
	}

	/* Determine the probability of finding a match */
	BN_sub(&bntarg, &bnhigh, &bnlow);
	if (check_upper) {
		BN_sub(&bntmp, &bnhigh2, &bnlow2);
		BN_add(&bntmp2, &bntarg, &bntmp);
		BN_copy(&bntarg, &bntmp2);
	}
	BN_set_word(&bntmp, 0);
	BN_set_bit(&bntmp, 192);
	BN_div(&bntmp2, NULL, &bntmp, &bntarg, bnctx);
	dbuf = BN_bn2dec(&bntmp2);
	printf("Difficulty: %s\n", dbuf);
	OPENSSL_free(dbuf);

	/*
	 * Step 2: Search for matching private keys
	 * Generate a base private key, and start searching increments.
	 */

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	EC_KEY_precompute_mult(pkey, bnctx);

	npoints = 0;
	rekey_at = 0;
	binres[0] = addrtype;
	t = 0;
	c = 0;
	gettimeofday(&tvstart, NULL);
	while (1) {
		if (++npoints >= rekey_at) {
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, &bntmp, bnctx);
			BN_sub(&bntmp2,
			       &bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(&bntmp2);
			if ((rekey_at == BN_MASK2) || (rekey_at > 1000000))
				rekey_at = 1000000;
			assert(rekey_at > 0);

			if (ppnt)
				EC_POINT_free(ppnt);
			ppnt = EC_POINT_dup(EC_KEY_get0_public_key(pkey),
					    pgroup);

		} else {
			/* Common case: next point */
			EC_POINT_add(pgroup, ppnt, ppnt, pgen, bnctx);
		}

		/* Hash the public key */
		i = EC_POINT_point2oct(pgroup, ppnt,
				       POINT_CONVERSION_UNCOMPRESSED,
				       eckey_buf, sizeof(eckey_buf), bnctx);
		SHA256(eckey_buf, i, hash1);
		RIPEMD160(hash1, sizeof(hash1), &binres[1]);

		/*
		 * We constrain the prefix so that we can check for a match
		 * without generating the lower four byte check code.
		 */

		BN_bin2bn(binres, sizeof(binres), &bntarg);

		if ((check_upper &&
		     (BN_cmp(&bnlow2, &bntarg) <= 0) &&
		     (BN_cmp(&bnhigh2, &bntarg) > 0)) ||
		    ((BN_cmp(&bnlow, &bntarg) <= 0) &&
		     (BN_cmp(&bnhigh, &bntarg) > 0))) {

			printf("\n");

			if (npoints) {
				BN_clear(&bntmp);
				BN_set_word(&bntmp, npoints);
				BN_add(&bntmp2,
				       EC_KEY_get0_private_key(pkey),
				       &bntmp);
				EC_KEY_set_private_key(pkey, &bntmp2);
			}

			EC_KEY_set_public_key(pkey, ppnt);

			output_match(pkey, addrtype, privtype);
			break;
		}

		if (++c >= 20000) {
			long long rate;
			gettimeofday(&tvnow, NULL);
			timersub(&tvnow, &tvstart, &tv);
			memcpy(&tvstart, &tvnow, sizeof(tvstart));
			rate = tv.tv_usec + (1000000 * tv.tv_sec);
			rate = (1000000ULL * c) / rate;
			t += c;
			c = 0;
			printf("\r%lld K/s, total %d         ", rate, t);
			fflush(stdout);
		}
	}

	BN_clear_free(&bntarg);
	BN_clear_free(&bnceil);
	BN_clear_free(&bnfloor);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnhigh);
	BN_clear_free(&bnlow);
	BN_clear_free(&bnhigh2);
	BN_clear_free(&bnlow2);
	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	BN_CTX_free(bnctx);
	EC_KEY_free(pkey);
	EC_POINT_free(ppnt);
}


/*
 * Search for a key for which the encoded address matches a regular
 * expression.
 * Equivalent behavior to the bitcoin vanity address patch.
 */
void
generate_address_regex(int addrtype, int privtype, const char *re)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32], hash2[32];
	unsigned char binres[25] = {0,};
	char b58[40];

	int t, c, zpfx, p, d, re_vec[9];

	BN_ULONG npoints, rekey_at;

	BN_CTX *bnctx;
	BIGNUM bna, bnb, bnbase, bnrem, bntmp, bntmp2;
	BIGNUM *bn, *bndiv, *bnptmp;

	EC_KEY *pkey;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT *ppnt = NULL;

	pcre *regex;
	pcre_extra *regex_extra;
	const char *pcre_errptr;
	int pcre_erroffset;

	struct timeval tvstart, tvnow, tv;

	regex = pcre_compile(re, 0, &pcre_errptr, &pcre_erroffset, NULL);
	if (!regex) {
		const char *spaces = "                ";
		printf("%s\n", re);
		while (pcre_erroffset > 16) {
			printf("%s", spaces);
			pcre_erroffset -= 16;
		}
		if (pcre_erroffset > 0)
			printf("%s", &spaces[16 - pcre_erroffset]);
		printf("^\nRegex error: %s\n", pcre_errptr);
		return;
	}
	regex_extra = pcre_study(regex, 0, &pcre_errptr);
	if (!regex_extra) {
		printf("Regex error: %s\n", pcre_errptr);
		pcre_free(regex);
		return;
	}

	bnctx = BN_CTX_new();

	BN_init(&bna);
	BN_init(&bnb);
	BN_init(&bnbase);
	BN_init(&bnrem);
	BN_init(&bntmp);
	BN_init(&bntmp2);

	BN_set_word(&bnbase, 58);

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	EC_KEY_precompute_mult(pkey, bnctx);

	npoints = 0;
	rekey_at = 0;
	binres[0] = addrtype;
	t = 0;
	c = 0;
	gettimeofday(&tvstart, NULL);

	while (1) {
		if (++npoints >= rekey_at) {
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, &bntmp, bnctx);
			BN_sub(&bntmp2,
			       &bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(&bntmp2);
			if ((rekey_at == BN_MASK2) || (rekey_at > 1000000))
				rekey_at = 1000000;
			assert(rekey_at > 0);

			if (ppnt)
				EC_POINT_free(ppnt);
			ppnt = EC_POINT_dup(EC_KEY_get0_public_key(pkey),
					    pgroup);

		} else {
			/* Common case: next point */
			EC_POINT_add(pgroup, ppnt, ppnt, pgen, bnctx);
		}

		/* Hash the public key */
		d = EC_POINT_point2oct(pgroup, ppnt,
				       POINT_CONVERSION_UNCOMPRESSED,
				       eckey_buf, sizeof(eckey_buf), bnctx);
		SHA256(eckey_buf, d, hash1);
		RIPEMD160(hash1, sizeof(hash1), &binres[1]);

		/* Hash the hash and write the four byte check code */
		SHA256(binres, 21, hash1);
		SHA256(hash1, sizeof(hash1), hash2);
		memcpy(hash2, &binres[21], 4);

		bn = &bna;
		bndiv = &bnb;

		BN_bin2bn(binres, sizeof(binres), bn);

		/* Compute the complete encoded address */
		for (zpfx = 0; zpfx < 25 && binres[zpfx] == 0; zpfx++);
		p = sizeof(b58) - 1;
		b58[p] = '\0';
		while (!BN_is_zero(bn)) {
			BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
			bnptmp = bn;
			bn = bndiv;
			bndiv = bnptmp;
			d = BN_get_word(&bnrem);
			b58[--p] = b58_alphabet[d];
		}
		while (zpfx--) {
			b58[--p] = b58_alphabet[0];
		}

		/* Run the regular expression on it */
		d = pcre_exec(regex, regex_extra,
			      &b58[p], sizeof(b58) - (p+1), 0,
			      0,
			      re_vec, sizeof(re_vec)/sizeof(re_vec[0]));

		if (d > 0) {
			printf("\n");

			if (npoints) {
				BN_clear(&bntmp);
				BN_set_word(&bntmp, npoints);
				BN_add(&bntmp2,
				       EC_KEY_get0_private_key(pkey),
				       &bntmp);
				EC_KEY_set_private_key(pkey, &bntmp2);
			}

			EC_KEY_set_public_key(pkey, ppnt);

			output_match(pkey, addrtype, privtype);
			break;
		}

		if (d != PCRE_ERROR_NOMATCH) {
			printf("PCRE error: %d\n", d);
			break;
		}

		if (++c >= 10000) {
			long long rate;
			gettimeofday(&tvnow, NULL);
			timersub(&tvnow, &tvstart, &tv);
			memcpy(&tvstart, &tvnow, sizeof(tvstart));
			rate = tv.tv_usec + (1000000 * tv.tv_sec);
			rate = (1000000ULL * c) / rate;
			t += c;

			c = 0;
			printf("\r%lld K/s, total %d         ", rate, t);
			fflush(stdout);
		}
	}

	BN_clear_free(&bna);
	BN_clear_free(&bnb);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnrem);
	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	BN_CTX_free(bnctx);
	EC_KEY_free(pkey);
	EC_POINT_free(ppnt);
	pcre_free(regex_extra);
	pcre_free(regex);
}

void
usage(const char *name)
{
	printf(
"Usage: %s [-rNT] <pattern>\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-N            Generate namecoin address\n"
"-T            Generate bitcoin testnet address\n", name);
}

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int privtype = 128;
	int regex = 0;
	int opt;
	const char *pattern = argv[1];

	while ((opt = getopt(argc, argv, "rNTh?")) != -1) {
		switch (opt) {
		case 'r':
			regex = 1;
			break;
		case 'N':
			addrtype = 52;
			break;
		case 'T':
			addrtype = 111;
			privtype = 239;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}

	pattern = argv[optind];

	if (regex)
		generate_address_regex(addrtype, privtype, pattern);
	else
		generate_address_prefix(addrtype, privtype, pattern);

	return 0;
}
