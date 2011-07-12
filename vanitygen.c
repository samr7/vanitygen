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
#include <string.h>
#include <math.h>
#include <assert.h>

#include <pthread.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <pcre.h>

#ifndef _WIN32
#define INLINE inline
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#else
#include "winglue.c"
#endif

const char *version = "0.10";
const int debug = 0;
int verbose = 1;
int remove_on_match = 1;
const char *result_file = NULL;

const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
	printf("%s\n", buf ? buf : "0");
	if (buf)
		OPENSSL_free(buf);
}


typedef struct _vg_thread_context_s {
	BN_CTX		*vct_bnctx;
	EC_KEY		*vct_key;
	EC_POINT	*vct_point;
	int		vct_delta;
	unsigned char	vct_binres[25];
	BIGNUM		vct_bntarg;
	BIGNUM		vct_bnbase;
	BIGNUM		vct_bntmp;
	BIGNUM		vct_bntmp2;
} vg_thread_context_t;


struct _vg_context_s;

typedef int (*vg_test_func_t)(struct _vg_context_s *,
			      vg_thread_context_t *);

typedef struct _vg_context_s {
	int			vc_addrtype;
	int			vc_privtype;
	unsigned long		vc_npatterns;
	unsigned long		vc_npatterns_start;
	unsigned long long	vc_found;
	double			vc_chance;
	vg_test_func_t		vc_test;
} vg_context_t;


typedef struct _timing_info_s {
	struct _timing_info_s	*ti_next;
	pthread_t		ti_thread;
	unsigned long		ti_last_rate;
} timing_info_t;

void
output_timing(int cycle, struct timeval *last, vg_context_t *vcp)
{
	static unsigned long long total = 0, prevfound = 0, sincelast = 0;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static timing_info_t *timing_head = NULL;

	pthread_t me;
	struct timeval tvnow, tv;
	timing_info_t *tip, *mytip;
	unsigned long long rate, myrate;
	double count, prob, time, targ;
	char linebuf[80];
	char *unit;
	int rem, p, i;

	const double targs[] = { 0.5, 0.75, 0.8, 0.9, 0.95, 1.0 };

	/* Compute the rate */
	gettimeofday(&tvnow, NULL);
	timersub(&tvnow, last, &tv);
	memcpy(last, &tvnow, sizeof(*last));
	myrate = tv.tv_usec + (1000000 * tv.tv_sec);
	myrate = (1000000ULL * cycle) / myrate;

	pthread_mutex_lock(&mutex);
	me = pthread_self();
	rate = myrate;
	for (tip = timing_head, mytip = NULL; tip != NULL; tip = tip->ti_next) {
		if (pthread_equal(tip->ti_thread, me)) {
			mytip = tip;
			tip->ti_last_rate = myrate;
		} else
			rate += tip->ti_last_rate;
	}
	if (!mytip) {
		mytip = (timing_info_t *) malloc(sizeof(*tip));
		mytip->ti_next = timing_head;
		mytip->ti_thread = me;
		timing_head = mytip;
		mytip->ti_last_rate = myrate;
	}

	total += cycle;
	if (prevfound != vcp->vc_found) {
		prevfound = vcp->vc_found;
		sincelast = 0;
	}
	sincelast += cycle;
	count = sincelast;

	if (mytip != timing_head) {
		pthread_mutex_unlock(&mutex);
		return;
	}
	pthread_mutex_unlock(&mutex);

	rem = sizeof(linebuf);
	p = snprintf(linebuf, rem, "[%lld K/s][total %lld]", rate, total);
	assert(p > 0);
	rem -= p;
	if (rem < 0)
		rem = 0;

	if (vcp->vc_chance >= 1.0) {
		prob = 1.0f - exp(-count/vcp->vc_chance);

		if (prob <= 0.999) {
			p = snprintf(&linebuf[p], rem, "[Prob %.1f%%]",
				     prob * 100);
			assert(p > 0);
			rem -= p;
			if (rem < 0)
				rem = 0;
			p = sizeof(linebuf) - rem;
		}

		for (i = 0; i < sizeof(targs)/sizeof(targs[0]); i++) {
			targ = targs[i];
			if ((targ < 1.0) && (prob <= targ))
				break;
		}

		if (targ < 1.0) {
			time = ((-vcp->vc_chance * log(1.0 - targ)) - count) /
				rate;
			unit = "s";
			if (time > 60) {
				time /= 60;
				unit = "min";
				if (time > 60) {
					time /= 60;
					unit = "h";
					if (time > 24) {
						time /= 24;
						unit = "d";
						if (time > 365) {
							time /= 365;
							unit = "y";
						}
					}
				}
			}

			if (time > 1000000) {
				p = snprintf(&linebuf[p], rem,
					     "[%d%% in %e%s]",
					     (int) (100 * targ), time, unit);
			} else {
				p = snprintf(&linebuf[p], rem,
					     "[%d%% in %.1f%s]",
					     (int) (100 * targ), time, unit);
			}
			assert(p > 0);
			rem -= p;
			if (rem < 0)
				rem = 0;
			p = sizeof(linebuf) - rem;
		}
	}

	if (vcp->vc_found) {
		if (remove_on_match)
			p = snprintf(&linebuf[p], rem, "[Found %lld/%ld]",
				     vcp->vc_found, vcp->vc_npatterns_start);
		else
			p = snprintf(&linebuf[p], rem, "[Found %lld]",
				     vcp->vc_found);
		assert(p > 0);
		rem -= p;
		if (rem < 0)
			rem = 0;
	}

	if (rem) {
		memset(&linebuf[sizeof(linebuf)-rem], 0x20, rem);
		linebuf[sizeof(linebuf)-1] = '\0';
	}
	printf("\r%s", linebuf);
	fflush(stdout);
}

void
output_match(EC_KEY *pkey, const char *pattern, vg_context_t *vcp)
{
	unsigned char key_buf[512], *pend;
	char addr_buf[64];
	char privkey_buf[128];
	int len;

	assert(EC_KEY_check_key(pkey));
	encode_address(pkey, vcp->vc_addrtype, addr_buf);
	encode_privkey(pkey, vcp->vc_privtype, privkey_buf);

	if (!result_file || (verbose > 0)) {
		printf("\r%79s\rPattern: %s\n", "", pattern);
	}

	if (verbose > 0) {
		if (verbose > 1) {
			/* Hexadecimal OpenSSL notation */
			pend = key_buf;
			len = i2o_ECPublicKey(pkey, &pend);
			printf("Pubkey (ASN1): ");
			dumphex(key_buf, len);
			pend = key_buf;
			len = i2d_ECPrivateKey(pkey, &pend);
			printf("Privkey (ASN1): ");
			dumphex(key_buf, len);
		}

	}

	if (!result_file || (verbose > 0)) {
		printf("Address: %s\n"
		       "Privkey: %s\n",
		       addr_buf, privkey_buf);
	}

	if (result_file) {
		FILE *fp = fopen(result_file, "a");
		if (!fp) {
			printf("ERROR: could not open result file: %s\n",
			       strerror(errno));
		} else {
			fprintf(fp,
				"Pattern: %s\n"
				"Address: %s\n"
				"Privkey: %s\n",
				pattern, addr_buf, privkey_buf);
			fclose(fp);
		}
	}
}


/*
 * Address search thread main loop
 */

void *
vg_thread_loop(vg_context_t *vcp)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32];

	int i, c, len;

	BN_ULONG npoints, rekey_at, nbatch;

	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	const int ptarraysize = 256;
	EC_POINT *ppnt[ptarraysize];

	vg_thread_context_t ctx;
	vg_test_func_t test_func = vcp->vc_test;

	struct timeval tvstart;

	static pthread_mutex_t crypto_mutex = PTHREAD_MUTEX_INITIALIZER;

	memset(ctx.vct_binres, 0, sizeof(ctx.vct_binres));

	ctx.vct_bnctx = BN_CTX_new();
	BN_init(&ctx.vct_bntarg);
	BN_init(&ctx.vct_bnbase);
	BN_init(&ctx.vct_bntmp);
	BN_init(&ctx.vct_bntmp2);

	BN_set_word(&ctx.vct_bnbase, 58);

	pthread_mutex_lock(&crypto_mutex);
	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	assert(pkey);
	pgroup = EC_KEY_get0_group(pkey);
	assert(pgroup);
	pgen = EC_GROUP_get0_generator(pgroup);
	assert(pgen);

	EC_KEY_precompute_mult(pkey, ctx.vct_bnctx);
	pthread_mutex_unlock(&crypto_mutex);

	for (i = 0; i < ptarraysize; i++) {
		ppnt[i] = EC_POINT_new(pgroup);
		if (!ppnt[i]) {
			printf("ERROR: out of memory?\n");
			exit(1);
		}
	}

	npoints = 0;
	rekey_at = 0;
	nbatch = 0;
	ctx.vct_key = pkey;
	ctx.vct_binres[0] = vcp->vc_addrtype;
	c = 0;
	gettimeofday(&tvstart, NULL);
	while (1) {
		if (npoints >= rekey_at) {
			pthread_mutex_lock(&crypto_mutex);
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, &ctx.vct_bntmp,
					   ctx.vct_bnctx);
			BN_sub(&ctx.vct_bntmp2,
			       &ctx.vct_bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(&ctx.vct_bntmp2);
			if ((rekey_at == BN_MASK2) || (rekey_at > 1000000))
				rekey_at = 1000000;
			assert(rekey_at > 0);

			EC_POINT_copy(ppnt[0], EC_KEY_get0_public_key(pkey));
			pthread_mutex_unlock(&crypto_mutex);

			npoints++;
			ctx.vct_delta = 0;

		} else {
			assert(nbatch > 0);
			EC_POINT_add(pgroup,
				     ppnt[0],
				     ppnt[nbatch-1],
				     pgen, ctx.vct_bnctx);
			npoints++;
		}

		/*
		 * The single most expensive operation performed in this
		 * loop is modular inversion of ppnt->Z.  There is an
		 * algorithm implemented in OpenSSL to do batched inversion
		 * that only does one actual BN_mod_inverse(), and saves
		 * a _lot_ of time.
		 *
		 * To take advantage of this, we batch up a few points,
		 * and feed them to EC_POINTs_make_affine() below.
		 */

		for (nbatch = 1;
		     (nbatch < ptarraysize) && (npoints < rekey_at);
		     nbatch++, npoints++) {
			EC_POINT_add(pgroup,
				     ppnt[nbatch],
				     ppnt[nbatch-1],
				     pgen, ctx.vct_bnctx);
		}

		EC_POINTs_make_affine(pgroup, nbatch, ppnt, ctx.vct_bnctx);

		for (i = 0; i < nbatch; i++, ctx.vct_delta++) {
			/* Hash the public key */
			len = EC_POINT_point2oct(pgroup, ppnt[i],
						 POINT_CONVERSION_UNCOMPRESSED,
						 eckey_buf, sizeof(eckey_buf),
						 ctx.vct_bnctx);
			SHA256(eckey_buf, len, hash1);
			RIPEMD160(hash1, sizeof(hash1), &ctx.vct_binres[1]);

			ctx.vct_point = ppnt[i];

			switch (test_func(vcp, &ctx)) {
			case 1:
				npoints = 0;
				rekey_at = 0;
				i = nbatch;
				break;
			case 2:
				goto out;
			default:
				break;
			}
		}

		if ((c += nbatch) >= 50000) {
			output_timing(c, &tvstart, vcp);
			c = 0;
		}
	}

out:
	BN_clear_free(&ctx.vct_bntarg);
	BN_clear_free(&ctx.vct_bnbase);
	BN_clear_free(&ctx.vct_bntmp);
	BN_clear_free(&ctx.vct_bntmp2);
	BN_CTX_free(ctx.vct_bnctx);
	EC_KEY_free(pkey);
	for (i = 0; i < ptarraysize; i++)
		EC_POINT_free(ppnt[i]);
	return NULL;
}



const signed char b58_reverse_map[256] = {
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

/*
 * Find the bignum ranges that produce a given prefix.
 */
int
get_prefix_ranges(int addrtype, const char *pfx, BIGNUM **result,
		  BN_CTX *bnctx)
{
	int i, p, c;
	int zero_prefix = 0;
	int check_upper = 0;
	int b58pow, b58ceil, b58top = 0;
	int ret = 0;

	BIGNUM bntarg, bnceil, bnfloor;
	BIGNUM bnbase;
	BIGNUM *bnap, *bnbp, *bntp;
	BIGNUM *bnhigh = NULL, *bnlow = NULL, *bnhigh2 = NULL, *bnlow2 = NULL;
	BIGNUM bntmp, bntmp2;

	BN_init(&bntarg);
	BN_init(&bnceil);
	BN_init(&bnfloor);
	BN_init(&bnbase);
	BN_init(&bntmp);
	BN_init(&bntmp2);

	BN_set_word(&bnbase, 58);

	p = strlen(pfx);

	for (i = 0; i < p; i++) {
		c = b58_reverse_map[(int)pfx[i]];
		if (c == -1) {
			printf("Invalid character '%c' in prefix '%s'\n",
			       pfx[i], pfx);
			goto out;
		}
		if (i == zero_prefix) {
			if (c == 0) {
				/* Add another zero prefix */
				zero_prefix++;
				if (zero_prefix > 19) {
					printf("Prefix '%s' is too long\n",
						pfx);
					goto out;
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

	bnlow = BN_new();
	bnhigh = BN_new();

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
			printf("Prefix '%s' is too long\n", pfx);
			goto out;
		}

		BN_set_word(&bntmp2, b58pow - (p - zero_prefix));
		BN_exp(&bntmp, &bnbase, &bntmp2, bnctx);
		BN_mul(bnlow, &bntmp, &bntarg, bnctx);
		BN_set_word(bnhigh, 1);
		BN_sub(&bntmp2, &bntmp, bnhigh);
		BN_add(bnhigh, bnlow, &bntmp2);

		if (b58top <= b58ceil) {
			/* Fill out the upper range too */
			check_upper = 1;
			bnlow2 = BN_new();
			bnhigh2 = BN_new();

			BN_mul(bnlow2, bnlow, &bnbase, bnctx);
			BN_mul(&bntmp2, bnhigh, &bnbase, bnctx);
			BN_set_word(&bntmp, 57);
			BN_add(bnhigh2, &bntmp2, &bntmp);

			/*
			 * Addresses above the ceiling will have one
			 * fewer "1" prefix in front than we require.
			 */
			if (BN_cmp(&bnceil, bnlow2) < 0) {
				/* High prefix is above the ceiling */
				check_upper = 0;
				BN_free(bnhigh2);
				bnhigh2 = NULL;
				BN_free(bnlow2);
				bnlow2 = NULL;
			}
			else if (BN_cmp(&bnceil, bnhigh2) < 0)
				/* High prefix is partly above the ceiling */
				BN_copy(bnhigh2, &bnceil);

			/*
			 * Addresses below the floor will have another
			 * "1" prefix in front instead of our target.
			 */
			if (BN_cmp(&bnfloor, bnhigh) >= 0) {
				/* Low prefix is completely below the floor */
				assert(check_upper);
				check_upper = 0;
				BN_free(bnhigh);
				bnhigh = bnhigh2;
				bnhigh2 = NULL;
				BN_free(bnlow);
				bnlow = bnlow2;
				bnlow2 = NULL;
			}			
			else if (BN_cmp(&bnfloor, bnlow) > 0) {
				/* Low prefix is partly below the floor */
				BN_copy(bnlow, &bnfloor);
			}
		}

	} else {
		BN_copy(bnhigh, &bnceil);
		BN_set_word(bnlow, 0);
	}

	/* Limit the prefix to the address type */
	BN_clear(&bntmp);
	BN_set_word(&bntmp, addrtype);
	BN_lshift(&bntmp2, &bntmp, 192);

	if (check_upper) {
		if (BN_cmp(&bntmp2, bnhigh2) > 0) {
			check_upper = 0;
			BN_free(bnhigh2);
			bnhigh2 = NULL;
			BN_free(bnlow2);
			bnlow2 = NULL;
		}
		else if (BN_cmp(&bntmp2, bnlow2) > 0)
			BN_copy(bnlow2, &bntmp2);
	}

	if (BN_cmp(&bntmp2, bnhigh) > 0) {
		if (!check_upper) {
			printf("Prefix '%s' not possible\n", pfx);
			goto out;
		}
		check_upper = 0;
		BN_free(bnhigh);
		bnhigh = bnhigh2;
		bnhigh2 = NULL;
		BN_free(bnlow);
		bnlow = bnlow2;
		bnlow2 = NULL;
	}
	else if (BN_cmp(&bntmp2, bnlow) > 0) {
		BN_copy(bnlow, &bntmp2);
	}

	BN_set_word(&bntmp, addrtype + 1);
	BN_lshift(&bntmp2, &bntmp, 192);

	if (check_upper) {
		if (BN_cmp(&bntmp2, bnlow2) < 0) {
			check_upper = 0;
			BN_free(bnhigh2);
			bnhigh2 = NULL;
			BN_free(bnlow2);
			bnlow2 = NULL;
		}
		else if (BN_cmp(&bntmp2, bnhigh2) < 0)
			BN_copy(bnlow2, &bntmp2);
	}

	if (BN_cmp(&bntmp2, bnlow) < 0) {
		if (!check_upper) {
			printf("Prefix '%s' not possible\n", pfx);
			goto out;
		}
		check_upper = 0;
		BN_free(bnhigh);
		bnhigh = bnhigh2;
		bnhigh2 = NULL;
		BN_free(bnlow);
		bnlow = bnlow2;
		bnlow2 = NULL;
	}
	else if (BN_cmp(&bntmp2, bnhigh) < 0) {
		BN_copy(bnhigh, &bntmp2);
	}

	/* Address ranges are complete */
	assert(check_upper || ((bnlow2 == NULL) && (bnhigh2 == NULL)));
	result[0] = bnlow;
	result[1] = bnhigh;
	result[2] = bnlow2;
	result[3] = bnhigh2;
	bnlow = NULL;
	bnhigh = NULL;
	bnlow2 = NULL;
	bnhigh2 = NULL;
	ret = 1;

out:
	BN_clear_free(&bntarg);
	BN_clear_free(&bnceil);
	BN_clear_free(&bnfloor);
	BN_clear_free(&bnbase);
	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	if (bnhigh)
		BN_free(bnhigh);
	if (bnlow)
		BN_free(bnlow);
	if (bnhigh2)
		BN_free(bnhigh2);
	if (bnlow2)
		BN_free(bnlow2);

	return ret;
}

/*
 * AVL tree implementation
 */

typedef enum { CENT = 1, LEFT = 0, RIGHT = 2 } avl_balance_t;

typedef struct _avl_item_s {
	struct _avl_item_s *ai_left, *ai_right, *ai_up;
	avl_balance_t ai_balance;
#ifndef NDEBUG
	int ai_indexed;
#endif
} avl_item_t;

typedef struct _avl_root_s {
	avl_item_t *ar_root;
} avl_root_t;

INLINE void
avl_root_init(avl_root_t *rootp)
{
	rootp->ar_root = NULL;
}

INLINE int
avl_root_empty(avl_root_t *rootp)
{
	return (rootp->ar_root == NULL) ? 1 : 0;
}

INLINE void
avl_item_init(avl_item_t *itemp)
{
	memset(itemp, 0, sizeof(*itemp));
	itemp->ai_balance = CENT;
}

#define container_of(ptr, type, member) \
	(((type*) (((unsigned char *)ptr) - \
		   (size_t)&(((type *)((unsigned char *)0))->member))))

#define avl_item_entry(ptr, type, member) \
	container_of(ptr, type, member)



INLINE void
_avl_rotate_ll(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *tmp;
	tmp = itemp->ai_left;
	itemp->ai_left = tmp->ai_right;
	if (itemp->ai_left)
		itemp->ai_left->ai_up = itemp;
	tmp->ai_right = itemp;

	if (itemp->ai_up) {
		if (itemp->ai_up->ai_left == itemp) {
			itemp->ai_up->ai_left = tmp;
		} else {
			assert(itemp->ai_up->ai_right == itemp);
			itemp->ai_up->ai_right = tmp;
		}
	} else {
		rootp->ar_root = tmp;
	}
	tmp->ai_up = itemp->ai_up;
	itemp->ai_up = tmp;
}

INLINE void
_avl_rotate_lr(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *rcp, *rlcp;
	rcp = itemp->ai_left;
	rlcp = rcp->ai_right;
	if (itemp->ai_up) {
		if (itemp == itemp->ai_up->ai_left) {
			itemp->ai_up->ai_left = rlcp;
		} else {
			assert(itemp == itemp->ai_up->ai_right);
			itemp->ai_up->ai_right = rlcp;
		}
	} else {
		rootp->ar_root = rlcp;
	}
	rlcp->ai_up = itemp->ai_up;
	rcp->ai_right = rlcp->ai_left;
	if (rcp->ai_right)
		rcp->ai_right->ai_up = rcp;
	itemp->ai_left = rlcp->ai_right;
	if (itemp->ai_left)
		itemp->ai_left->ai_up = itemp;
	rlcp->ai_left = rcp;
	rlcp->ai_right = itemp;
	rcp->ai_up = rlcp;
	itemp->ai_up = rlcp;
}

INLINE void
_avl_rotate_rr(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *tmp;
	tmp = itemp->ai_right;
	itemp->ai_right = tmp->ai_left;
	if (itemp->ai_right)
		itemp->ai_right->ai_up = itemp;
	tmp->ai_left = itemp;

	if (itemp->ai_up) {
		if (itemp->ai_up->ai_right == itemp) {
			itemp->ai_up->ai_right = tmp;
		} else {
			assert(itemp->ai_up->ai_left == itemp);
			itemp->ai_up->ai_left = tmp;
		}
	} else {
		rootp->ar_root = tmp;
	}
	tmp->ai_up = itemp->ai_up;
	itemp->ai_up = tmp;
}

INLINE void
_avl_rotate_rl(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *rcp, *rlcp;
	rcp = itemp->ai_right;
	rlcp = rcp->ai_left;
	if (itemp->ai_up) {
		if (itemp == itemp->ai_up->ai_right) {
			itemp->ai_up->ai_right = rlcp;
		} else {
			assert(itemp == itemp->ai_up->ai_left);
			itemp->ai_up->ai_left = rlcp;
		}
	} else {
		rootp->ar_root = rlcp;
	}
	rlcp->ai_up = itemp->ai_up;
	rcp->ai_left = rlcp->ai_right;
	if (rcp->ai_left)
		rcp->ai_left->ai_up = rcp;
	itemp->ai_right = rlcp->ai_left;
	if (itemp->ai_right)
		itemp->ai_right->ai_up = itemp;
	rlcp->ai_right = rcp;
	rlcp->ai_left = itemp;
	rcp->ai_up = rlcp;
	itemp->ai_up = rlcp;
}

void
avl_delete_fix(avl_root_t *rootp, avl_item_t *itemp, avl_item_t *parentp)
{
	avl_item_t *childp;

	if ((parentp->ai_left == NULL) &&
	    (parentp->ai_right == NULL)) {
		assert(itemp == NULL);
		parentp->ai_balance = CENT;
		itemp = parentp;
		parentp = itemp->ai_up;
	}

	while (parentp) {
		if (itemp == parentp->ai_right) {
			itemp = parentp->ai_left;
			if (parentp->ai_balance == LEFT) {
				/* Parent was left-heavy, now worse */
				if (itemp->ai_balance == LEFT) {
					/* If left child is also
					 * left-heavy, LL fixes it. */
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					parentp = itemp;
				} else if (itemp->ai_balance == CENT) {
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = RIGHT;
					parentp->ai_balance = LEFT;
					break;
				} else {
					childp = itemp->ai_right;
					_avl_rotate_lr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						itemp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						parentp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					parentp = childp;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = LEFT;
				break;
			} else {
				parentp->ai_balance = CENT;
			}

		} else {
			itemp = parentp->ai_right;
			if (parentp->ai_balance == RIGHT) {
				if (itemp->ai_balance == RIGHT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					parentp = itemp;
				} else if (itemp->ai_balance == CENT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = LEFT;
					parentp->ai_balance = RIGHT;
					break;
				} else {
					childp = itemp->ai_left;
					_avl_rotate_rl(rootp, parentp);

					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						parentp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						itemp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					parentp = childp;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = RIGHT;
				break;
			} else {
				parentp->ai_balance = CENT;
			}
		}

		itemp = parentp;
		parentp = itemp->ai_up;
	}
}

void
avl_insert_fix(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *childp, *parentp = itemp->ai_up;
	itemp->ai_left = itemp->ai_right = NULL;
#ifndef NDEBUG
	assert(!itemp->ai_indexed);
	itemp->ai_indexed = 1;
#endif
	while (parentp) {
		if (itemp == parentp->ai_left) {
			if (parentp->ai_balance == LEFT) {
				/* Parent was left-heavy, now worse */
				if (itemp->ai_balance == LEFT) {
					/* If left child is also
					 * left-heavy, LL fixes it. */
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					break;
				} else {
					assert(itemp->ai_balance != CENT);
					childp = itemp->ai_right;
					_avl_rotate_lr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						itemp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						parentp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					break;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = LEFT;
			} else {
				parentp->ai_balance = CENT;
				return;
			}
		} else {
			if (parentp->ai_balance == RIGHT) {
				if (itemp->ai_balance == RIGHT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					break;
				} else {
					assert(itemp->ai_balance != CENT);
					childp = itemp->ai_left;
					_avl_rotate_rl(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						parentp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						itemp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					break;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = RIGHT;
			} else {
				parentp->ai_balance = CENT;
				break;
			}
		}

		itemp = parentp;
		parentp = itemp->ai_up;
	}
}

INLINE avl_item_t *
avl_next(avl_item_t *itemp)
{
	if (itemp->ai_right) {
		itemp = itemp->ai_right;
		while (itemp->ai_left)
			itemp = itemp->ai_left;
		return itemp;
	}

	while (itemp->ai_up && (itemp == itemp->ai_up->ai_right))
		itemp = itemp->ai_up;

	if (!itemp->ai_up)
		return NULL;

	return itemp->ai_up;
}

void
avl_remove(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *relocp, *replacep, *parentp = NULL;
#ifndef NDEBUG
	assert(itemp->ai_indexed);
	itemp->ai_indexed = 0;
#endif
	/* If the item is directly replaceable, do it. */
	if ((itemp->ai_left == NULL) || (itemp->ai_right == NULL)) {
		parentp = itemp->ai_up;
		replacep = itemp->ai_left;
		if (replacep == NULL)
			replacep = itemp->ai_right;
		if (replacep != NULL)
			replacep->ai_up = parentp;
		if (parentp == NULL) {
			rootp->ar_root = replacep;
		} else {
			if (itemp == parentp->ai_left)
				parentp->ai_left = replacep;
			else
				parentp->ai_right = replacep;

			avl_delete_fix(rootp, replacep, parentp);
		}
		return;
	}

	/*
	 * Otherwise we do an indirect replacement with
	 * the item's leftmost right descendant.
	 */
	relocp = avl_next(itemp);
	assert(relocp);
	assert(relocp->ai_up != NULL);
	assert(relocp->ai_left == NULL);
	replacep = relocp->ai_right;
	relocp->ai_left = itemp->ai_left;
	if (relocp->ai_left != NULL)
		relocp->ai_left->ai_up = relocp;
	if (itemp->ai_up == NULL)
		rootp->ar_root = relocp;
	else {
		if (itemp == itemp->ai_up->ai_left)
			itemp->ai_up->ai_left = relocp;
		else
			itemp->ai_up->ai_right = relocp;
	}
	if (relocp == relocp->ai_up->ai_left) {
		assert(relocp->ai_up != itemp);
		relocp->ai_up->ai_left = replacep;
		parentp = relocp->ai_up;
		if (replacep != NULL)
			replacep->ai_up = relocp->ai_up;
		relocp->ai_right = itemp->ai_right;
	} else {
		assert(relocp->ai_up == itemp);
		relocp->ai_right = replacep;
		parentp = relocp;
	}
	if (relocp->ai_right != NULL)
		relocp->ai_right->ai_up = relocp;
	relocp->ai_up = itemp->ai_up;
	relocp->ai_balance = itemp->ai_balance;
	avl_delete_fix(rootp, replacep, parentp);
}



/*
 * Address prefix AVL tree node
 */

typedef struct _vg_prefix_s {
	avl_item_t		vp_item;
	struct _vg_prefix_s	*vp_sibling;
	const char		*vp_pattern;
	BIGNUM			*vp_low;
	BIGNUM			*vp_high;
} vg_prefix_t;

void
vg_prefix_free(vg_prefix_t *vp)
{
	if (vp->vp_low)
		BN_free(vp->vp_low);
	if (vp->vp_high)
		BN_free(vp->vp_high);
	free(vp);
}

vg_prefix_t *
vg_prefix_avl_search(avl_root_t *rootp, BIGNUM *targ)
{
	vg_prefix_t *vp;
	avl_item_t *itemp = rootp->ar_root;

	while (itemp) {
		vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
		if (BN_cmp(vp->vp_low, targ) > 0) {
			itemp = itemp->ai_left;
		} else {
			if (BN_cmp(vp->vp_high, targ) < 0) {
				itemp = itemp->ai_right;
			} else
				return vp;
		}
	}
	return NULL;
}

vg_prefix_t *
vg_prefix_avl_insert(avl_root_t *rootp, vg_prefix_t *vpnew)
{
	vg_prefix_t *vp;
	avl_item_t *itemp = NULL;
	avl_item_t **ptrp = &rootp->ar_root;
	while (*ptrp) {
		itemp = *ptrp;
		vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
		if (BN_cmp(vp->vp_low, vpnew->vp_high) > 0) {
			ptrp = &itemp->ai_left;
		} else {
			if (BN_cmp(vp->vp_high, vpnew->vp_low) < 0) {
				ptrp = &itemp->ai_right;
			} else
				return vp;
		}
	}
	vpnew->vp_item.ai_up = itemp;
	itemp = &vpnew->vp_item;
	*ptrp = itemp;
	avl_insert_fix(rootp, itemp);
	return NULL;
}

vg_prefix_t *
vg_prefix_add(avl_root_t *rootp, const char *pattern, BIGNUM *low, BIGNUM *high)
{
	vg_prefix_t *vp, *vp2;
	assert(BN_cmp(low, high) < 0);
	vp = (vg_prefix_t *) malloc(sizeof(*vp));
	if (vp) {
		avl_item_init(&vp->vp_item);
		vp->vp_sibling = NULL;
		vp->vp_pattern = pattern;
		vp->vp_low = low;
		vp->vp_high = high;
		vp2 = vg_prefix_avl_insert(rootp, vp);
		if (vp2 != NULL) {
			printf("Prefix '%s' ignored, overlaps '%s'\n",
			       pattern, vp2->vp_pattern);
			vg_prefix_free(vp);
			vp = NULL;
		}
	}
	return vp;
}

void
vg_prefix_delete(avl_root_t *rootp, vg_prefix_t *vp)
{
	vg_prefix_t *sibp, *delp;

	avl_remove(rootp, &vp->vp_item);
	sibp = vp->vp_sibling;
	while (sibp && sibp != vp) {
		avl_remove(rootp, &sibp->vp_item);
		delp = sibp;
		sibp = sibp->vp_sibling;
		vg_prefix_free(delp);
	}
	vg_prefix_free(vp);
}

vg_prefix_t *
vg_prefix_add_ranges(avl_root_t *rootp, const char *pattern, BIGNUM **ranges,
		     vg_prefix_t *master)
{
	vg_prefix_t *vp, *vp2 = NULL;

	assert(ranges[0]);
	vp = vg_prefix_add(rootp, pattern, ranges[0], ranges[1]);
	if (!vp)
		return NULL;

	if (ranges[2]) {
		vp2 = vg_prefix_add(rootp, pattern, ranges[2], ranges[3]);
		if (!vp2) {
			vg_prefix_delete(rootp, vp);
			return NULL;
		}
	}

	if (!master) {
		vp->vp_sibling = vp2;
		if (vp2)
			vp2->vp_sibling = vp;
	} else if (vp2) {
		vp->vp_sibling = vp2;
		vp2->vp_sibling = (master->vp_sibling ? 
				   master->vp_sibling :
				   master);
		master->vp_sibling = vp;
	} else {
		vp->vp_sibling = (master->vp_sibling ? 
				  master->vp_sibling :
				  master);
		master->vp_sibling = vp;
	}
	return vp;
}

void
vg_prefix_range_sum(vg_prefix_t *vp, BIGNUM *result, BIGNUM *tmp1, BIGNUM *tmp2)
{
	vg_prefix_t *startp;

	BIGNUM *bnptr = result;

	startp = vp;
	BN_clear(result);
	do {
		BN_sub(tmp1, vp->vp_high, vp->vp_low);
		if (bnptr == result) {
			BN_add(tmp2, bnptr, tmp1);
			bnptr = tmp2;
		} else {
			BN_add(result, bnptr, tmp1);
			bnptr = result;
		}
		vp = vp->vp_sibling;
	} while (vp && (vp != startp));

	if (bnptr != result)
		BN_copy(result, bnptr);
}


typedef struct _prefix_case_iter_s {
	char	ci_prefix[32];
	char	ci_case_map[32];
	char	ci_nbits;
	int	ci_value;
} prefix_case_iter_t;

const unsigned char b58_case_map[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
};

int
prefix_case_iter_init(prefix_case_iter_t *cip, const char *pfx)
{
	int i;

	cip->ci_nbits = 0;
	cip->ci_value = 0;
	for (i = 0; pfx[i]; i++) {
		if (i > sizeof(cip->ci_prefix))
			return 0;
		if (!b58_case_map[(int)pfx[i]]) {
			cip->ci_prefix[i] = pfx[i];
			continue;
		}
		cip->ci_prefix[i] = pfx[i] | 0x20;
		cip->ci_case_map[(int)cip->ci_nbits] = i;
		cip->ci_nbits++;
	}
	cip->ci_prefix[i] = '\0';
	return 1;
}

int
prefix_case_iter_next(prefix_case_iter_t *cip)
{
	unsigned long val, max, mask;
	int i, nbits;

	nbits = cip->ci_nbits;
	max = (1UL << nbits) - 1;
	val = cip->ci_value + 1;
	if (val >= max)
		return 0;

	for (i = 0, mask = 1; i < nbits; i++, mask <<= 1) {
		if (val & mask)
			cip->ci_prefix[(int)cip->ci_case_map[i]] &= 0xdf;
		else
			cip->ci_prefix[(int)cip->ci_case_map[i]] |= 0x20;
	}
	cip->ci_value = val;
	return 1;
}


typedef struct _vg_prefix_context_s {
	vg_context_t		base;
	avl_root_t		vcp_avlroot;
	BIGNUM			vcp_difficulty;
	pthread_mutex_t		vcp_lock;
} vg_prefix_context_t;

void
vg_prefix_context_free(vg_prefix_context_t *vcpp)
{
	vg_prefix_t *vp;
	unsigned long npfx_left = 0;

	while (!avl_root_empty(&vcpp->vcp_avlroot)) {
		vp = avl_item_entry(vcpp->vcp_avlroot.ar_root,
				    vg_prefix_t, vp_item);
		vg_prefix_delete(&vcpp->vcp_avlroot, vp);
		npfx_left++;
	}

	assert(npfx_left == vcpp->base.vc_npatterns);
	BN_clear_free(&vcpp->vcp_difficulty);
	pthread_mutex_destroy(&vcpp->vcp_lock);
	free(vcpp);
}

void
vg_prefix_context_next_difficulty(vg_prefix_context_t *vcpp,
				  BIGNUM *bntmp, BIGNUM *bntmp2, BN_CTX *bnctx)
{
	char *dbuf;

	BN_clear(bntmp);
	BN_set_bit(bntmp, 192);
	BN_div(bntmp2, NULL, bntmp, &vcpp->vcp_difficulty, bnctx);

	dbuf = BN_bn2dec(bntmp2);
	if (verbose > 0) {
		if (vcpp->base.vc_npatterns > 1)
			printf("Next match difficulty: %s (%ld prefixes)\n",
			       dbuf, vcpp->base.vc_npatterns);
		else
			printf("Difficulty: %s\n", dbuf);
	}
	vcpp->base.vc_chance = atof(dbuf);
	OPENSSL_free(dbuf);
}

int
vg_prefix_context_add_patterns(vg_prefix_context_t *vcpp,
			       char ** const patterns, int npatterns,
			       int caseinsensitive)
{
	prefix_case_iter_t caseiter;
	vg_prefix_t *vp, *vp2;
	BN_CTX *bnctx;
	BIGNUM bntmp, bntmp2, bntmp3;
	BIGNUM *ranges[4];
	int ret = 0;
	int i, fail;
	unsigned long npfx;
	char *dbuf;

	bnctx = BN_CTX_new();
	BN_init(&bntmp);
	BN_init(&bntmp2);
	BN_init(&bntmp3);

	npfx = 0;
	fail = 0;
	for (i = 0; i < npatterns; i++) {
		if (!caseinsensitive) {
			vp = NULL;
			if (get_prefix_ranges(vcpp->base.vc_addrtype,
					      patterns[i],
					      ranges, bnctx)) {
				vp = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
							  patterns[i],
							  ranges, NULL);
			}

		} else {
			/* Case-enumerate the prefix */
			if (!prefix_case_iter_init(&caseiter, patterns[i])) {
				printf("Prefix '%s' is too long\n",
				       patterns[i]);
				continue;
			}

			if (caseiter.ci_nbits > 16) {
				printf("WARNING: Prefix '%s' has "
				       "2^%d case-varied derivitives\n",
				       patterns[i], caseiter.ci_nbits);
			}

			vp = NULL;
			fail = 0;
			do {
				if (!get_prefix_ranges(vcpp->base.vc_addrtype,
						       caseiter.ci_prefix,
						       ranges, bnctx)) {
					fail = 1;
					break;
				}
				vp2 = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
							   patterns[i],
							   ranges,
							   vp);
				if (!vp2) {
					fail = 1;
					break;
				}
				if (!vp)
					vp = vp2;

			} while (prefix_case_iter_next(&caseiter));

			if (fail && vp) {
				vg_prefix_delete(&vcpp->vcp_avlroot, vp);
				vp = NULL;
			}
		}

		if (!vp)
			continue;

		npfx++;

		/* Determine the probability of finding a match */
		vg_prefix_range_sum(vp, &bntmp, &bntmp2, &bntmp3);
		BN_add(&bntmp2, &vcpp->vcp_difficulty, &bntmp);
		BN_copy(&vcpp->vcp_difficulty, &bntmp2);

		if (verbose > 1) {
			BN_clear(&bntmp2);
			BN_set_bit(&bntmp2, 192);
			BN_div(&bntmp3, NULL, &bntmp2, &bntmp, bnctx);

			dbuf = BN_bn2dec(&bntmp3);
			printf("Prefix difficulty: %20s %s\n",
			       dbuf, patterns[i]);
			OPENSSL_free(dbuf);
		}
	}

	vcpp->base.vc_npatterns += npfx;
	vcpp->base.vc_npatterns_start += npfx;

	if (avl_root_empty(&vcpp->vcp_avlroot)) {
		printf("No prefix patterns to search\n");
		vg_prefix_context_free(vcpp);
		vcpp = NULL;
		goto out;
	}

	assert(npfx);
	ret = 1;

	vg_prefix_context_next_difficulty(vcpp, &bntmp, &bntmp2, bnctx);

out:
	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	BN_clear_free(&bntmp3);
	BN_CTX_free(bnctx);
	return ret;
}


int
vg_prefix_test(vg_context_t *vcp, vg_thread_context_t *vctp)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t *vp;
	int res = 0;

	/*
	 * We constrain the prefix so that we can check for
	 * a match without generating the lower four byte
	 * check code.
	 */

	BN_bin2bn(vctp->vct_binres, sizeof(vctp->vct_binres),
		  &vctp->vct_bntarg);

	pthread_mutex_lock(&vcpp->vcp_lock);
	vp = vg_prefix_avl_search(&vcpp->vcp_avlroot, &vctp->vct_bntarg);
	if (vp) {
		BN_clear(&vctp->vct_bntmp);
		BN_set_word(&vctp->vct_bntmp, vctp->vct_delta);
		BN_add(&vctp->vct_bntmp2,
		       EC_KEY_get0_private_key(vctp->vct_key),
		       &vctp->vct_bntmp);
		EC_KEY_set_private_key(vctp->vct_key,
				       &vctp->vct_bntmp2);
		EC_KEY_set_public_key(vctp->vct_key,
				      vctp->vct_point);
				
		output_match(vctp->vct_key, vp->vp_pattern, &vcpp->base);

		vcpp->base.vc_found++;

		if (remove_on_match) {
			/* Subtract the range from the difficulty */
			vg_prefix_range_sum(vp,
					    &vctp->vct_bntarg,
					    &vctp->vct_bntmp,
					    &vctp->vct_bntmp2);
			BN_sub(&vctp->vct_bntmp,
			       &vcpp->vcp_difficulty,
			       &vctp->vct_bntarg);
			BN_copy(&vcpp->vcp_difficulty, &vctp->vct_bntmp);

			vg_prefix_delete(&vcpp->vcp_avlroot,vp);
			vcpp->base.vc_npatterns--;

			if (!avl_root_empty(&vcpp->vcp_avlroot))
				vg_prefix_context_next_difficulty(
					vcpp, &vctp->vct_bntmp,
					&vctp->vct_bntmp2,
					vctp->vct_bnctx);
		}
		res = 1;
	}
	if (avl_root_empty(&vcpp->vcp_avlroot)) {
		pthread_mutex_unlock(&vcpp->vcp_lock);
		return 2;
	}
	pthread_mutex_unlock(&vcpp->vcp_lock);
	return res;
}

vg_prefix_context_t *
vg_prefix_context_new(int addrtype, int privtype)
{
	vg_prefix_context_t *vcpp;

	vcpp = (vg_prefix_context_t *) malloc(sizeof(*vcpp));
	if (vcpp) {
		vcpp->base.vc_addrtype = addrtype;
		vcpp->base.vc_privtype = privtype;
		vcpp->base.vc_npatterns = 0;
		vcpp->base.vc_npatterns_start = 0;
		vcpp->base.vc_found = 0;
		vcpp->base.vc_chance = 0.0;
		vcpp->base.vc_test = vg_prefix_test;
		avl_root_init(&vcpp->vcp_avlroot);
		BN_init(&vcpp->vcp_difficulty);
		pthread_mutex_init(&vcpp->vcp_lock, NULL);
	}
	return vcpp;
}




typedef struct _vg_regex_context_s {
	vg_context_t		base;
	pcre 			**vcr_regex;
	pcre_extra		**vcr_regex_extra;
	const char		**vcr_regex_pat;
	unsigned long		vcr_nalloc;
	pthread_rwlock_t	vcr_lock;
} vg_regex_context_t;

int
vg_regex_context_add_patterns(vg_regex_context_t *vcrp,
			      char ** const patterns, int npatterns)
{
	const char *pcre_errptr;
	int pcre_erroffset;
	unsigned long i, nres, count;
	void **mem;

	if (!npatterns)
		return 1;

	if (npatterns > (vcrp->vcr_nalloc - vcrp->base.vc_npatterns)) {
		count = npatterns + vcrp->base.vc_npatterns;
		if (count < (2 * vcrp->vcr_nalloc)) {
			count = (2 * vcrp->vcr_nalloc);
		}
		if (count < 16) {
			count = 16;
		}
		mem = (void **) malloc(3 * count * sizeof(void*));
		if (!mem)
			return 0;

		for (i = 0; i < vcrp->base.vc_npatterns; i++) {
			mem[i] = vcrp->vcr_regex[i];
			mem[count + i] = vcrp->vcr_regex_extra[i];
			mem[(2 * count) + i] = (void *) vcrp->vcr_regex_pat[i];
		}

		if (vcrp->vcr_nalloc)
			free(vcrp->vcr_regex);
		vcrp->vcr_regex = (pcre **) mem;
		vcrp->vcr_regex_extra = (pcre_extra **) &mem[count];
		vcrp->vcr_regex_pat = (const char **) &mem[2 * count];
		vcrp->vcr_nalloc = count;
	}

	nres = vcrp->base.vc_npatterns;
	for (i = 0; i < npatterns; i++) {
		vcrp->vcr_regex[nres] =
			pcre_compile(patterns[i], 0,
				     &pcre_errptr, &pcre_erroffset, NULL);
		if (!vcrp->vcr_regex[nres]) {
			const char *spaces = "                ";
			printf("%s\n", patterns[i]);
			while (pcre_erroffset > 16) {
				printf("%s", spaces);
				pcre_erroffset -= 16;
			}
			if (pcre_erroffset > 0)
				printf("%s", &spaces[16 - pcre_erroffset]);
			printf("^\nRegex error: %s\n", pcre_errptr);
			continue;
		}
		vcrp->vcr_regex_extra[nres] =
			pcre_study(vcrp->vcr_regex[nres], 0, &pcre_errptr);
		if (pcre_errptr) {
			printf("Regex error: %s\n", pcre_errptr);
			pcre_free(vcrp->vcr_regex[nres]);
			continue;
		}
		vcrp->vcr_regex_pat[nres] = patterns[i];
		nres += 1;
	}

	if (nres == vcrp->base.vc_npatterns)
		return 0;

	vcrp->base.vc_npatterns_start += (nres - vcrp->base.vc_npatterns);
	vcrp->base.vc_npatterns = nres;
	return 1;
}

void
vg_regex_context_free(vg_regex_context_t *vcrp)
{
	int i;
	for (i = 0; i < vcrp->base.vc_npatterns; i++) {
		if (vcrp->vcr_regex_extra[i])
			pcre_free(vcrp->vcr_regex_extra[i]);
		pcre_free(vcrp->vcr_regex[i]);
	}
	if (vcrp->vcr_nalloc)
		free(vcrp->vcr_regex);
	pthread_rwlock_destroy(&vcrp->vcr_lock);
	free(vcrp);
}

int
vg_regex_test(vg_context_t *vcp, vg_thread_context_t *vctp)
{
	vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;

	unsigned char hash1[32], hash2[32];
	int i, zpfx, p, d, nres, re_vec[9];
	char b58[40];
	BIGNUM bnrem;
	BIGNUM *bn, *bndiv, *bnptmp;
	int res = 0;

	pcre *re;

	BN_init(&bnrem);

	/* Hash the hash and write the four byte check code */
	SHA256(vctp->vct_binres, 21, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&vctp->vct_binres[21], hash2, 4);

	bn = &vctp->vct_bntmp;
	bndiv = &vctp->vct_bntmp2;

	BN_bin2bn(vctp->vct_binres, sizeof(vctp->vct_binres), bn);

	/* Compute the complete encoded address */
	for (zpfx = 0; zpfx < 25 && vctp->vct_binres[zpfx] == 0; zpfx++);
	p = sizeof(b58) - 1;
	b58[p] = '\0';
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, &bnrem, bn, &vctp->vct_bnbase, vctp->vct_bnctx);
		bnptmp = bn;
		bn = bndiv;
		bndiv = bnptmp;
		d = BN_get_word(&bnrem);
		b58[--p] = b58_alphabet[d];
	}
	while (zpfx--) {
		b58[--p] = b58_alphabet[0];
	}

	/*
	 * Run the regular expressions on it
	 * SLOW, runs in linear time with the number of REs
	 */
	pthread_rwlock_rdlock(&vcrp->vcr_lock);
	nres = vcrp->base.vc_npatterns;
	if (!nres) {
		res = 2;
		goto out;
	}
	for (i = 0; i < nres; i++) {
		d = pcre_exec(vcrp->vcr_regex[i],
			      vcrp->vcr_regex_extra[i],
			      &b58[p], (sizeof(b58) - 1) - p, 0,
			      0,
			      re_vec, sizeof(re_vec)/sizeof(re_vec[0]));

		if (d <= 0) {
			if (d != PCRE_ERROR_NOMATCH) {
				printf("PCRE error: %d\n", d);
				res = 2;
				goto out;
			}
			continue;
		}

		re = vcrp->vcr_regex[i];
		pthread_rwlock_unlock(&vcrp->vcr_lock);
		pthread_rwlock_wrlock(&vcrp->vcr_lock);
		nres = vcrp->base.vc_npatterns;
		if ((i >= nres) || (vcrp->vcr_regex[i] != re)) {
			/* Redo the search */
			i = -1;
			pthread_rwlock_unlock(&vcrp->vcr_lock);
			pthread_rwlock_rdlock(&vcrp->vcr_lock);
			nres = vcrp->base.vc_npatterns;
			if (!nres) {
				res = 2;
				goto out;
			}
			continue;
		}

		BN_clear(&vctp->vct_bntmp);
		BN_set_word(&vctp->vct_bntmp, vctp->vct_delta);
		BN_add(&vctp->vct_bntmp2,
		       EC_KEY_get0_private_key(vctp->vct_key),
		       &vctp->vct_bntmp);
		EC_KEY_set_private_key(vctp->vct_key,
				       &vctp->vct_bntmp2);
		EC_KEY_set_public_key(vctp->vct_key,
				      vctp->vct_point);
				
		output_match(vctp->vct_key,
			     vcrp->vcr_regex_pat[i],
			     &vcrp->base);
		vcrp->base.vc_found++;

		if (remove_on_match) {
			pcre_free(vcrp->vcr_regex[i]);
			if (vcrp->vcr_regex_extra[i])
				pcre_free(vcrp->vcr_regex_extra[i]);
			nres -= 1;
			vcrp->base.vc_npatterns = nres;
			if (!nres) {
				res = 2;
				goto out;
			}
			vcrp->vcr_regex[i] = vcrp->vcr_regex[nres];
			vcrp->vcr_regex_extra[i] =
				vcrp->vcr_regex_extra[nres];
			vcrp->vcr_regex_pat[i] = vcrp->vcr_regex_pat[nres];
			vcrp->base.vc_npatterns = nres;
		}
		res = 1;
	}
out:
	pthread_rwlock_unlock(&vcrp->vcr_lock);
	BN_clear_free(&bnrem);
	return res;
}


vg_regex_context_t *
vg_regex_context_new(int addrtype, int privtype)
{
	vg_regex_context_t *vcrp;

	vcrp = (vg_regex_context_t *) malloc(sizeof(*vcrp));
	if (vcrp) {
		vcrp->base.vc_addrtype = addrtype;
		vcrp->base.vc_privtype = privtype;
		vcrp->base.vc_npatterns = 0;
		vcrp->base.vc_npatterns_start = 0;
		vcrp->base.vc_found = 0;
		vcrp->base.vc_chance = 0.0;
		vcrp->base.vc_test = vg_regex_test;
		vcrp->vcr_regex = NULL;
		vcrp->vcr_nalloc = 0;
		pthread_rwlock_init(&vcrp->vcr_lock, NULL);
	}
	return vcrp;
}


int
read_file(FILE *fp, char ***result, int *rescount)
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

#if !defined(_WIN32)
int
count_processors(void)
{
	FILE *fp;
	char buf[512];
	int count = 0;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "processor\t", 10))
			count += 1;
	}
	fclose(fp);
	return count;
}
#endif

int
start_threads(void *(*func)(void *), void *arg, int nthreads)
{
	pthread_t thread;

	if (nthreads <= 0) {
		/* Determine the number of threads */
		nthreads = count_processors();
		if (nthreads <= 0) {
			printf("ERROR: could not determine processor count\n");
			nthreads = 1;
		}
	}

	if (verbose > 1) {
		printf("Using %d worker thread(s)\n", nthreads);
	}

	while (--nthreads) {
		if (pthread_create(&thread, NULL, func, arg))
			return 0;
	}

	func(arg);
	return 1;
}


void
usage(const char *name)
{
	printf(
"Vanitygen %s\n"
"Usage: %s [-vqrikNT] [-t <threads>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-i            Case-insensitive prefix search\n"
"-k            Keep pattern and continue search after finding a match\n"
"-N            Generate namecoin address\n"
"-T            Generate bitcoin testnet address\n"
"-t <threads>  Set number of worker threads (Default: number of CPUs)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n",
version, name);
}

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int privtype = 128;
	int regex = 0;
	int caseinsensitive = 0;
	int opt;
	FILE *fp = NULL;
	char **patterns;
	int npatterns = 0;
	int nthreads = 0;
	void *thread_arg = NULL;

	while ((opt = getopt(argc, argv, "vqrikNTt:h?f:o:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'r':
			regex = 1;
			break;
		case 'i':
			caseinsensitive = 1;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case 'N':
			addrtype = 52;
			break;
		case 'T':
			addrtype = 111;
			privtype = 239;
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				printf("Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'f':
			if (fp) {
				printf("Multiple files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				fp = stdin;
			} else {
				fp = fopen(optarg, "r+");
				if (!fp) {
					printf("Could not open %s: %s\n",
					       optarg, strerror(errno));
					return 1;
				}
			}
			break;
		case 'o':
			if (result_file) {
				printf("Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (caseinsensitive && regex)
		printf("WARNING: case insensitive mode incompatible with "
		       "regular expressions\n");

	if (fp) {
		if (!read_file(fp, &patterns, &npatterns)) {
			printf("Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin)
			fclose(fp);

	} else {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;
	}
		
	if (regex) {
		vg_regex_context_t *vcrp;
		vcrp = vg_regex_context_new(addrtype, privtype);
		if (!vg_regex_context_add_patterns(vcrp, patterns, npatterns))
			return 1;
		if ((verbose > 0) && (vcrp->base.vc_npatterns > 1))
			printf("Regular expressions: %ld\n",
			       vcrp->base.vc_npatterns);
		thread_arg = vcrp;

	} else {
		vg_prefix_context_t *vcpp;
		vcpp = vg_prefix_context_new(addrtype, privtype);
		if (!vg_prefix_context_add_patterns(vcpp, patterns, npatterns,
						    caseinsensitive))
			return 1;
		thread_arg = vcpp;
	}

	if (!start_threads((void *(*)(void*))vg_thread_loop,
			   thread_arg, nthreads))
		return 1;
	return 0;
}
