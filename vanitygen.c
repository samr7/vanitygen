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

const char *version = "0.4";
const int debug = 0;
int verbose = 0;

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
output_timing(int cycle, int *total, struct timeval *last, double chance)
{
	struct timeval tvnow, tv;
	long long rate;
	double count, prob, time, targ;
	char linebuf[80];
	char *unit;
	int rem, p, i;

	const double targs[] = { 0.5, 0.75, 0.8, 0.9, 0.95, 1.0 };

	/* Compute the rate */
	gettimeofday(&tvnow, NULL);
	timersub(&tvnow, last, &tv);
	memcpy(last, &tvnow, sizeof(*last));
	rate = tv.tv_usec + (1000000 * tv.tv_sec);
	rate = (1000000ULL * cycle) / rate;
	*total += cycle;

	rem = sizeof(linebuf);
	p = snprintf(linebuf, rem, "[%lld K/s][total %d]", rate, *total);
	assert(p > 0);
	rem -= p;
	if (rem < 0)
		rem = 0;

	if (chance >= 1.0) {
		count = *total;
		prob = 1.0f - exp(-count/chance);

		p = snprintf(&linebuf[p], rem, "[Prob %.1f%%]", prob * 100);
		assert(p > 0);
		rem -= p;
		if (rem < 0)
			rem = 0;
		p = sizeof(linebuf) - rem;

		for (i = 0; i < sizeof(targs)/sizeof(targs[0]); i++) {
			targ = targs[i];
			if ((targ < 1.0) && (prob <= targ))
				break;
		}

		if (targ < 1.0) {
			time = ((-chance * log(1.0 - targ)) - count) / rate;
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
		}
	}

	if (rem) {
		memset(&linebuf[sizeof(linebuf)-rem], 0x20, rem);
		linebuf[sizeof(linebuf)-1] = '\0';
	}
	printf("\r%s", linebuf);
	fflush(stdout);
}

void
output_match(EC_KEY *pkey, const char *pattern, int addrtype, int privtype)
{
	char print_buf[512];

	unsigned char key_buf[512], *pend;
	int len;

	assert(EC_KEY_check_key(pkey));

	printf("Pattern: %s\n", pattern);

	if (verbose) {
		/* Hexadecimal OpenSSL notation */
		pend = key_buf;
		len = i2o_ECPublicKey(pkey, &pend);
		printf("Pubkey (hex)  : ");
		dumphex(key_buf, len);
		pend = key_buf;
		len = i2d_ECPrivateKey(pkey, &pend);
		printf("Privkey (hex) : ");
		dumphex(key_buf, len);
	}

	/* Base-58 bitcoin notation public key hash */
	encode_address(pkey, addrtype, print_buf);
	printf("Address: %s\n", print_buf);

	/* Base-58 bitcoin notation private key */
	encode_privkey(pkey, privtype, print_buf);
	printf("Privkey: %s\n", print_buf);
}

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
		for (c = 0; c < 58; c++) {
			if (pfx[i] == b58_alphabet[c])
				break;
		}
		if (c >= 58) {
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
	vg_prefix_t *vp;
	vp = (vg_prefix_t *) malloc(sizeof(*vp));
	if (vp) {
		avl_item_init(&vp->vp_item);
		vp->vp_sibling = NULL;
		vp->vp_pattern = pattern;
		vp->vp_low = low;
		vp->vp_high = high;
		if (vg_prefix_avl_insert(rootp, vp) != NULL) {
			vg_prefix_free(vp);
			vp = NULL;
		}
	}
	return vp;
}

void
vg_prefix_delete(avl_root_t *rootp, vg_prefix_t *vp)
{
	avl_remove(rootp, &vp->vp_item);
	if (vp->vp_sibling) {
		avl_remove(rootp, &vp->vp_sibling->vp_item);
		vg_prefix_free(vp->vp_sibling);
	}
	vg_prefix_free(vp);
}


/*
 * Search for a key for which the encoded address has a specific prefix.
 * Uses bignum arithmetic to predetermine value ranges.
 * Faster than regular expression searching.
 */
void
generate_address_prefix(int addrtype, int privtype,
			char ** const patterns, int npatterns)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32];
	unsigned char binres[25] = {0,};
	char *dbuf, *mostdifficult = NULL;

	int i, c, t, nranges, npfx;

	BN_ULONG npoints, rekey_at;

	BN_CTX *bnctx;
	BIGNUM bntarg;
	BIGNUM bnbase;
	BIGNUM bndifficulty;
	BIGNUM bnmostdifficult;
	BIGNUM *ranges[4];
	BIGNUM bntmp, bntmp2;

	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT *ppnt = NULL;

	struct timeval tvstart;

	avl_root_t avlroot;
	vg_prefix_t *vp, *vp2;

	double chance;

	avl_root_init(&avlroot);

	bnctx = BN_CTX_new();

	BN_init(&bntarg);
	BN_init(&bnbase);
	BN_init(&bndifficulty);
	BN_init(&bnmostdifficult);
	BN_init(&bntmp);
	BN_init(&bntmp2);

	BN_set_word(&bnbase, 58);

	/*
	 * Step 1: compute the integer boundaries for accepted addresses
	 */

	nranges = 0;
	npfx = 0;
	for (c = 0; c < npatterns; c++) {
		if (!get_prefix_ranges(addrtype, patterns[c], ranges, bnctx))
			continue;

		if (debug) {
			if (ranges[2]) {
				printf("Upper Min: ");
				dumpbn(ranges[2]);
				printf("Upper Max: ");
				dumpbn(ranges[3]);
			}
			printf("Min: ");
			dumpbn(ranges[0]);
			printf("Max: ");
			dumpbn(ranges[1]);
		}

		vp = vg_prefix_add(&avlroot, patterns[c],
				   ranges[0], ranges[1]);
		if (vp && ranges[2]) {
			vp2 = vg_prefix_add(&avlroot, patterns[c],
					    ranges[2], ranges[3]);
			if (vp2) {
				nranges++;
				vp->vp_sibling = vp2;
				vp2->vp_sibling = vp;
			}
		}

		if (!vp) {
			printf("Could not add prefix '%s': overlapping?\n",
			       patterns[c]);
			continue;
		}
		nranges++;
		npfx++;

		/* Determine the probability of finding a match */
		BN_sub(&bntarg, ranges[1], ranges[0]);
		if (ranges[2]) {
			BN_sub(&bntmp, ranges[3], ranges[2]);
			BN_add(&bntmp2, &bntarg, &bntmp);
			BN_copy(&bntarg, &bntmp2);
		}

		if (BN_is_zero(&bnmostdifficult) ||
		    (BN_cmp(&bnmostdifficult, &bntarg) > 0)) {
			BN_copy(&bnmostdifficult, &bntarg);
			mostdifficult = patterns[c];
		}

		BN_add(&bntmp, &bndifficulty, &bntarg);
		BN_copy(&bndifficulty, &bntmp);

		if (verbose) {
			BN_set_word(&bntmp, 0);
			BN_set_bit(&bntmp, 192);
			BN_div(&bntmp2, NULL, &bntmp, &bntarg, bnctx);

			dbuf = BN_bn2dec(&bntmp2);
			printf("Prefix difficulty: %20s %s\n",
			       dbuf, patterns[c]);
			OPENSSL_free(dbuf);
		}
	}

	if (!nranges) {
		printf("No prefixes to search\n");
		goto out;
	}

	BN_set_word(&bntmp, 0);
	BN_set_bit(&bntmp, 192);
	BN_div(&bntmp2, NULL, &bntmp, &bndifficulty, bnctx);

	dbuf = BN_bn2dec(&bntmp2);
	if (npfx > 1)
		printf("Next match difficulty: %s (%d prefixes)\n", dbuf, npfx);
	else
		printf("Difficulty: %s\n", dbuf);
	chance = atof(dbuf);
	OPENSSL_free(dbuf);

	if (avl_root_empty(&avlroot)) {
		printf("No prefix patterns to search\n");
		return;
	}

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

		vp = vg_prefix_avl_search(&avlroot, &bntarg);

		if (vp) {
			printf("\n");

			if (npoints) {
				BN_clear(&bntmp);
				BN_set_word(&bntmp, npoints);
				BN_add(&bntmp2,
				       EC_KEY_get0_private_key(pkey),
				       &bntmp);
				EC_KEY_set_private_key(pkey, &bntmp2);
				EC_KEY_set_public_key(pkey, ppnt);

				/* Rekey immediately */
				rekey_at = 0;
				npoints = 0;
			}

			output_match(pkey, vp->vp_pattern, addrtype, privtype);

			/* Subtract the range from the aggregate difficulty */
			BN_sub(&bntmp, vp->vp_high, vp->vp_low);
			BN_sub(&bntmp2, &bndifficulty, &bntmp);
			BN_copy(&bndifficulty, &bntmp2);
			if (vp->vp_sibling) {
				BN_sub(&bntmp,
				       vp->vp_sibling->vp_high,
				       vp->vp_sibling->vp_low);
				BN_sub(&bntmp2, &bndifficulty, &bntmp);
				BN_copy(&bndifficulty, &bntmp2);
			}

			vg_prefix_delete(&avlroot, vp);
			npfx--;
			if (avl_root_empty(&avlroot))
				break;

			BN_set_word(&bntmp, 0);
			BN_set_bit(&bntmp, 192);
			BN_div(&bntmp2, NULL, &bntmp, &bndifficulty, bnctx);

			dbuf = BN_bn2dec(&bntmp2);
			printf("Next match difficulty: %s (%d prefixes)\n",
			       dbuf, npfx);
			chance = atof(dbuf);
			OPENSSL_free(dbuf);
		}

		if (++c >= 20000) {			
			output_timing(c, &t, &tvstart, chance);
			c = 0;
		}
	}

out:
	BN_clear_free(&bntarg);
	BN_clear_free(&bnbase);
	BN_clear_free(&bndifficulty);
	BN_clear_free(&bnmostdifficult);
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
generate_address_regex(int addrtype, int privtype,
		       char ** const patterns, int npatterns)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32], hash2[32];
	unsigned char binres[25] = {0,};
	char b58[40];

	int i, t, c, zpfx, p, d, nres, re_vec[9];

	BN_ULONG npoints, rekey_at;

	BN_CTX *bnctx;
	BIGNUM bna, bnb, bnbase, bnrem, bntmp, bntmp2;
	BIGNUM *bn, *bndiv, *bnptmp;

	EC_KEY *pkey;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT *ppnt = NULL;

	pcre **regex;
	pcre_extra **regex_extra;
	const char ** regex_pat;
	const char *pcre_errptr;
	int pcre_erroffset;

	struct timeval tvstart;

	regex = (pcre**) malloc(npatterns * sizeof(pcre*));
	regex_extra = (pcre_extra**) malloc(npatterns * sizeof(pcre_extra*));
	regex_pat = (const char **) malloc(npatterns * sizeof(char*));

	for (i = 0, nres = 0; i < npatterns; i++) {
		regex[nres] = pcre_compile(patterns[i], 0,
					   &pcre_errptr, &pcre_erroffset, NULL);
		if (!regex[nres]) {
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
		regex_extra[nres] = pcre_study(regex[nres], 0, &pcre_errptr);
		if (pcre_errptr) {
			printf("Regex error: %s\n", pcre_errptr);
			pcre_free(regex[nres]);
			continue;
		}
		regex_pat[nres] = patterns[i];
		nres += 1;
	}

	if (!nres) {
		printf("No suitable regular expressions\n");
		free(regex);
		free(regex_extra);
		free(regex_pat);
		return;
	}

	if (nres > 1)
		printf("Regular expressions: %d\n", nres);

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
		memcpy(&binres[21], hash2, 4);

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

		/*
		 * Run the regular expressions on it
		 * SLOW, runs in linear time with the number of REs
		 */
		for (i = 0; i < nres; i++) {
			d = pcre_exec(regex[i], regex_extra[i],
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
					EC_KEY_set_public_key(pkey, ppnt);

					/* Rekey immediately */
					rekey_at = 0;
					npoints = 0;
				}

				output_match(pkey, regex_pat[i],
					     addrtype, privtype);

				pcre_free(regex[i]);
				if (regex_extra[i])
					pcre_free(regex_extra[i]);
				nres -= 1;
				if (!nres)
					goto out;
				regex[i] = regex[nres];
				regex_extra[i] = regex_extra[nres];
				regex_pat[i] = regex_pat[nres];

				printf("Regular expressions: %d\n", nres);
			}

			else if (d != PCRE_ERROR_NOMATCH) {
				printf("PCRE error: %d\n", d);
				goto out;
			}
		}

		if (++c >= 10000) {
			output_timing(c, &t, &tvstart, 0.0);
			c = 0;
		}
	}

out:
	BN_clear_free(&bna);
	BN_clear_free(&bnb);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnrem);
	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	BN_CTX_free(bnctx);
	EC_KEY_free(pkey);
	EC_POINT_free(ppnt);

	for (i = 0; i < nres; i++) {
		if (regex_extra[i])
			pcre_free(regex_extra[i]);
		pcre_free(regex[i]);
	}
	free(regex);
	free(regex_extra);
	free(regex_pat);
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


void
usage(const char *name)
{
	printf(
"Vanitygen %s\n"
"Usage: %s [-vrNT] [-f <filename>|-] <pattern> [...<pattern>]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-N            Generate namecoin address\n"
"-T            Generate bitcoin testnet address\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n",
version, name);
}

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int privtype = 128;
	int regex = 0;
	int opt;
	FILE *fp = NULL;
	char **patterns;
	int npatterns = 0;

	while ((opt = getopt(argc, argv, "vrNTh?f:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 1;
			break;
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
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (fp) {
		if (!read_file(fp, &patterns, &npatterns)) {
			printf("Failed to load pattern file\n");
			return 1;
		}

	} else {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;
	}
		
	if (regex)
		generate_address_regex(addrtype, privtype,
				       patterns, npatterns);
	else
		generate_address_prefix(addrtype, privtype,
					patterns, npatterns);

	return 0;
}
