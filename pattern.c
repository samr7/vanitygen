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
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <pcre.h>

#include "pattern.h"
#include "util.h"
#include "avl.h"


/*
 * Common code for execution helper
 */

EC_KEY *
vg_exec_context_new_key(void)
{
	return EC_KEY_new_by_curve_name(NID_secp256k1);
}

/*
 * Thread synchronization helpers
 */

static pthread_mutex_t vg_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vg_thread_rdcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_wrcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_upcond = PTHREAD_COND_INITIALIZER;

static void
__vg_exec_context_yield(vg_exec_context_t *vxcp)
{
	vxcp->vxc_lockmode = 0;
	while (vxcp->vxc_vc->vc_thread_excl) {
		if (vxcp->vxc_stop) {
			assert(vxcp->vxc_vc->vc_thread_excl);
			vxcp->vxc_stop = 0;
			pthread_cond_signal(&vg_thread_upcond);
		}
		pthread_cond_wait(&vg_thread_rdcond, &vg_thread_lock);
	}
	assert(!vxcp->vxc_stop);
	assert(!vxcp->vxc_lockmode);
	vxcp->vxc_lockmode = 1;
}

int
vg_exec_context_upgrade_lock(vg_exec_context_t *vxcp)
{
	vg_exec_context_t *tp;
	vg_context_t *vcp;

	if (vxcp->vxc_lockmode == 2)
		return 0;

	pthread_mutex_lock(&vg_thread_lock);

	assert(vxcp->vxc_lockmode == 1);
	vxcp->vxc_lockmode = 0;
	vcp = vxcp->vxc_vc;

	if (vcp->vc_thread_excl++) {
		assert(vxcp->vxc_stop);
		vxcp->vxc_stop = 0;
		pthread_cond_signal(&vg_thread_upcond);
		pthread_cond_wait(&vg_thread_wrcond, &vg_thread_lock);

		for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
			assert(!tp->vxc_lockmode);
			assert(!tp->vxc_stop);
		}

	} else {
		for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
			if (tp->vxc_lockmode) {
				assert(tp->vxc_lockmode != 2);
				tp->vxc_stop = 1;
			}
		}

		do {
			for (tp = vcp->vc_threads;
			     tp != NULL;
			     tp = tp->vxc_next) {
				if (tp->vxc_lockmode) {
					assert(tp->vxc_lockmode != 2);
					pthread_cond_wait(&vg_thread_upcond,
							  &vg_thread_lock);
					break;
				}
			}
		} while (tp);
	}

	vxcp->vxc_lockmode = 2;
	pthread_mutex_unlock(&vg_thread_lock);
	return 1;
}

void
vg_exec_context_downgrade_lock(vg_exec_context_t *vxcp)
{
	pthread_mutex_lock(&vg_thread_lock);
	assert(vxcp->vxc_lockmode == 2);
	assert(!vxcp->vxc_stop);
	if (!--vxcp->vxc_vc->vc_thread_excl) {
		vxcp->vxc_lockmode = 1;
		pthread_cond_broadcast(&vg_thread_rdcond);
		pthread_mutex_unlock(&vg_thread_lock);
		return;
	}
	pthread_cond_signal(&vg_thread_wrcond);
	__vg_exec_context_yield(vxcp);
	pthread_mutex_unlock(&vg_thread_lock);
}

int
vg_exec_context_init(vg_context_t *vcp, vg_exec_context_t *vxcp)
{
	pthread_mutex_lock(&vg_thread_lock);

	memset(vxcp, 0, sizeof(*vxcp));

	vxcp->vxc_vc = vcp;

	BN_init(&vxcp->vxc_bntarg);
	BN_init(&vxcp->vxc_bnbase);
	BN_init(&vxcp->vxc_bntmp);
	BN_init(&vxcp->vxc_bntmp2);

	BN_set_word(&vxcp->vxc_bnbase, 58);

	vxcp->vxc_bnctx = BN_CTX_new();
	assert(vxcp->vxc_bnctx);
	vxcp->vxc_key = vg_exec_context_new_key();
	assert(vxcp->vxc_key);
	EC_KEY_precompute_mult(vxcp->vxc_key, vxcp->vxc_bnctx);

	vxcp->vxc_lockmode = 0;
	vxcp->vxc_stop = 0;

	vxcp->vxc_next = vcp->vc_threads;
	vcp->vc_threads = vxcp;
	__vg_exec_context_yield(vxcp);
	pthread_mutex_unlock(&vg_thread_lock);
	return 1;
}

void
vg_exec_context_del(vg_exec_context_t *vxcp)
{
	vg_exec_context_t *tp, **pprev;

	if (vxcp->vxc_lockmode == 2)
		vg_exec_context_downgrade_lock(vxcp);

	pthread_mutex_lock(&vg_thread_lock);
	assert(vxcp->vxc_lockmode == 1);
	vxcp->vxc_lockmode = 0;

	for (pprev = &vxcp->vxc_vc->vc_threads, tp = *pprev;
	     (tp != vxcp) && (tp != NULL);
	     pprev = &tp->vxc_next, tp = *pprev);

	assert(tp == vxcp);
	*pprev = tp->vxc_next;

	if (tp->vxc_stop)
		pthread_cond_signal(&vg_thread_upcond);

	BN_clear_free(&vxcp->vxc_bntarg);
	BN_clear_free(&vxcp->vxc_bnbase);
	BN_clear_free(&vxcp->vxc_bntmp);
	BN_clear_free(&vxcp->vxc_bntmp2);
	BN_CTX_free(vxcp->vxc_bnctx);
	vxcp->vxc_bnctx = NULL;
	pthread_mutex_unlock(&vg_thread_lock);
}

void
vg_exec_context_yield(vg_exec_context_t *vxcp)
{
	if (vxcp->vxc_lockmode == 2)
		vg_exec_context_downgrade_lock(vxcp);

	else if (vxcp->vxc_stop) {
		assert(vxcp->vxc_lockmode == 1);
		pthread_mutex_lock(&vg_thread_lock);
		__vg_exec_context_yield(vxcp);
		pthread_mutex_unlock(&vg_thread_lock);
	}

	assert(vxcp->vxc_lockmode == 1);
}

void
vg_exec_context_consolidate_key(vg_exec_context_t *vxcp)
{
	if (vxcp->vxc_delta) {
		BN_clear(&vxcp->vxc_bntmp);
		BN_set_word(&vxcp->vxc_bntmp, vxcp->vxc_delta);
		BN_add(&vxcp->vxc_bntmp2,
		       EC_KEY_get0_private_key(vxcp->vxc_key),
		       &vxcp->vxc_bntmp);
		vg_set_privkey(&vxcp->vxc_bntmp2, vxcp->vxc_key);
		vxcp->vxc_delta = 0;
	}
}

void
vg_exec_context_calc_address(vg_exec_context_t *vxcp)
{
	EC_POINT *pubkey;
	const EC_GROUP *pgroup;
	unsigned char eckey_buf[96], hash1[32], hash2[20];
	int len;

	vg_exec_context_consolidate_key(vxcp);
	pgroup = EC_KEY_get0_group(vxcp->vxc_key);
	pubkey = EC_POINT_new(pgroup);
	EC_POINT_copy(pubkey, EC_KEY_get0_public_key(vxcp->vxc_key));
	if (vxcp->vxc_vc->vc_pubkey_base) {
		EC_POINT_add(pgroup,
			     pubkey,
			     pubkey,
			     vxcp->vxc_vc->vc_pubkey_base,
			     vxcp->vxc_bnctx);
	}
	len = EC_POINT_point2oct(pgroup,
				 pubkey,
				 POINT_CONVERSION_UNCOMPRESSED,
				 eckey_buf,
				 sizeof(eckey_buf),
				 vxcp->vxc_bnctx);
	SHA256(eckey_buf, len, hash1);
	RIPEMD160(hash1, sizeof(hash1), hash2);
	memcpy(&vxcp->vxc_binres[1],
	       hash2, 20);
	EC_POINT_free(pubkey);
}

enum {
	timing_hist_size = 5
};

typedef struct _timing_info_s {
	struct _timing_info_s	*ti_next;
	pthread_t		ti_thread;
	unsigned long		ti_last_rate;

	unsigned long long	ti_hist_time[timing_hist_size];
	unsigned long		ti_hist_work[timing_hist_size];
	int			ti_hist_last;
} timing_info_t;

static pthread_mutex_t timing_mutex = PTHREAD_MUTEX_INITIALIZER;

int
vg_output_timing(vg_context_t *vcp, int cycle, struct timeval *last)
{
	pthread_t me;
	struct timeval tvnow, tv;
	timing_info_t *tip, *mytip;
	unsigned long long rate, myrate = 0, mytime, total, sincelast;
	int p, i;

	/* Compute the rate */
	gettimeofday(&tvnow, NULL);
	timersub(&tvnow, last, &tv);
	memcpy(last, &tvnow, sizeof(*last));
	mytime = tv.tv_usec + (1000000ULL * tv.tv_sec);
	if (!mytime)
		mytime = 1;
	rate = 0;

	pthread_mutex_lock(&timing_mutex);
	me = pthread_self();
	for (tip = vcp->vc_timing_head, mytip = NULL;
	     tip != NULL; tip = tip->ti_next) {
		if (pthread_equal(tip->ti_thread, me)) {
			mytip = tip;
			p = ((tip->ti_hist_last + 1) % timing_hist_size);
			tip->ti_hist_time[p] = mytime;
			tip->ti_hist_work[p] = cycle;
			tip->ti_hist_last = p;

			mytime = 0;
			myrate = 0;
			for (i = 0; i < timing_hist_size; i++) {
				mytime += tip->ti_hist_time[i];
				myrate += tip->ti_hist_work[i];
			}
			myrate = (myrate * 1000000) / mytime;
			tip->ti_last_rate = myrate;
			rate += myrate;

		} else
			rate += tip->ti_last_rate;
	}
	if (!mytip) {
		mytip = (timing_info_t *) malloc(sizeof(*tip));
		mytip->ti_next = vcp->vc_timing_head;
		mytip->ti_thread = me;
		vcp->vc_timing_head = mytip;
		mytip->ti_hist_last = 0;
		mytip->ti_hist_time[0] = mytime;
		mytip->ti_hist_work[0] = cycle;
		for (i = 1; i < timing_hist_size; i++) {
			mytip->ti_hist_time[i] = 1;
			mytip->ti_hist_work[i] = 0;
		}
		myrate = ((unsigned long long)cycle * 1000000) / mytime;
		mytip->ti_last_rate = myrate;
		rate += myrate;
	}

	vcp->vc_timing_total += cycle;
	if (vcp->vc_timing_prevfound != vcp->vc_found) {
		vcp->vc_timing_prevfound = vcp->vc_found;
		vcp->vc_timing_sincelast = 0;
	}
	vcp->vc_timing_sincelast += cycle;

	if (mytip != vcp->vc_timing_head) {
		pthread_mutex_unlock(&timing_mutex);
		return myrate;
	}
	total = vcp->vc_timing_total;
	sincelast = vcp->vc_timing_sincelast;
	pthread_mutex_unlock(&timing_mutex);

	vcp->vc_output_timing(vcp, sincelast, rate, total);
	return myrate;
}

void
vg_context_thread_exit(vg_context_t *vcp)
{
	timing_info_t *tip, **ptip;
	pthread_t me;

	pthread_mutex_lock(&timing_mutex);
	me = pthread_self();
	for (ptip = &vcp->vc_timing_head, tip = *ptip;
	     tip != NULL;
	     ptip = &tip->ti_next, tip = *ptip) {
		if (!pthread_equal(tip->ti_thread, me))
			continue;
		*ptip = tip->ti_next;
		free(tip);
		break;
	}
	pthread_mutex_unlock(&timing_mutex);

}

static void
vg_timing_info_free(vg_context_t *vcp)
{
	timing_info_t *tp;
	while (vcp->vc_timing_head != NULL) {
		tp = vcp->vc_timing_head;
		vcp->vc_timing_head = tp->ti_next;
		free(tp);
	}
}

void
vg_output_timing_console(vg_context_t *vcp, double count,
			 unsigned long long rate, unsigned long long total)
{
	double prob, time, targ;
	char *unit;
	char linebuf[80];
	int rem, p, i;

	const double targs[] = { 0.5, 0.75, 0.8, 0.9, 0.95, 1.0 };

	targ = rate;
	unit = "key/s";
	if (targ > 1000) {
		unit = "Kkey/s";
		targ /= 1000.0;
		if (targ > 1000) {
			unit = "Mkey/s";
			targ /= 1000.0;
		}
	}

	rem = sizeof(linebuf);
	p = snprintf(linebuf, rem, "[%.2f %s][total %lld]",
		     targ, unit, total);
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
		if (vcp->vc_remove_on_match)
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
vg_output_match_console(vg_context_t *vcp, EC_KEY *pkey, const char *pattern)
{
	unsigned char key_buf[512], *pend;
	char addr_buf[64], addr2_buf[64];
	char privkey_buf[VG_PROTKEY_MAX_B58];
	const char *keytype = "Privkey";
	int len;
	int isscript = (vcp->vc_format == VCF_SCRIPT);

	EC_POINT *ppnt;
	int free_ppnt = 0;
	if (vcp->vc_pubkey_base) {
		ppnt = EC_POINT_new(EC_KEY_get0_group(pkey));
		EC_POINT_copy(ppnt, EC_KEY_get0_public_key(pkey));
		EC_POINT_add(EC_KEY_get0_group(pkey),
			     ppnt,
			     ppnt,
			     vcp->vc_pubkey_base,
			     NULL);
		free_ppnt = 1;
		keytype = "PrivkeyPart";
	} else {
		ppnt = (EC_POINT *) EC_KEY_get0_public_key(pkey);
	}

	assert(EC_KEY_check_key(pkey));
	vg_encode_address(ppnt,
			  EC_KEY_get0_group(pkey),
			  vcp->vc_pubkeytype, addr_buf);
	if (isscript)
		vg_encode_script_address(ppnt,
					 EC_KEY_get0_group(pkey),
					 vcp->vc_addrtype, addr2_buf);

	if (vcp->vc_key_protect_pass) {
		len = vg_protect_encode_privkey(privkey_buf,
						pkey, vcp->vc_privtype,
						VG_PROTKEY_DEFAULT,
						vcp->vc_key_protect_pass);
		if (len) {
			keytype = "Protkey";
		} else {
			fprintf(stderr,
				"ERROR: could not password-protect key\n");
			vcp->vc_key_protect_pass = NULL;
		}
	}
	if (!vcp->vc_key_protect_pass) {
		vg_encode_privkey(pkey, vcp->vc_privtype, privkey_buf);
	}

	if (!vcp->vc_result_file || (vcp->vc_verbose > 0)) {
		printf("\r%79s\rPattern: %s\n", "", pattern);
	}

	if (vcp->vc_verbose > 0) {
		if (vcp->vc_verbose > 1) {
			pend = key_buf;
			len = i2o_ECPublicKey(pkey, &pend);
			printf("Pubkey (hex): ");
			dumphex(key_buf, len);
			printf("Privkey (hex): ");
			dumpbn(EC_KEY_get0_private_key(pkey));
			pend = key_buf;
			len = i2d_ECPrivateKey(pkey, &pend);
			printf("Privkey (ASN1): ");
			dumphex(key_buf, len);
		}

	}

	if (!vcp->vc_result_file || (vcp->vc_verbose > 0)) {
		if (isscript)
			printf("P2SHAddress: %s\n", addr2_buf);
		printf("Address: %s\n"
		       "%s: %s\n",
		       addr_buf, keytype, privkey_buf);
	}

	if (vcp->vc_result_file) {
		FILE *fp = fopen(vcp->vc_result_file, "a");
		if (!fp) {
			fprintf(stderr,
				"ERROR: could not open result file: %s\n",
				strerror(errno));
		} else {
			fprintf(fp,
				"Pattern: %s\n"
				, pattern);
			if (isscript)
				fprintf(fp, "P2SHAddress: %s\n", addr2_buf);
			fprintf(fp,
				"Address: %s\n"
				"%s: %s\n",
				addr_buf, keytype, privkey_buf);
			fclose(fp);
		}
	}
	if (free_ppnt)
		EC_POINT_free(ppnt);
}


void
vg_context_free(vg_context_t *vcp)
{
	vg_timing_info_free(vcp);
	vcp->vc_free(vcp);
}

int
vg_context_add_patterns(vg_context_t *vcp,
			const char ** const patterns, int npatterns)
{
	vcp->vc_pattern_generation++;
	return vcp->vc_add_patterns(vcp, patterns, npatterns);
}

void
vg_context_clear_all_patterns(vg_context_t *vcp)
{
	vcp->vc_clear_all_patterns(vcp);
	vcp->vc_pattern_generation++;
}

int
vg_context_hash160_sort(vg_context_t *vcp, void *buf)
{
	if (!vcp->vc_hash160_sort)
		return 0;
	return vcp->vc_hash160_sort(vcp, buf);
}

int
vg_context_start_threads(vg_context_t *vcp)
{
	vg_exec_context_t *vxcp;
	int res;

	for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
		res = pthread_create((pthread_t *) &vxcp->vxc_pthread,
				     NULL,
				     (void *(*)(void *)) vxcp->vxc_threadfunc,
				     vxcp);
		if (res) {
			fprintf(stderr, "ERROR: could not create thread: %d\n",
				res);
			vg_context_stop_threads(vcp);
			return -1;
		}
		vxcp->vxc_thread_active = 1;
	}
	return 0;
}

void
vg_context_stop_threads(vg_context_t *vcp)
{
	vcp->vc_halt = 1;
	vg_context_wait_for_completion(vcp);
	vcp->vc_halt = 0;
}

void
vg_context_wait_for_completion(vg_context_t *vcp)
{
	vg_exec_context_t *vxcp;

	for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
		if (!vxcp->vxc_thread_active)
			continue;
		pthread_join((pthread_t) vxcp->vxc_pthread, NULL);
		vxcp->vxc_thread_active = 0;
	}
}


/*
 * Find the bignum ranges that produce a given prefix.
 */
static int
get_prefix_ranges(int addrtype, const char *pfx, BIGNUM **result,
		  BN_CTX *bnctx)
{
	int i, p, c;
	int zero_prefix = 0;
	int check_upper = 0;
	int b58pow, b58ceil, b58top = 0;
	int ret = -1;

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
		c = vg_b58_reverse_map[(int)pfx[i]];
		if (c == -1) {
			fprintf(stderr,
				"Invalid character '%c' in prefix '%s'\n",
				pfx[i], pfx);
			goto out;
		}
		if (i == zero_prefix) {
			if (c == 0) {
				/* Add another zero prefix */
				zero_prefix++;
				if (zero_prefix > 19) {
					fprintf(stderr,
						"Prefix '%s' is too long\n",
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
	BN_sub(&bnceil, &bntmp, BN_value_one());
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
			fprintf(stderr, "Prefix '%s' is too long\n", pfx);
			goto out;
		}

		BN_set_word(&bntmp2, b58pow - (p - zero_prefix));
		BN_exp(&bntmp, &bnbase, &bntmp2, bnctx);
		BN_mul(bnlow, &bntmp, &bntarg, bnctx);
		BN_sub(&bntmp2, &bntmp, BN_value_one());
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
		BN_clear(bnlow);
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
		if (!check_upper)
			goto not_possible;
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
		if (!check_upper)
			goto not_possible;
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
	ret = 0;

	if (0) {
	not_possible:
		ret = -2;
	}

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

static void
free_ranges(BIGNUM **ranges)
{
	BN_free(ranges[0]);
	BN_free(ranges[1]);
	ranges[0] = NULL;
	ranges[1] = NULL;
	if (ranges[2]) {
		BN_free(ranges[2]);
		BN_free(ranges[3]);
		ranges[2] = NULL;
		ranges[3] = NULL;
	}
}


/*
 * Address prefix AVL tree node
 */

const int vpk_nwords = (25 + sizeof(BN_ULONG) - 1) / sizeof(BN_ULONG);

typedef struct _vg_prefix_s {
	avl_item_t		vp_item;
	struct _vg_prefix_s	*vp_sibling;
	const char		*vp_pattern;
	BIGNUM			*vp_low;
	BIGNUM			*vp_high;
} vg_prefix_t;

static void
vg_prefix_free(vg_prefix_t *vp)
{
	if (vp->vp_low)
		BN_free(vp->vp_low);
	if (vp->vp_high)
		BN_free(vp->vp_high);
	free(vp);
}

static vg_prefix_t *
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

static vg_prefix_t *
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

static vg_prefix_t *
vg_prefix_first(avl_root_t *rootp)
{
	avl_item_t *itemp;
	itemp = avl_first(rootp);
	if (itemp)
		return avl_item_entry(itemp, vg_prefix_t, vp_item);
	return NULL;
}

static vg_prefix_t *
vg_prefix_next(vg_prefix_t *vp)
{
	avl_item_t *itemp = &vp->vp_item;
	itemp = avl_next(itemp);
	if (itemp)
		return avl_item_entry(itemp, vg_prefix_t, vp_item);
	return NULL;
}

static vg_prefix_t *
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
			fprintf(stderr,
				"Prefix '%s' ignored, overlaps '%s'\n",
				pattern, vp2->vp_pattern);
			vg_prefix_free(vp);
			vp = NULL;
		}
	}
	return vp;
}

static void
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

static vg_prefix_t *
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

static void
vg_prefix_range_sum(vg_prefix_t *vp, BIGNUM *result, BIGNUM *tmp1)
{
	vg_prefix_t *startp;

	startp = vp;
	BN_clear(result);
	do {
		BN_sub(tmp1, vp->vp_high, vp->vp_low);
		BN_add(result, result, tmp1);
		vp = vp->vp_sibling;
	} while (vp && (vp != startp));
}


typedef struct _prefix_case_iter_s {
	char	ci_prefix[32];
	char	ci_case_map[32];
	char	ci_nbits;
	int	ci_value;
} prefix_case_iter_t;

static const unsigned char b58_case_map[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 0, 1, 1, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 2, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
};

static int
prefix_case_iter_init(prefix_case_iter_t *cip, const char *pfx)
{
	int i;

	cip->ci_nbits = 0;
	cip->ci_value = 0;
	for (i = 0; pfx[i]; i++) {
		if (i > sizeof(cip->ci_prefix))
			return 0;
		if (!b58_case_map[(int)pfx[i]]) {
			/* Character isn't case-swappable, ignore it */
			cip->ci_prefix[i] = pfx[i];
			continue;
		}
		if (b58_case_map[(int)pfx[i]] == 2) {
			/* Character invalid, but valid in swapped case */
			cip->ci_prefix[i] = pfx[i] ^ 0x20;
			continue;
		}
		/* Character is case-swappable */
		cip->ci_prefix[i] = pfx[i] | 0x20;
		cip->ci_case_map[(int)cip->ci_nbits] = i;
		cip->ci_nbits++;
	}
	cip->ci_prefix[i] = '\0';
	return 1;
}

static int
prefix_case_iter_next(prefix_case_iter_t *cip)
{
	unsigned long val, max, mask;
	int i, nbits;

	nbits = cip->ci_nbits;
	max = (1UL << nbits) - 1;
	val = cip->ci_value + 1;
	if (val > max)
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
	int			vcp_caseinsensitive;
} vg_prefix_context_t;

void
vg_prefix_context_set_case_insensitive(vg_context_t *vcp, int caseinsensitive)
{
	((vg_prefix_context_t *) vcp)->vcp_caseinsensitive = caseinsensitive;
}

static void
vg_prefix_context_clear_all_patterns(vg_context_t *vcp)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t *vp;
	unsigned long npfx_left = 0;

	while (!avl_root_empty(&vcpp->vcp_avlroot)) {
		vp = avl_item_entry(vcpp->vcp_avlroot.ar_root,
				    vg_prefix_t, vp_item);
		vg_prefix_delete(&vcpp->vcp_avlroot, vp);
		npfx_left++;
	}

	assert(npfx_left == vcpp->base.vc_npatterns);
	vcpp->base.vc_npatterns = 0;
	vcpp->base.vc_npatterns_start = 0;
	vcpp->base.vc_found = 0;
	BN_clear(&vcpp->vcp_difficulty);
}

static void
vg_prefix_context_free(vg_context_t *vcp)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_context_clear_all_patterns(vcp);
	BN_clear_free(&vcpp->vcp_difficulty);
	free(vcpp);
}

static void
vg_prefix_context_next_difficulty(vg_prefix_context_t *vcpp,
				  BIGNUM *bntmp, BIGNUM *bntmp2, BN_CTX *bnctx)
{
	char *dbuf;

	BN_clear(bntmp);
	BN_set_bit(bntmp, 192);
	BN_div(bntmp2, NULL, bntmp, &vcpp->vcp_difficulty, bnctx);

	dbuf = BN_bn2dec(bntmp2);
	if (vcpp->base.vc_verbose > 0) {
		if (vcpp->base.vc_npatterns > 1)
			fprintf(stderr,
				"Next match difficulty: %s (%ld prefixes)\n",
				dbuf, vcpp->base.vc_npatterns);
		else
			fprintf(stderr, "Difficulty: %s\n", dbuf);
	}
	vcpp->base.vc_chance = atof(dbuf);
	OPENSSL_free(dbuf);
}

static int
vg_prefix_context_add_patterns(vg_context_t *vcp,
			       const char ** const patterns, int npatterns)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
	prefix_case_iter_t caseiter;
	vg_prefix_t *vp, *vp2;
	BN_CTX *bnctx;
	BIGNUM bntmp, bntmp2, bntmp3;
	BIGNUM *ranges[4];
	int ret = 0;
	int i, impossible = 0;
	int case_impossible;
	unsigned long npfx;
	char *dbuf;

	bnctx = BN_CTX_new();
	BN_init(&bntmp);
	BN_init(&bntmp2);
	BN_init(&bntmp3);

	npfx = 0;
	for (i = 0; i < npatterns; i++) {
		if (!vcpp->vcp_caseinsensitive) {
			vp = NULL;
			ret = get_prefix_ranges(vcpp->base.vc_addrtype,
						patterns[i],
						ranges, bnctx);
			if (!ret) {
				vp = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
							  patterns[i],
							  ranges, NULL);
			}

		} else {
			/* Case-enumerate the prefix */
			if (!prefix_case_iter_init(&caseiter, patterns[i])) {
				fprintf(stderr,
					"Prefix '%s' is too long\n",
					patterns[i]);
				continue;
			}

			if (caseiter.ci_nbits > 16) {
				fprintf(stderr,
					"WARNING: Prefix '%s' has "
					"2^%d case-varied derivatives\n",
					patterns[i], caseiter.ci_nbits);
			}

			case_impossible = 0;
			vp = NULL;
			do {
				ret = get_prefix_ranges(vcpp->base.vc_addrtype,
							caseiter.ci_prefix,
							ranges, bnctx);
				if (ret == -2) {
					case_impossible++;
					ret = 0;
					continue;
				}
				if (ret)
					break;
				vp2 = vg_prefix_add_ranges(&vcpp->vcp_avlroot,
							   patterns[i],
							   ranges,
							   vp);
				if (!vp2) {
					ret = -1;
					break;
				}
				if (!vp)
					vp = vp2;

			} while (prefix_case_iter_next(&caseiter));

			if (!vp && case_impossible)
				ret = -2;

			if (ret && vp) {
				vg_prefix_delete(&vcpp->vcp_avlroot, vp);
				vp = NULL;
			}
		}

		if (ret == -2) {
			fprintf(stderr,
				"Prefix '%s' not possible\n", patterns[i]);
			impossible++;
		}

		if (!vp)
			continue;

		npfx++;

		/* Determine the probability of finding a match */
		vg_prefix_range_sum(vp, &bntmp, &bntmp2);
		BN_add(&bntmp2, &vcpp->vcp_difficulty, &bntmp);
		BN_copy(&vcpp->vcp_difficulty, &bntmp2);

		if (vcp->vc_verbose > 1) {
			BN_clear(&bntmp2);
			BN_set_bit(&bntmp2, 192);
			BN_div(&bntmp3, NULL, &bntmp2, &bntmp, bnctx);

			dbuf = BN_bn2dec(&bntmp3);
			fprintf(stderr,
				"Prefix difficulty: %20s %s\n",
				dbuf, patterns[i]);
			OPENSSL_free(dbuf);
		}
	}

	vcpp->base.vc_npatterns += npfx;
	vcpp->base.vc_npatterns_start += npfx;

	if (!npfx && impossible) {
		const char *ats = "bitcoin", *bw = "\"1\"";
		switch (vcpp->base.vc_addrtype) {
		case 5:
			ats = "bitcoin script";
			bw = "\"3\"";
			break;
		case 111:
			ats = "testnet";
			bw = "\"m\" or \"n\"";
			break;
		case 52:
			ats = "namecoin";
			bw = "\"M\" or \"N\"";
			break;
		default:
			break;
		}
		fprintf(stderr,
			"Hint: valid %s addresses begin with %s\n", ats, bw);
	}

	if (npfx)
		vg_prefix_context_next_difficulty(vcpp, &bntmp, &bntmp2, bnctx);

	ret = (npfx != 0);

	BN_clear_free(&bntmp);
	BN_clear_free(&bntmp2);
	BN_clear_free(&bntmp3);
	BN_CTX_free(bnctx);
	return ret;
}

double
vg_prefix_get_difficulty(int addrtype, const char *pattern)
{
	BN_CTX *bnctx;
	BIGNUM result, bntmp;
	BIGNUM *ranges[4];
	char *dbuf;
	int ret;
	double diffret = 0.0;

	bnctx = BN_CTX_new();
	BN_init(&result);
	BN_init(&bntmp);

	ret = get_prefix_ranges(addrtype,
				pattern, ranges, bnctx);

	if (ret == 0) {
		BN_sub(&bntmp, ranges[1], ranges[0]);
		BN_add(&result, &result, &bntmp);
		if (ranges[2]) {
			BN_sub(&bntmp, ranges[3], ranges[2]);
			BN_add(&result, &result, &bntmp);
		}
		free_ranges(ranges);

		BN_clear(&bntmp);
		BN_set_bit(&bntmp, 192);
		BN_div(&result, NULL, &bntmp, &result, bnctx);

		dbuf = BN_bn2dec(&result);
		diffret = strtod(dbuf, NULL);
		OPENSSL_free(dbuf);
	}

	BN_clear_free(&result);
	BN_clear_free(&bntmp);
	BN_CTX_free(bnctx);
	return diffret;
}


static int
vg_prefix_test(vg_exec_context_t *vxcp)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vxcp->vxc_vc;
	vg_prefix_t *vp;
	int res = 0;

	/*
	 * We constrain the prefix so that we can check for
	 * a match without generating the lower four byte
	 * check code.
	 */

	BN_bin2bn(vxcp->vxc_binres, 25, &vxcp->vxc_bntarg);

research:
	vp = vg_prefix_avl_search(&vcpp->vcp_avlroot, &vxcp->vxc_bntarg);
	if (vp) {
		if (vg_exec_context_upgrade_lock(vxcp))
			goto research;

		vg_exec_context_consolidate_key(vxcp);
		vcpp->base.vc_output_match(&vcpp->base, vxcp->vxc_key,
					   vp->vp_pattern);

		vcpp->base.vc_found++;

		if (vcpp->base.vc_only_one) {
			return 2;
		}

		if (vcpp->base.vc_remove_on_match) {
			/* Subtract the range from the difficulty */
			vg_prefix_range_sum(vp,
					    &vxcp->vxc_bntarg,
					    &vxcp->vxc_bntmp);
			BN_sub(&vxcp->vxc_bntmp,
			       &vcpp->vcp_difficulty,
			       &vxcp->vxc_bntarg);
			BN_copy(&vcpp->vcp_difficulty, &vxcp->vxc_bntmp);

			vg_prefix_delete(&vcpp->vcp_avlroot,vp);
			vcpp->base.vc_npatterns--;

			if (!avl_root_empty(&vcpp->vcp_avlroot))
				vg_prefix_context_next_difficulty(
					vcpp, &vxcp->vxc_bntmp,
					&vxcp->vxc_bntmp2,
					vxcp->vxc_bnctx);
			vcpp->base.vc_pattern_generation++;
		}
		res = 1;
	}
	if (avl_root_empty(&vcpp->vcp_avlroot)) {
		return 2;
	}
	return res;
}

static int
vg_prefix_hash160_sort(vg_context_t *vcp, void *buf)
{
	vg_prefix_context_t *vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t *vp;
	unsigned char *cbuf = (unsigned char *) buf;
	unsigned char bnbuf[25];
	int nbytes, ncopy, nskip, npfx = 0;

	/*
	 * Walk the prefix tree in order, copy the upper and lower bound
	 * values into the hash160 buffer.  Skip the lower four bytes
	 * and anything above the 24th byte.
	 */
	for (vp = vg_prefix_first(&vcpp->vcp_avlroot);
	     vp != NULL;
	     vp = vg_prefix_next(vp)) {
		npfx++;
		if (!buf)
			continue;

		/* Low */
		nbytes = BN_bn2bin(vp->vp_low, bnbuf);
		ncopy = ((nbytes >= 24) ? 20 :
			 ((nbytes > 4) ? (nbytes - 4) : 0));
		nskip = (nbytes >= 24) ? (nbytes - 24) : 0;
		if (ncopy < 20)
			memset(cbuf, 0, 20 - ncopy);
		memcpy(cbuf + (20 - ncopy),
		       bnbuf + nskip,
		       ncopy);
		cbuf += 20;

		/* High */
		nbytes = BN_bn2bin(vp->vp_high, bnbuf);
		ncopy = ((nbytes >= 24) ? 20 :
			 ((nbytes > 4) ? (nbytes - 4) : 0));
		nskip = (nbytes >= 24) ? (nbytes - 24) : 0;
		if (ncopy < 20)
			memset(cbuf, 0, 20 - ncopy);
		memcpy(cbuf + (20 - ncopy),
		       bnbuf + nskip,
		       ncopy);
		cbuf += 20;
	}
	return npfx;
}

vg_context_t *
vg_prefix_context_new(int addrtype, int privtype, int caseinsensitive)
{
	vg_prefix_context_t *vcpp;

	vcpp = (vg_prefix_context_t *) malloc(sizeof(*vcpp));
	if (vcpp) {
		memset(vcpp, 0, sizeof(*vcpp));
		vcpp->base.vc_addrtype = addrtype;
		vcpp->base.vc_privtype = privtype;
		vcpp->base.vc_npatterns = 0;
		vcpp->base.vc_npatterns_start = 0;
		vcpp->base.vc_found = 0;
		vcpp->base.vc_chance = 0.0;
		vcpp->base.vc_free = vg_prefix_context_free;
		vcpp->base.vc_add_patterns = vg_prefix_context_add_patterns;
		vcpp->base.vc_clear_all_patterns =
			vg_prefix_context_clear_all_patterns;
		vcpp->base.vc_test = vg_prefix_test;
		vcpp->base.vc_hash160_sort = vg_prefix_hash160_sort;
		avl_root_init(&vcpp->vcp_avlroot);
		BN_init(&vcpp->vcp_difficulty);
		vcpp->vcp_caseinsensitive = caseinsensitive;
	}
	return &vcpp->base;
}




typedef struct _vg_regex_context_s {
	vg_context_t		base;
	pcre 			**vcr_regex;
	pcre_extra		**vcr_regex_extra;
	const char		**vcr_regex_pat;
	unsigned long		vcr_nalloc;
} vg_regex_context_t;

static int
vg_regex_context_add_patterns(vg_context_t *vcp,
			      const char ** const patterns, int npatterns)
{
	vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
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
			fprintf(stderr, "%s\n", patterns[i]);
			while (pcre_erroffset > 16) {
				fprintf(stderr, "%s", spaces);
				pcre_erroffset -= 16;
			}
			if (pcre_erroffset > 0)
				fprintf(stderr,
					"%s", &spaces[16 - pcre_erroffset]);
			fprintf(stderr, "^\nRegex error: %s\n", pcre_errptr);
			continue;
		}
		vcrp->vcr_regex_extra[nres] =
			pcre_study(vcrp->vcr_regex[nres], 0, &pcre_errptr);
		if (pcre_errptr) {
			fprintf(stderr, "Regex error: %s\n", pcre_errptr);
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

static void
vg_regex_context_clear_all_patterns(vg_context_t *vcp)
{
	vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
	int i;
	for (i = 0; i < vcrp->base.vc_npatterns; i++) {
		if (vcrp->vcr_regex_extra[i])
			pcre_free(vcrp->vcr_regex_extra[i]);
		pcre_free(vcrp->vcr_regex[i]);
	}
	vcrp->base.vc_npatterns = 0;
	vcrp->base.vc_npatterns_start = 0;
	vcrp->base.vc_found = 0;
}

static void
vg_regex_context_free(vg_context_t *vcp)
{
	vg_regex_context_t *vcrp = (vg_regex_context_t *) vcp;
	vg_regex_context_clear_all_patterns(vcp);
	if (vcrp->vcr_nalloc)
		free(vcrp->vcr_regex);
	free(vcrp);
}

static int
vg_regex_test(vg_exec_context_t *vxcp)
{
	vg_regex_context_t *vcrp = (vg_regex_context_t *) vxcp->vxc_vc;

	unsigned char hash1[32], hash2[32];
	int i, zpfx, p, d, nres, re_vec[9];
	char b58[40];
	BIGNUM bnrem;
	BIGNUM *bn, *bndiv, *bnptmp;
	int res = 0;

	pcre *re;

	BN_init(&bnrem);

	/* Hash the hash and write the four byte check code */
	SHA256(vxcp->vxc_binres, 21, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&vxcp->vxc_binres[21], hash2, 4);

	bn = &vxcp->vxc_bntmp;
	bndiv = &vxcp->vxc_bntmp2;

	BN_bin2bn(vxcp->vxc_binres, 25, bn);

	/* Compute the complete encoded address */
	for (zpfx = 0; zpfx < 25 && vxcp->vxc_binres[zpfx] == 0; zpfx++);
	p = sizeof(b58) - 1;
	b58[p] = '\0';
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, &bnrem, bn, &vxcp->vxc_bnbase, vxcp->vxc_bnctx);
		bnptmp = bn;
		bn = bndiv;
		bndiv = bnptmp;
		d = BN_get_word(&bnrem);
		b58[--p] = vg_b58_alphabet[d];
	}
	while (zpfx--) {
		b58[--p] = vg_b58_alphabet[0];
	}

	/*
	 * Run the regular expressions on it
	 * SLOW, runs in linear time with the number of REs
	 */
restart_loop:
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
				fprintf(stderr, "PCRE error: %d\n", d);
				res = 2;
				goto out;
			}
			continue;
		}

		re = vcrp->vcr_regex[i];

		if (vg_exec_context_upgrade_lock(vxcp) &&
		    ((i >= vcrp->base.vc_npatterns) ||
		     (vcrp->vcr_regex[i] != re)))
			goto restart_loop;

		vg_exec_context_consolidate_key(vxcp);
		vcrp->base.vc_output_match(&vcrp->base, vxcp->vxc_key,
					   vcrp->vcr_regex_pat[i]);
		vcrp->base.vc_found++;

		if (vcrp->base.vc_only_one) {
			res = 2;
			goto out;
		}

		if (vcrp->base.vc_remove_on_match) {
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
			vcrp->base.vc_pattern_generation++;
		}
		res = 1;
	}
out:
	BN_clear_free(&bnrem);
	return res;
}

vg_context_t *
vg_regex_context_new(int addrtype, int privtype)
{
	vg_regex_context_t *vcrp;

	vcrp = (vg_regex_context_t *) malloc(sizeof(*vcrp));
	if (vcrp) {
		memset(vcrp, 0, sizeof(*vcrp));
		vcrp->base.vc_addrtype = addrtype;
		vcrp->base.vc_privtype = privtype;
		vcrp->base.vc_npatterns = 0;
		vcrp->base.vc_npatterns_start = 0;
		vcrp->base.vc_found = 0;
		vcrp->base.vc_chance = 0.0;
		vcrp->base.vc_free = vg_regex_context_free;
		vcrp->base.vc_add_patterns = vg_regex_context_add_patterns;
		vcrp->base.vc_clear_all_patterns =
			vg_regex_context_clear_all_patterns;
		vcrp->base.vc_test = vg_regex_test;
		vcrp->base.vc_hash160_sort = NULL;
		vcrp->vcr_regex = NULL;
		vcrp->vcr_nalloc = 0;
	}
	return &vcrp->base;
}
