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
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "pattern.h"

const char *version = "0.15";

typedef struct _vg_thread_context_s {
	vg_exec_context_t		base;
	struct _vg_thread_context_s	*vt_next;
	int				vt_mode;
	int				vt_stop;
} vg_thread_context_t;


/*
 * To synchronize pattern lists, we use a special shared-exclusive lock
 * geared toward being held in shared mode 99.9% of the time.
 */

static pthread_mutex_t vg_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vg_thread_rdcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_wrcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_upcond = PTHREAD_COND_INITIALIZER;
static vg_thread_context_t *vg_threads = NULL;
static int vg_thread_excl = 0;

void
__vg_thread_yield(vg_thread_context_t *vtcp)
{
	vtcp->vt_mode = 0;
	while (vg_thread_excl) {
		if (vtcp->vt_stop) {
			assert(vg_thread_excl);
			vtcp->vt_stop = 0;
			pthread_cond_signal(&vg_thread_upcond);
		}
		pthread_cond_wait(&vg_thread_rdcond, &vg_thread_lock);
	}
	assert(!vtcp->vt_stop);
	assert(!vtcp->vt_mode);
	vtcp->vt_mode = 1;
}

void
vg_thread_context_init(vg_context_t *vcp, vg_thread_context_t *vtcp)
{
	vtcp->vt_mode = 0;
	vtcp->vt_stop = 0;

	pthread_mutex_lock(&vg_thread_lock);
	vg_exec_context_init(vcp, &vtcp->base);
	vtcp->vt_next = vg_threads;
	vg_threads = vtcp;
	__vg_thread_yield(vtcp);
	pthread_mutex_unlock(&vg_thread_lock);
}

void
vg_thread_context_del(vg_thread_context_t *vtcp)
{
	vg_thread_context_t *tp, **pprev;

	if (vtcp->vt_mode == 2)
		vg_exec_downgrade_lock(&vtcp->base);

	pthread_mutex_lock(&vg_thread_lock);
	assert(vtcp->vt_mode == 1);
	vtcp->vt_mode = 0;

	for (pprev = &vg_threads, tp = *pprev;
	     (tp != vtcp) && (tp != NULL);
	     pprev = &tp->vt_next, tp = *pprev);

	assert(tp == vtcp);
	*pprev = tp->vt_next;

	if (tp->vt_stop)
		pthread_cond_signal(&vg_thread_upcond);

	vg_exec_context_del(&vtcp->base);
	pthread_mutex_unlock(&vg_thread_lock);
}

void
vg_thread_yield(vg_thread_context_t *vtcp)
{
	if (vtcp->vt_mode == 2)
		vg_exec_downgrade_lock(&vtcp->base);

	else if (vtcp->vt_stop) {
		assert(vtcp->vt_mode == 1);
		pthread_mutex_lock(&vg_thread_lock);
		__vg_thread_yield(vtcp);
		pthread_mutex_unlock(&vg_thread_lock);
	}

	assert(vtcp->vt_mode == 1);
}



void
vg_exec_downgrade_lock(vg_exec_context_t *vxcp)
{
	vg_thread_context_t *vtcp = (vg_thread_context_t *) vxcp;
	pthread_mutex_lock(&vg_thread_lock);

	assert(vtcp->vt_mode == 2);
	assert(!vtcp->vt_stop);
	if (!--vg_thread_excl) {
		vtcp->vt_mode = 1;
		pthread_cond_broadcast(&vg_thread_rdcond);
		pthread_mutex_unlock(&vg_thread_lock);
		return;
	}
	pthread_cond_signal(&vg_thread_wrcond);
	__vg_thread_yield(vtcp);
	pthread_mutex_unlock(&vg_thread_lock);
}

int
vg_exec_upgrade_lock(vg_exec_context_t *vxcp)
{
	vg_thread_context_t *vtcp = (vg_thread_context_t *) vxcp;
	vg_thread_context_t *tp;

	if (vtcp->vt_mode == 2)
		return 0;

	pthread_mutex_lock(&vg_thread_lock);

	assert(vtcp->vt_mode == 1);
	vtcp->vt_mode = 0;

	if (vg_thread_excl++) {
		assert(vtcp->vt_stop);
		vtcp->vt_stop = 0;
		pthread_cond_signal(&vg_thread_upcond);
		pthread_cond_wait(&vg_thread_wrcond, &vg_thread_lock);

		for (tp = vg_threads; tp != NULL; tp = tp->vt_next) {
			assert(!tp->vt_mode);
			assert(!tp->vt_stop);
		}

	} else {
		for (tp = vg_threads; tp != NULL; tp = tp->vt_next) {
			if (tp->vt_mode) {
				assert(tp->vt_mode != 2);
				tp->vt_stop = 1;
			}
		}

		do {
			for (tp = vg_threads; tp != NULL; tp = tp->vt_next) {
				if (tp->vt_mode) {
					assert(tp->vt_mode != 2);
					pthread_cond_wait(&vg_thread_upcond,
							  &vg_thread_lock);
					break;
				}
			}
		} while (tp);
	}

	vtcp->vt_mode = 2;
	pthread_mutex_unlock(&vg_thread_lock);
	return 1;
}

/*
 * Address search thread main loop
 */

void *
vg_thread_loop(void *arg)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32];

	int i, c, len, output_interval;

	const BN_ULONG rekey_max = 10000000;
	BN_ULONG npoints, rekey_at, nbatch;

	vg_context_t *vcp = (vg_context_t *) arg;
	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	const int ptarraysize = 256;
	EC_POINT *ppnt[ptarraysize];
	EC_POINT *pbatchinc;

	vg_test_func_t test_func = vcp->vc_test;
	vg_thread_context_t ctx;
	vg_exec_context_t *vxcp;

	struct timeval tvstart;


	memset(&ctx, 0, sizeof(ctx));
	vxcp = &ctx.base;

	vg_thread_context_init(vcp, &ctx);

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	for (i = 0; i < ptarraysize; i++) {
		ppnt[i] = EC_POINT_new(pgroup);
		if (!ppnt[i]) {
			printf("ERROR: out of memory?\n");
			exit(1);
		}
	}
	pbatchinc = EC_POINT_new(pgroup);
	if (!pbatchinc) {
		printf("ERROR: out of memory?\n");
		exit(1);
	}

	BN_set_word(&vxcp->vxc_bntmp, ptarraysize);
	EC_POINT_mul(pgroup, pbatchinc, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	npoints = 0;
	rekey_at = 0;
	nbatch = 0;
	vxcp->vxc_key = pkey;
	vxcp->vxc_binres[0] = vcp->vc_addrtype;
	c = 0;
	output_interval = 1000;
	gettimeofday(&tvstart, NULL);

	while (1) {
		if (++npoints >= rekey_at) {
			pthread_mutex_lock(&vg_thread_lock);
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, &vxcp->vxc_bntmp,
					   vxcp->vxc_bnctx);
			BN_sub(&vxcp->vxc_bntmp2,
			       &vxcp->vxc_bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(&vxcp->vxc_bntmp2);
			if ((rekey_at == BN_MASK2) || (rekey_at > rekey_max))
				rekey_at = rekey_max;
			assert(rekey_at > 0);

			EC_POINT_copy(ppnt[0], EC_KEY_get0_public_key(pkey));
			pthread_mutex_unlock(&vg_thread_lock);

			npoints++;
			vxcp->vxc_delta = 0;

			for (nbatch = 1;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch-1],
					     pgen, vxcp->vxc_bnctx);
			}

		} else {
			/*
			 * Common case
			 *
			 * EC_POINT_add() can skip a few multiplies if
			 * one or both inputs are affine (Z_is_one).
			 * This is the case for every point in ppnt, as
			 * well as pbatchinc.
			 */
			assert(nbatch == ptarraysize);
			for (nbatch = 0;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch],
					     pbatchinc,
					     vxcp->vxc_bnctx);
			}
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

		EC_POINTs_make_affine(pgroup, nbatch, ppnt, vxcp->vxc_bnctx);

		for (i = 0; i < nbatch; i++, vxcp->vxc_delta++) {
			/* Hash the public key */
			len = EC_POINT_point2oct(pgroup, ppnt[i],
						 POINT_CONVERSION_UNCOMPRESSED,
						 eckey_buf,
						 sizeof(eckey_buf),
						 vxcp->vxc_bnctx);

			SHA256(eckey_buf, len, hash1);
			RIPEMD160(hash1, sizeof(hash1), &vxcp->vxc_binres[1]);

			vxcp->vxc_point = ppnt[i];

			switch (test_func(vxcp)) {
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

		c += (i + 1);
		if (c >= output_interval) {
			output_interval = vg_output_timing(vcp, c, &tvstart);
			c = 0;
		}

		vg_thread_yield(&ctx);
	}

out:
	vg_thread_context_del(&ctx);

	for (i = 0; i < ptarraysize; i++)
		if (ppnt[i])
			EC_POINT_free(ppnt[i]);
	if (pbatchinc)
		EC_POINT_free(pbatchinc);
	return NULL;
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
start_threads(vg_context_t *vcp, int nthreads)
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

	if (vcp->vc_verbose > 1) {
		printf("Using %d worker thread(s)\n", nthreads);
	}

	while (--nthreads) {
		if (pthread_create(&thread, NULL, vg_thread_loop, vcp))
			return 0;
	}

	vg_thread_loop(vcp);
	return 1;
}


void
usage(const char *name)
{
	printf(
"Vanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
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
"-X <version>  Generate address with the given version\n"
"-t <threads>  Set number of worker threads (Default: number of CPUs)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n",
version, name);
}

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int privtype = 128;
	int regex = 0;
	int caseinsensitive = 0;
	int verbose = 1;
	int remove_on_match = 1;
	int opt;
	char *seedfile = NULL;
	FILE *fp = NULL;
	const char *result_file = NULL;
	char **patterns;
	int npatterns = 0;
	int nthreads = 0;
	vg_context_t *vcp = NULL;

	while ((opt = getopt(argc, argv, "vqrikNTX:t:h?f:o:s:")) != -1) {
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
			privtype = 180;
			break;
		case 'T':
			addrtype = 111;
			privtype = 239;
			break;
		case 'X':
			addrtype = atoi(optarg);
			privtype = 128 + addrtype;
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
				fp = fopen(optarg, "r");
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
		case 's':
			if (seedfile != NULL) {
				printf("Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		printf("WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
		       "WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif

	if (caseinsensitive && regex)
		printf("WARNING: case insensitive mode incompatible with "
		       "regular expressions\n");

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) &&
			    (st.st_mode & (S_IFBLK|S_IFCHR))) {
				opt = 32;
		} }
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			printf("Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			printf("Read %d bytes from RNG seed file\n", opt);
		}
	}

	if (fp) {
		if (!vg_read_file(fp, &patterns, &npatterns)) {
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
		vcp = vg_regex_context_new(addrtype, privtype);

	} else {
		vcp = vg_prefix_context_new(addrtype, privtype,
					    caseinsensitive);
	}

	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;

	if (!vg_context_add_patterns(vcp, patterns, npatterns))
		return 1;

	if (!vcp->vc_npatterns) {
		printf("No patterns to search\n");
		return 1;
	}

	if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
		printf("Regular expressions: %ld\n", vcp->vc_npatterns);

	if (!start_threads(vcp, nthreads))
		return 1;
	return 0;
}
