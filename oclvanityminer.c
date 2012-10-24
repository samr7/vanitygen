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

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <curl/curl.h>

#include "oclengine.h"
#include "pattern.h"
#include "util.h"
#include "avl.h"


const char *version = VANITYGEN_VERSION;
const int debug = 0;


/*
 * Bounty work item, which includes a pattern and a public key
 * Indexed in an AVL tree by pattern
 */

typedef struct workitem_s {
	avl_item_t avlent;
	const char *pattern;
	const char *comment;
	EC_POINT *pubkey;
	int addrtype;
	double difficulty;
	double reward;
	double value;
} workitem_t;


static int
workitem_cmp(workitem_t *a, workitem_t *b)
{
	int cmpres;
	cmpres = strcmp(a->pattern, b->pattern);
	if (!cmpres)
		cmpres = (a->reward < b->reward) ? -1 :
			((a->reward > b->reward) ? 1 : 0);
	return cmpres;
}

static workitem_t *
workitem_avl_search(avl_root_t *rootp, const char *pattern)
{
	workitem_t *vp;
	avl_item_t *itemp = rootp->ar_root;

	while (itemp) {
		int cmpres;
		vp = avl_item_entry(itemp, workitem_t, avlent);
		cmpres = strcmp(vp->pattern, pattern);
		if (cmpres > 0) {
			itemp = itemp->ai_left;
		} else {
			if (cmpres < 0) {
				itemp = itemp->ai_right;
			} else
				return vp;
		}
	}
	return NULL;
}

static workitem_t *
workitem_avl_insert(avl_root_t *rootp, workitem_t *vpnew)
{
	workitem_t *vp;
	avl_item_t *itemp = NULL;
	avl_item_t **ptrp = &rootp->ar_root;
	while (*ptrp) {
		int cmpres;
		itemp = *ptrp;
		vp = avl_item_entry(itemp, workitem_t, avlent);
		cmpres = workitem_cmp(vp, vpnew);
		if (cmpres > 0) {
			ptrp = &itemp->ai_left;
		} else {
			if (cmpres < 0) {
				ptrp = &itemp->ai_right;
			} else
				return vp;
		}
	}
	vpnew->avlent.ai_up = itemp;
	itemp = &vpnew->avlent;
	*ptrp = itemp;
	avl_insert_fix(rootp, itemp);
	return NULL;
}

static workitem_t *
workitem_avl_first(avl_root_t *rootp)
{
	avl_item_t *itemp;
	itemp = avl_first(rootp);
	if (itemp)
		return avl_item_entry(itemp, workitem_t, avlent);
	return NULL;
}

static workitem_t *
workitem_avl_next(workitem_t *vp)
{
	avl_item_t *itemp = &vp->avlent;
	itemp = avl_next(itemp);
	if (itemp)
		return avl_item_entry(itemp, workitem_t, avlent);
	return NULL;
}

void
server_workitem_free(workitem_t *wip)
{
	if (wip->pubkey)
		EC_POINT_free(wip->pubkey);
	free(wip);
}


/*
 * pubkeybatch, which includes a set of pattern bounties with the same
 * base public key.  Patterns may be searched for concurrently due to
 * having the same base public key.
 *
 * Indexed in an AVL tree by public key.
 */

typedef struct pubkeybatch_s {
	avl_item_t avlent;
	EC_POINT *pubkey;
	const char *pubkey_hex;
	avl_root_t items;
	int nitems;
	double total_value;
} pubkeybatch_t;

void
server_batch_free(pubkeybatch_t *pbatch)
{
	workitem_t *wip;
	while ((wip = workitem_avl_first(&pbatch->items)) != NULL) {
		if (wip->pubkey == pbatch->pubkey)
			wip->pubkey = NULL;
		avl_remove(&pbatch->items, &wip->avlent);
		server_workitem_free(wip);
	}
	if (pbatch->pubkey)
		EC_POINT_free(pbatch->pubkey);
	if (pbatch->pubkey_hex)
		OPENSSL_free((char*)pbatch->pubkey_hex);
	free(pbatch);
}

static int
pubkeybatch_cmp(pubkeybatch_t *a, pubkeybatch_t *b)
{
	return strcmp(a->pubkey_hex, b->pubkey_hex);
}

static pubkeybatch_t *
pubkeybatch_avl_search(avl_root_t *rootp, const EC_POINT *pubkey,
		       const EC_GROUP *pgroup)
{
	char *pubkey_hex;
	pubkeybatch_t *vp;
	avl_item_t *itemp = rootp->ar_root;
	pubkey_hex = EC_POINT_point2hex(pgroup,
					pubkey,
					POINT_CONVERSION_UNCOMPRESSED,
					NULL);
	while (itemp) {
		int cmpres;
		vp = avl_item_entry(itemp, pubkeybatch_t, avlent);
		cmpres = strcmp(pubkey_hex, vp->pubkey_hex);
		if (cmpres > 0) {
			itemp = itemp->ai_left;
		} else {
			if (cmpres < 0) {
				itemp = itemp->ai_right;
			} else {
				OPENSSL_free(pubkey_hex);
				return vp;
			}
		}
	}
	OPENSSL_free(pubkey_hex);
	return NULL;
}

static pubkeybatch_t *
pubkeybatch_avl_insert(avl_root_t *rootp, pubkeybatch_t *vpnew)
{
	pubkeybatch_t *vp;
	avl_item_t *itemp = NULL;
	avl_item_t **ptrp = &rootp->ar_root;
	while (*ptrp) {
		int cmpres;
		itemp = *ptrp;
		vp = avl_item_entry(itemp, pubkeybatch_t, avlent);
		cmpres = pubkeybatch_cmp(vpnew, vp);
		if (cmpres > 0) {
			ptrp = &itemp->ai_left;
		} else {
			if (cmpres < 0) {
				ptrp = &itemp->ai_right;
			} else
				return vp;
		}
	}
	vpnew->avlent.ai_up = itemp;
	itemp = &vpnew->avlent;
	*ptrp = itemp;
	avl_insert_fix(rootp, itemp);
	return NULL;
}

static pubkeybatch_t *
pubkeybatch_avl_first(avl_root_t *rootp)
{
	avl_item_t *itemp;
	itemp = avl_first(rootp);
	if (itemp)
		return avl_item_entry(itemp, pubkeybatch_t, avlent);
	return NULL;
}

static pubkeybatch_t *
pubkeybatch_avl_next(pubkeybatch_t *vp)
{
	avl_item_t *itemp = &vp->avlent;
	itemp = avl_next(itemp);
	if (itemp)
		return avl_item_entry(itemp, pubkeybatch_t, avlent);
	return NULL;
}


typedef struct server_request_s {
	int request_status;
	const EC_GROUP *group;

	char *part_buf;
	size_t part_off;
	size_t part_end;
	size_t part_size;

	avl_root_t items;
	int nitems;
} server_request_t;


static workitem_t *
server_workitem_new(server_request_t *reqp,
		    const char *pfx, const char *pubkey_s,
		    const char *addrtype_s, const char *reward_s,
		    const char *comment)
{
	workitem_t *wip;
	EC_POINT *pubkey;
	int addrtype;
	double reward;
	double difficulty;

	addrtype = atoi(addrtype_s);
	if ((addrtype < 0) || (addrtype > 255))
		return NULL;

	reward = strtod(reward_s, NULL);
	if (reward < 0.0)
		return NULL;

	difficulty = vg_prefix_get_difficulty(addrtype, pfx);
	if (difficulty == 0.0)
		return NULL;

	pubkey = EC_POINT_hex2point(reqp->group, pubkey_s, NULL, NULL);
	if (pubkey == NULL)
		return NULL;


	wip = (workitem_t *) malloc(sizeof(*wip) +
				    strlen(pfx) +
				    strlen(comment) + 2);
	memset(wip, 0, sizeof(*wip));
	avl_item_init(&wip->avlent);
	wip->pattern = (char *) (wip + 1);
	strcpy((char *)wip->pattern, pfx);
	wip->comment = wip->pattern + (strlen(wip->pattern) + 1);
	strcpy((char *) wip->comment, comment);
	wip->pubkey = pubkey;
	wip->addrtype = addrtype;
	wip->difficulty = difficulty;
	wip->reward = reward;
	wip->value = (reward * 1000000000.0) / difficulty;

	return wip;
}


typedef struct server_context_s {
	EC_KEY *dummy_key;
	const char *url;
	const char *credit_addr;
	char *getwork;
	char *submit;
	int verbose;
	avl_root_t items;
	int nitems;
} server_context_t;


static int
server_workitem_equal(workitem_t *a, workitem_t *b)
{
	return (a->reward == b->reward) && !strcmp(a->pattern, b->pattern);
}

static int
server_pubkeybatch_equal(server_context_t *ctxp,
			 pubkeybatch_t *a, pubkeybatch_t *b)
{
	workitem_t *wipa, *wipb;

	if (a->nitems != b->nitems)
		return 0;
	if (EC_POINT_cmp(EC_KEY_get0_group(ctxp->dummy_key),
			 a->pubkey, b->pubkey, NULL))
		return 0;

	for (wipa = workitem_avl_first(&a->items),
		     wipb = workitem_avl_first(&b->items);
	     wipa && wipb;
	     wipa = workitem_avl_next(wipa), wipb = workitem_avl_next(wipb)) {
		if (!server_workitem_equal(wipa, wipb))
			return 0;
	}
	return 1;
}

void
server_context_free(server_context_t *ctxp)
{
	if (ctxp->dummy_key)
		EC_KEY_free(ctxp->dummy_key);
	if (ctxp->getwork)
		free(ctxp->getwork);
	if (ctxp->submit)
		free(ctxp->submit);
	free(ctxp);
}

server_context_t *
server_context_new(const char *url, const char *credit_addr)
{
	server_context_t *ctxp;
	int urllen = strlen(url);
	int addrlen = strlen(credit_addr);
	ctxp = (server_context_t *)
		malloc(sizeof(*ctxp) + urllen + addrlen + 2);
	memset(ctxp, 0, sizeof(*ctxp));
	avl_root_init(&ctxp->items);
	ctxp->url = (const char *) (ctxp + 1);
	ctxp->credit_addr = (const char *) (ctxp->url + urllen + 1);
	strcpy((char *) ctxp->url, url);
	strcpy((char *) ctxp->credit_addr, credit_addr);

	ctxp->dummy_key = vg_exec_context_new_key();
	ctxp->getwork = (char *) malloc(urllen + 9);
	ctxp->submit = (char *) malloc(urllen + 7);
	if (url[urllen - 1] == '/') {
		snprintf(ctxp->getwork, urllen + 9, "%sgetWork", url);
		snprintf(ctxp->submit, urllen + 7, "%ssolve", url);
	} else {
		snprintf(ctxp->getwork, urllen + 9, "%s/getWork", url);
		snprintf(ctxp->submit, urllen + 7, "%s/solve", url);
	}

	return ctxp;
}


int
server_workitem_add(server_request_t *reqp, workitem_t *wip)
{
	workitem_t *xwip;
	pubkeybatch_t *pbatch = NULL;

	pbatch = pubkeybatch_avl_search(&reqp->items, wip->pubkey, reqp->group);
	if (pbatch == NULL) {
		pbatch = (pubkeybatch_t *) malloc(sizeof(*pbatch));
		if (pbatch == NULL)
			return -1;
		memset(pbatch, 0, sizeof(*pbatch));
		avl_item_init(&pbatch->avlent);
		avl_root_init(&pbatch->items);
		pbatch->total_value = 0;
		pbatch->pubkey = wip->pubkey;
		pbatch->pubkey_hex = EC_POINT_point2hex(reqp->group, 
					wip->pubkey, 
					POINT_CONVERSION_UNCOMPRESSED, 
					NULL);
		pubkeybatch_avl_insert(&reqp->items, pbatch);
		reqp->nitems++;
	}

	/* Make sure there isn't an overlap */
	xwip = workitem_avl_insert(&pbatch->items, wip);
	if (xwip)
		return -1;

	if (wip->pubkey && wip->pubkey != pbatch->pubkey)
		EC_POINT_free(wip->pubkey);
	wip->pubkey = pbatch->pubkey;
	
	pbatch->nitems++;
	pbatch->total_value += wip->value;
	return 0;
}


static size_t
server_body_reader(const char *buf, size_t elemsize, size_t len, void *param)
{
	server_request_t *reqp = (server_request_t *) param;
	char *line, *sep, *pfx, *pubkey_s, *addrtype_s, *reward_s, *comment;
	workitem_t *wip;

	if (!len)
		return 0;

	if ((reqp->part_size < (reqp->part_end + len + 1)) &&
	    (reqp->part_off > 0)) {
		memmove(reqp->part_buf,
			reqp->part_buf + reqp->part_off,
			reqp->part_end - reqp->part_off);
		reqp->part_end -= reqp->part_off;
		reqp->part_off = 0;
	}

	if (reqp->part_size < (reqp->part_end + len + 1)) {
		if (reqp->part_size == 0)
			reqp->part_size = 4096;
		while (reqp->part_size < (reqp->part_end + len + 1)) {
			reqp->part_size *= 2;
			if (reqp->part_size > (1024*1024)) {
				fprintf(stderr, "Line too long from server");
				reqp->request_status = 0;
				return 0;
			}
		}
		reqp->part_buf = (char *) realloc(reqp->part_buf,
						  reqp->part_size);
		if (!reqp->part_buf) {
			fprintf(stderr, "Out of memory");
			return 0;
		}
	}

	memcpy(reqp->part_buf + reqp->part_end, buf, len);
	reqp->part_end += len;
	reqp->part_buf[reqp->part_end] = '\0';

	line = reqp->part_buf + reqp->part_off;
	while (1) {
		sep = strchr(line, '\n');
		if (!sep)
			break;
		pfx = line;
		*sep = '\0';
		line = sep + 1;
		sep = strchr(pfx, ':');
		if (!sep)
			goto bad_line;
	        *sep = '\0'; sep += 1;
		pubkey_s = sep;
		sep = strchr(sep, ':');
		if (!sep)
			goto bad_line;
	        *sep = '\0'; sep += 1;
		addrtype_s = sep;
		sep = strchr(sep, ':');
		if (!sep)
			goto bad_line;
	        *sep = '\0'; sep += 1;
		reward_s = sep;
		sep = strchr(sep, ';');
		if (!sep)
			goto bad_line;
	        *sep = '\0'; sep += 1;
		comment = sep;

		wip = server_workitem_new(reqp, pfx, pubkey_s, addrtype_s,
					  reward_s, comment);
		if (!wip)
			goto bad_line;
		if (server_workitem_add(reqp, wip)) {
			server_workitem_free(wip);
			goto bad_line;
		}
		continue;

	bad_line:
		;
	}

	reqp->part_off = line - reqp->part_buf;
	if (reqp->part_off == reqp->part_end) {
		reqp->part_off = 0;
		reqp->part_end = 0;
	}

	return len;
}

void
dump_work(avl_root_t *work)
{
	pubkeybatch_t *pbatch;
	workitem_t *wip;
	printf("Available bounties:\n");
	for (pbatch = pubkeybatch_avl_first(work);
	     pbatch != NULL;
	     pbatch = pubkeybatch_avl_next(pbatch)) {

		for (wip = workitem_avl_first(&pbatch->items);
		     wip != NULL;
		     wip = workitem_avl_next(wip)) {
			printf("Pattern: \"%s\" Reward: %f "
			       "Value: %f BTC/Gkey\n",
			       wip->pattern,
			       wip->reward,
			       wip->value);
		}
		if (pbatch->nitems > 1)
			printf("Batch of %d, total value: %f BTC/Gkey\n",
			       pbatch->nitems, pbatch->total_value);
	}
}

void
free_pkb_tree(avl_root_t *rootp, pubkeybatch_t *save_pkb)
{
	pubkeybatch_t *pkb;
	while ((pkb = pubkeybatch_avl_first(rootp)) != NULL) {
		avl_remove(rootp, &pkb->avlent);
		if (pkb != save_pkb)
			server_batch_free(pkb);
	}
}

void
server_request_free(server_request_t *reqp)
{
	if (reqp->part_buf != NULL)
		free(reqp->part_buf);
	if (!avl_root_empty(&reqp->items))
		free_pkb_tree(&reqp->items, NULL);
	free(reqp);
}

int
server_context_getwork(server_context_t *ctxp)
{
	CURLcode res;
	server_request_t *reqp;
	CURL *creq;

	reqp = (server_request_t *) malloc(sizeof(*reqp));
	memset(reqp, 0, sizeof(*reqp));

	reqp->group = EC_KEY_get0_group(ctxp->dummy_key);

	creq = curl_easy_init();
	if (curl_easy_setopt(creq, CURLOPT_URL, ctxp->getwork) ||
	    curl_easy_setopt(creq, CURLOPT_VERBOSE, ctxp->verbose > 1) ||
	    curl_easy_setopt(creq, CURLOPT_WRITEFUNCTION,
			     server_body_reader) ||
	    curl_easy_setopt(creq, CURLOPT_FOLLOWLOCATION, 1) ||
	    curl_easy_setopt(creq, CURLOPT_WRITEDATA, reqp)) {
		fprintf(stderr, "Failed to set up libcurl\n");
		exit(1);
	}

	res = curl_easy_perform(creq);
	curl_easy_cleanup(creq);

	if (res != CURLE_OK) {
		fprintf(stderr, "Get work request failed: %s\n",
			curl_easy_strerror(res));
		server_request_free(reqp);
		return -1;
	}

	ctxp->items.ar_root = reqp->items.ar_root;
	return 0;
}


int
server_context_submit_solution(server_context_t *ctxp,
			       workitem_t *work,
			       const char *privkey)
{
	char urlbuf[8192];
	char *pubhex;
	CURL *creq;
	CURLcode res;

	pubhex = EC_POINT_point2hex(EC_KEY_get0_group(ctxp->dummy_key),
				    work->pubkey,
				    POINT_CONVERSION_UNCOMPRESSED,
				    NULL);
	snprintf(urlbuf, sizeof(urlbuf),
		 "%s?key=%s%%3A%s&privateKey=%s&bitcoinAddress=%s",
		 ctxp->submit,
		 work->pattern,
		 pubhex,
		 privkey,
		 ctxp->credit_addr);
	OPENSSL_free(pubhex);
	creq = curl_easy_init();
	if (curl_easy_setopt(creq, CURLOPT_URL, urlbuf) ||
	    curl_easy_setopt(creq, CURLOPT_VERBOSE, ctxp->verbose > 1) ||
	    curl_easy_setopt(creq, CURLOPT_FOLLOWLOCATION, 1)) {
		fprintf(stderr, "Failed to set up libcurl\n");
		exit(1);
	}

	res = curl_easy_perform(creq);
	if (res != CURLE_OK) {
		fprintf(stderr, "Submission failed: %s\n",
			curl_easy_strerror(res));
		curl_easy_cleanup(creq);
		return -1;
	}

	curl_easy_cleanup(creq);
	return 0;
}

static pthread_mutex_t soln_lock;
static pthread_cond_t soln_cond;
static char *soln_pattern = NULL;
static char *soln_private_key = NULL;

void
free_soln()
{
	if (soln_pattern) {
		free(soln_pattern);
		soln_pattern = NULL;
	}
	if (soln_private_key) {
		OPENSSL_free(soln_private_key);
		soln_private_key = NULL;
	}
}

void
output_match_work_complete(vg_context_t *vcp, EC_KEY *pkey, const char *pattern)
{
	vg_output_match_console(vcp, pkey, pattern);
	pthread_mutex_lock(&soln_lock);
	free_soln();
	soln_pattern = strdup(pattern);
	soln_private_key = BN_bn2hex(EC_KEY_get0_private_key(pkey));

	/* Signal the generator to stop */
	vcp->vc_halt = 1;

	/* Wake up the main thread, if it's sleeping */
	pthread_cond_broadcast(&soln_cond);
	pthread_mutex_unlock(&soln_lock);
}

int
check_solution(server_context_t *scp, pubkeybatch_t *pbatch)
{
	int res = 0;
	pthread_mutex_lock(&soln_lock);
	if (soln_private_key != NULL) {
		workitem_t *wip = workitem_avl_search(&pbatch->items,
						      soln_pattern);
		assert(wip != NULL);
		avl_remove(&pbatch->items, &wip->avlent);
		pbatch->nitems--;
		pbatch->total_value -= wip->value;
		server_context_submit_solution(scp, wip, soln_private_key);
		if (wip->pubkey == pbatch->pubkey)
			wip->pubkey = NULL;
		server_workitem_free(wip);
		free_soln();
		res = 1;
	}
	pthread_mutex_unlock(&soln_lock);
	return res;
}

pubkeybatch_t *
most_valuable_pkb(server_context_t *scp)
{
	pubkeybatch_t *pbatch, *res = NULL;
	for (pbatch = pubkeybatch_avl_first(&scp->items);
	     pbatch != NULL;
	     pbatch = pubkeybatch_avl_next(pbatch)) {
		if (!res || (res->total_value < pbatch->total_value))
			res = pbatch;
	}
	return res;
}

void
usage(const char *name)
{
	fprintf(stderr,
"oclVanityMiner %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s -u <URL> -a <credit address>\n"
"Organized vanity address mining client using OpenCL.  Contacts the specified\n"
"bounty pool server, downloads a list of active bounties, and attempts to\n"
"generate the address with the best difficulty to reward ratio.  Maintains\n"
"contact with the bounty pool server and periodically refreshes the bounty\n"
"list.\n"
"By default, if no device is specified, and the system has exactly one OpenCL\n"
"device, it will be selected automatically, otherwise if the system has\n"
"multiple OpenCL devices and no device is specified, an error will be\n"
"reported.  To use multiple devices simultaneously, specify the -D option for\n"
"each device.\n"
"\n"
"Options:\n"
"-u <URL>      Bounty pool URL\n"
"-a <address>  Credit address for completed work\n"
"-i <interval> Set server polling interval in seconds (default 90)\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-D <devstr>   Use OpenCL device, identified by device string\n"
"              Form: <platform>:<devicenumber>[,<options>]\n"
"              Example: 0:0,grid=1024x1024\n"
"-S            Safe mode, disable OpenCL loop unrolling optimizations\n"
"-w <worksize> Set work items per thread in a work unit\n"
"-t <threads>  Set target thread count per multiprocessor\n"
"-g <x>x<y>    Set grid size\n"
"-b <invsize>  Set modular inverse ops per thread\n"
"-V            Enable kernel/OpenCL/hardware verification (SLOW)\n",
version, name);
}

#define MAX_DEVS 32

int
main(int argc, char **argv)
{
	const char *url = NULL;
	const char *credit_addr = NULL;
	int opt;
	int platformidx = -1, deviceidx = -1;
	char *pend;
	int verbose = 1;
	int interval = 90;
	int nthreads = 0;
	int worksize = 0;
	int nrows = 0, ncols = 0;
	int invsize = 0;
	int verify_mode = 0;
	int safe_mode = 0;

	char *devstrs[MAX_DEVS];
	int ndevstrs = 0;

	vg_context_t *vcp = NULL;
	vg_ocl_context_t *vocp = NULL;

	int res;
	int thread_started = 0;
	pubkeybatch_t *active_pkb = NULL;
	float active_pkb_value = 0;

	server_context_t *scp = NULL;
	pubkeybatch_t *pkb;
	int was_sleeping = 0;

	struct timeval tv;
	struct timespec sleepy;

	pthread_mutex_init(&soln_lock, NULL);
	pthread_cond_init(&soln_cond, NULL);

	if (argc == 1) {
		usage(argv[0]);
		return 1;
	}

	while ((opt = getopt(argc, argv,
			     "u:a:vqp:d:w:t:g:b:VD:Sh?i:")) != -1) {
		switch (opt) {
		case 'u':
			url = optarg;
			break;
		case 'a':
			credit_addr = optarg;
			break;
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'i':
			interval = atoi(optarg);
			if (interval < 10) {
				fprintf(stderr,
					"Invalid interval '%s'\n", optarg);
				return 1;
			}
			break;
		case 'p':
			platformidx = atoi(optarg);
			break;
		case 'd':
			deviceidx = atoi(optarg);
			break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
				fprintf(stderr,
					"Invalid work size '%s'\n", optarg);
				return 1;
			}
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr,
					"Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'g':
			nrows = 0;
			ncols = strtol(optarg, &pend, 0);
			if (pend && *pend == 'x') {
				nrows = strtol(pend+1, NULL, 0);
			}
			if (!nrows || !ncols) {
				fprintf(stderr,
					"Invalid grid size '%s'\n", optarg);
				return 1;
			}
			break;
		case 'b':
			invsize = atoi(optarg);
			if (!invsize) {
				fprintf(stderr,
					"Invalid modular inverse size '%s'\n",
					optarg);
				return 1;
			}
			if (invsize & (invsize - 1)) {
				fprintf(stderr,
					"Modular inverse size must be "
					"a power of 2\n");
				return 1;
			}
			break;
		case 'V':
			verify_mode = 1;
			break;
		case 'S':
			safe_mode = 1;
			break;
		case 'D':
			if (ndevstrs >= MAX_DEVS) {
				fprintf(stderr,
					"Too many OpenCL devices (limit %d)\n",
					MAX_DEVS);
				return 1;
			}
			devstrs[ndevstrs++] = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		fprintf(stderr,
			"WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
			"WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif
	curl_easy_init();

	vcp = vg_prefix_context_new(0, 128, 0);

	vcp->vc_verbose = verbose;

	vcp->vc_output_match = output_match_work_complete;
	vcp->vc_output_timing = vg_output_timing_console;


	if (!url) {
		fprintf(stderr, "ERROR: No server URL specified\n");
		return 1;
	}
	if (!credit_addr) {
		fprintf(stderr, "ERROR: No reward address specified\n");
		return 1;
	}
	if (!vg_b58_decode_check(credit_addr, NULL, 0)) {
		fprintf(stderr, "ERROR: Invalid reward address specified\n");
		return 1;
	}

	scp = server_context_new(url, credit_addr);
	scp->verbose = verbose;

	/* Get the initial bounty list, abort on failure */
	if (server_context_getwork(scp))
		return 1;

	/* Set up OpenCL */
	res = 0;
	if (ndevstrs) {
		for (opt = 0; opt < ndevstrs; opt++) {
			vocp = vg_ocl_context_new_from_devstr(vcp, devstrs[opt],
							      safe_mode,
							      verify_mode);
			if (!vocp) {
				fprintf(stderr,
				"Could not open device '%s', ignoring\n",
					devstrs[opt]);
			} else {
				res++;
			}
		}
	} else {
		vocp = vg_ocl_context_new(vcp, platformidx, deviceidx,
					  safe_mode, verify_mode,
					  worksize, nthreads,
					  nrows, ncols, invsize);
		if (vocp)
			res++;
	}
	if (!res) {
		vg_ocl_enumerate_devices();
		return 1;
	}

	if (verbose > 1)
		dump_work(&scp->items);

	while (1) {
		if (avl_root_empty(&scp->items))
			server_context_getwork(scp);

		pkb = most_valuable_pkb(scp);

		/* If the work item is the same as the one we're executing,
		   keep it */
		if (pkb && active_pkb &&
		    server_pubkeybatch_equal(scp, active_pkb, pkb))
			pkb = active_pkb;

		if (thread_started && (!active_pkb || (pkb != active_pkb))) {
			/* If a thread is running, stop it */
			vg_context_stop_threads(vcp);
			thread_started = 0;
			if (active_pkb) {
				check_solution(scp, active_pkb);
				active_pkb = NULL;
			}
			vg_context_clear_all_patterns(vcp);

			if (verbose > 1)
				dump_work(&scp->items);
		}

		if (!pkb) {
			if (!was_sleeping) {
				fprintf(stderr,
					"No work available, sleeping\n");
				was_sleeping = 1;
			}

		} else if (!active_pkb) {
			workitem_t *wip;
			was_sleeping = 0;
			active_pkb_value = 0;
			vcp->vc_pubkey_base = pkb->pubkey;
			for (wip = workitem_avl_first(&pkb->items);
			     wip != NULL;
			     wip = workitem_avl_next(wip)) {
				fprintf(stderr,
					"Searching for pattern: \"%s\" "
					"Reward: %f Value: %f BTC/Gkey\n",
					wip->pattern,
					wip->reward,
					wip->value);
				vcp->vc_addrtype = wip->addrtype;
				if (!vg_context_add_patterns(vcp,
							     &wip->pattern,
							     1)) {
					fprintf(stderr,
					   "WARNING: could not add pattern\n");
				}
				else {
					active_pkb_value += wip->value;
				}
				
				assert(vcp->vc_npatterns);
			}

			fprintf(stderr, 
				"\nTotal value for current work: %f BTC/Gkey\n", 
				active_pkb_value);
			res = vg_context_start_threads(vcp);
			if (res)
				return 1;
			thread_started = 1;
			active_pkb = pkb;
		}

		/* Wait for something to happen */
		gettimeofday(&tv, NULL);
		sleepy.tv_sec = tv.tv_sec;
		sleepy.tv_nsec = tv.tv_usec * 1000;
		sleepy.tv_sec += interval;

		pthread_mutex_lock(&soln_lock);
		res = 0;
		if (!soln_private_key)
			res = pthread_cond_timedwait(&soln_cond,
						     &soln_lock, &sleepy);
		pthread_mutex_unlock(&soln_lock);

		if (res == 0) {
			if (check_solution(scp, active_pkb))
				active_pkb = NULL;
		}
		else if (res == ETIMEDOUT) {
			free_pkb_tree(&scp->items, active_pkb);
		}
	}

	return 0;
}
