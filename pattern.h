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

#if !defined (__VG_PATTERN_H__)
#define __VG_PATTERN_H__

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <pthread.h>

#ifdef _WIN32
#include "winglue.h"
#else
#define INLINE inline
#define PRSIZET "z"
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#endif

#define VANITYGEN_VERSION "0.22"

typedef struct _vg_context_s vg_context_t;

struct _vg_exec_context_s;
typedef struct _vg_exec_context_s vg_exec_context_t;

typedef void *(*vg_exec_context_threadfunc_t)(vg_exec_context_t *);

/* Context of one pattern-matching unit within the process */
struct _vg_exec_context_s {
	vg_context_t			*vxc_vc;
	BN_CTX				*vxc_bnctx;
	EC_KEY				*vxc_key;
	int				vxc_delta;
	unsigned char			vxc_binres[28];
	BIGNUM				vxc_bntarg;
	BIGNUM				vxc_bnbase;
	BIGNUM				vxc_bntmp;
	BIGNUM				vxc_bntmp2;

	vg_exec_context_threadfunc_t	vxc_threadfunc;
	pthread_t			vxc_pthread;
	int				vxc_thread_active;

	/* Thread synchronization */
	struct _vg_exec_context_s	*vxc_next;
	int				vxc_lockmode;
	int				vxc_stop;
};


typedef void (*vg_free_func_t)(vg_context_t *);
typedef int (*vg_add_pattern_func_t)(vg_context_t *,
				     const char ** const patterns,
				     int npatterns);
typedef void (*vg_clear_all_patterns_func_t)(vg_context_t *);
typedef int (*vg_test_func_t)(vg_exec_context_t *);
typedef int (*vg_hash160_sort_func_t)(vg_context_t *vcp, void *buf);
typedef void (*vg_output_error_func_t)(vg_context_t *vcp, const char *info);
typedef void (*vg_output_match_func_t)(vg_context_t *vcp, EC_KEY *pkey,
				       const char *pattern);
typedef void (*vg_output_timing_func_t)(vg_context_t *vcp, double count,
					unsigned long long rate,
					unsigned long long total);

enum vg_format {
	VCF_PUBKEY,
	VCF_SCRIPT,
};

/* Application-level context, incl. parameters and global pattern store */
struct _vg_context_s {
	int			vc_addrtype;
	int			vc_privtype;
	unsigned long		vc_npatterns;
	unsigned long		vc_npatterns_start;
	unsigned long long	vc_found;
	int			vc_pattern_generation;
	double			vc_chance;
	const char		*vc_result_file;
	const char		*vc_key_protect_pass;
	int			vc_remove_on_match;
	int			vc_only_one;
	int			vc_verbose;
	enum vg_format		vc_format;
	int			vc_pubkeytype;
	EC_POINT		*vc_pubkey_base;
	int			vc_halt;

	vg_exec_context_t	*vc_threads;
	int			vc_thread_excl;

	/* Internal methods */
	vg_free_func_t			vc_free;
	vg_add_pattern_func_t		vc_add_patterns;
	vg_clear_all_patterns_func_t	vc_clear_all_patterns;
	vg_test_func_t			vc_test;
	vg_hash160_sort_func_t		vc_hash160_sort;

	/* Performance related members */
	unsigned long long		vc_timing_total;
	unsigned long long		vc_timing_prevfound;
	unsigned long long		vc_timing_sincelast;
	struct _timing_info_s		*vc_timing_head;

	/* External methods */
	vg_output_error_func_t		vc_output_error;
	vg_output_match_func_t		vc_output_match;
	vg_output_timing_func_t		vc_output_timing;
};


/* Base context methods */
extern void vg_context_free(vg_context_t *vcp);
extern int vg_context_add_patterns(vg_context_t *vcp,
				   const char ** const patterns, int npatterns);
extern void vg_context_clear_all_patterns(vg_context_t *vcp);
extern int vg_context_start_threads(vg_context_t *vcp);
extern void vg_context_stop_threads(vg_context_t *vcp);
extern void vg_context_wait_for_completion(vg_context_t *vcp);

/* Prefix context methods */
extern vg_context_t *vg_prefix_context_new(int addrtype, int privtype,
					   int caseinsensitive);
extern void vg_prefix_context_set_case_insensitive(vg_context_t *vcp,
						   int caseinsensitive);
extern double vg_prefix_get_difficulty(int addrtype, const char *pattern);

/* Regex context methods */
extern vg_context_t *vg_regex_context_new(int addrtype, int privtype);

/* Utility functions */
extern int vg_output_timing(vg_context_t *vcp, int cycle, struct timeval *last);
extern void vg_output_match_console(vg_context_t *vcp, EC_KEY *pkey,
				    const char *pattern);
extern void vg_output_timing_console(vg_context_t *vcp, double count,
				     unsigned long long rate,
				     unsigned long long total);



/* Internal vg_context methods */
extern int vg_context_hash160_sort(vg_context_t *vcp, void *buf);
extern void vg_context_thread_exit(vg_context_t *vcp);

/* Internal Init/cleanup for common execution context */
extern int vg_exec_context_init(vg_context_t *vcp, vg_exec_context_t *vxcp);
extern void vg_exec_context_del(vg_exec_context_t *vxcp);
extern void vg_exec_context_consolidate_key(vg_exec_context_t *vxcp);
extern void vg_exec_context_calc_address(vg_exec_context_t *vxcp);
extern EC_KEY *vg_exec_context_new_key(void);

/* Internal execution context lock handling functions */
extern void vg_exec_context_downgrade_lock(vg_exec_context_t *vxcp);
extern int vg_exec_context_upgrade_lock(vg_exec_context_t *vxcp);
extern void vg_exec_context_yield(vg_exec_context_t *vxcp);


#endif /* !defined (__VG_PATTERN_H__) */
