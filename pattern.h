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


typedef struct _vg_context_s vg_context_t;

/* Context of one pattern-matching unit within the process */
typedef struct _vg_exec_context_s {
	vg_context_t			*vxc_vc;
	BN_CTX				*vxc_bnctx;
	EC_KEY				*vxc_key;
	int				vxc_delta;
	unsigned char			vxc_binres[28];
	BIGNUM				vxc_bntarg;
	BIGNUM				vxc_bnbase;
	BIGNUM				vxc_bntmp;
	BIGNUM				vxc_bntmp2;
} vg_exec_context_t;

/* Init/cleanup for common execution context */
extern int vg_exec_context_init(vg_context_t *vcp, vg_exec_context_t *vxcp);
extern void vg_exec_context_del(vg_exec_context_t *vxcp);
extern void vg_exec_context_consolidate_key(vg_exec_context_t *vxcp);
extern void vg_exec_context_calc_address(vg_exec_context_t *vxcp);

/* Implementation-specific lock/unlock/consolidate */
extern void vg_exec_downgrade_lock(vg_exec_context_t *vxcp);
extern int vg_exec_upgrade_lock(vg_exec_context_t *vxcp);


typedef void (*vg_free_func_t)(vg_context_t *);
typedef int (*vg_add_pattern_func_t)(vg_context_t *,
				     char ** const patterns, int npatterns);
typedef int (*vg_test_func_t)(vg_exec_context_t *);
typedef int (*vg_hash160_sort_func_t)(vg_context_t *vcp, void *buf);

/* Application-level context, incl. parameters and global pattern store */
struct _vg_context_s {
	int			vc_addrtype;
	int			vc_privtype;
	unsigned long		vc_npatterns;
	unsigned long		vc_npatterns_start;
	unsigned long long	vc_found;
	double			vc_chance;
	const char		*vc_result_file;
	const char		*vc_key_protect_pass;
	int			vc_remove_on_match;
	int			vc_verbose;
	vg_free_func_t		vc_free;
	vg_add_pattern_func_t	vc_add_patterns;
	vg_test_func_t		vc_test;
	vg_hash160_sort_func_t	vc_hash160_sort;
};


extern void vg_context_free(vg_context_t *vcp);
extern int vg_context_add_patterns(vg_context_t *vcp,
				   char ** const patterns, int npatterns);
extern int vg_context_hash160_sort(vg_context_t *vcp, void *buf);


extern vg_context_t *vg_prefix_context_new(int addrtype, int privtype,
					   int caseinsensitive);
extern vg_context_t *vg_regex_context_new(int addrtype, int privtype);

extern int vg_output_timing(vg_context_t *vcp, int cycle, struct timeval *last);
extern void vg_output_match(vg_context_t *vcp, EC_KEY *pkey,
			    const char *pattern);

#endif /* !defined (__VG_PATTERN_H__) */
