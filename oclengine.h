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

#if !defined (__VG_OCLENGINE_H__)
#define __VG_OCLENGINE_H__

#include "pattern.h"

typedef struct _vg_ocl_context_s vg_ocl_context_t;

extern vg_ocl_context_t *vg_ocl_context_new(
	vg_context_t *vcp, int platformidx, int deviceidx,
	int safe_mode, int verify,
	int worksize, int nthreads, int nrows, int ncols,
	int invsize);
extern void vg_ocl_context_free(vg_ocl_context_t *vocp);

extern vg_ocl_context_t *vg_ocl_context_new_from_devstr(
	vg_context_t *vcp, const char *devstr, int safemode, int verify)
;

extern void vg_ocl_enumerate_devices(void);

#endif /* !defined (__VG_OCLENGINE_H__) */
