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

#include <CL/cl.h>

#include "pattern.h"


const char *version = "0.13";

#define MAX_SLOT 2

typedef struct _vg_ocl_context_s {
	vg_exec_context_t		base;
	cl_device_id			voc_ocldid;
	cl_context			voc_oclctx;
	cl_command_queue		voc_oclcmdq;
	cl_program			voc_oclprog;
	cl_kernel			voc_oclkernel[MAX_SLOT][3];
	cl_event			voc_oclkrnwait[MAX_SLOT];
	cl_mem				voc_args[MAX_SLOT][6];
	size_t				voc_arg_size[MAX_SLOT][6];

	pthread_t			voc_ocl_thread;
	pthread_mutex_t			voc_lock;
	pthread_cond_t			voc_wait;
	int				voc_ocl_slot;
	int				voc_ocl_rows;
	int				voc_ocl_cols;
	int				voc_halt;
	int				voc_rekey;
} vg_ocl_context_t;


/* Thread synchronization stubs */
void
vg_exec_downgrade_lock(vg_exec_context_t *vxcp)
{
}

int
vg_exec_upgrade_lock(vg_exec_context_t *vxcp)
{
	return 0;
}


/*
 * OpenCL per-exec functions
 */

int
vg_ocl_create_kernel(vg_ocl_context_t *vocp, int knum, const char *func)
{
	int i;
	cl_kernel krn;
	cl_int ret;

	for (i = 0; i < MAX_SLOT; i++) {
		krn = clCreateKernel(vocp->voc_oclprog, func, &ret);
		if (!krn) {
			printf("clCreateKernel(%d): %d\n", i, ret);
			while (--i >= 0) {
				clReleaseKernel(vocp->voc_oclkernel[i][knum]);
				vocp->voc_oclkernel[i][knum] = NULL;
			}
			return 0;
		}
		vocp->voc_oclkernel[i][knum] = krn;
		vocp->voc_oclkrnwait[i] = NULL;
	}
	return 1;
}

int
vg_ocl_load_program(vg_context_t *vcp, vg_ocl_context_t *vocp,
		    const char *filename, const char *opts)
{
	FILE *kfp;
	char *buf;
	int len;
	size_t sz;
	cl_program prog;
	cl_int ret;

	buf = (char *) malloc(128 * 1024);
	if (!buf)
		return 0;

	kfp = fopen(filename, "r");
	if (!kfp) {
		printf("Error loading CL kernel: %s\n", strerror(errno));
		free(buf);
		return 0;
	}

	len = fread(buf, 1, 128 * 1024, kfp);
	fclose(kfp);

	sz = len;
	prog = clCreateProgramWithSource(vocp->voc_oclctx,
					 1, (const char **) &buf, &sz,
					 &ret);
	free(buf);
	if (!prog) {
		printf("clCreateProgramWithSource: %d\n", ret);
		return 0;
	}

	if (vcp->vc_verbose > 0) {
		printf("Compiling kernel...");
		fflush(stdout);
	}
	ret = clBuildProgram(prog, 1, &vocp->voc_ocldid, opts, NULL, NULL);
	if (ret != CL_SUCCESS) {
		if (vcp->vc_verbose > 0)
			printf("failure.\n");
		printf("clBuildProgram: %d\n", ret);
	} else if (vcp->vc_verbose > 0) {
		printf("done!\n");
	}
	if ((ret != CL_SUCCESS) || (vcp->vc_verbose > 1)) {
		const size_t logbufsize = 1024 * 16;
		char *log = (char*) malloc(logbufsize);
		size_t logsize;
		cl_int ret2;

		ret2 = clGetProgramBuildInfo(prog,
					    vocp->voc_ocldid,
					    CL_PROGRAM_BUILD_LOG,
					    logbufsize,
					    log,
					    &logsize);
		if (ret2 != CL_SUCCESS) {
			printf("clGetProgramBuildInfo: %d\n", ret2);
		} else {
			printf("Build log:%s\n", log);
		}
		free(log);
	}
	if (ret != CL_SUCCESS) {
		clReleaseProgram(prog);
		return 0;
	}

	vocp->voc_oclprog = prog;
	if (!vg_ocl_create_kernel(vocp, 0, "ec_add_grid") ||
	    !vg_ocl_create_kernel(vocp, 1, "heap_invert") ||
	    !vg_ocl_create_kernel(vocp, 2, "hash_ec_point")) {
		clReleaseProgram(vocp->voc_oclprog);
		vocp->voc_oclprog = NULL;
		return 0;
	}

	return 1;
}

void
vg_ocl_context_callback(const char *errinfo,
			const void *private_info,
			size_t cb,
			void *user_data)
{
	printf("vg_ocl_context_callback error: %s\n", errinfo);
}

int
vg_ocl_init(vg_context_t *vcp, vg_ocl_context_t *vocp, cl_device_id did)
{
	cl_int ret;

	memset(vocp, 0, sizeof(*vocp));
	vg_exec_context_init(vcp, &vocp->base);

	pthread_mutex_init(&vocp->voc_lock, NULL);
	pthread_cond_init(&vocp->voc_wait, NULL);
	vocp->voc_ocl_slot = -1;

	vocp->voc_ocldid = did;
	vocp->voc_oclctx = clCreateContext(NULL,
					   1, &did,
					   vg_ocl_context_callback,
					   NULL,
					   &ret);
	if (!vocp->voc_oclctx) {
		printf("clCreateContext failed: %d\n", ret);
		return 0;
	}

	vocp->voc_oclcmdq = clCreateCommandQueue(vocp->voc_oclctx,
						 vocp->voc_ocldid,
						 0, &ret);
	if (!vocp->voc_oclcmdq) {
		printf("clCreateCommandQueue failed: %d\n", ret);
		return 0;
	}

	if (!vg_ocl_load_program(vcp, vocp,
				 "calc_addrs.cl",
				 //"-cl-nv-verbose -cl-nv-maxrregcount=32 "
				 "-DUNROLL_MAX=16")) {
		printf("Could not load kernel\n");
		return 0;
	}
	return 1;
}

void
vg_ocl_del(vg_ocl_context_t *vocp)
{
	if (vocp->voc_oclprog) {
		clReleaseProgram(vocp->voc_oclprog);
		vocp->voc_oclprog = NULL;
	}
	if (vocp->voc_oclcmdq) {
		clReleaseCommandQueue(vocp->voc_oclcmdq);
		vocp->voc_oclcmdq = NULL;
	}
	if (vocp->voc_oclctx) {
		clReleaseContext(vocp->voc_oclctx);
		vocp->voc_oclctx = NULL;
	}
	pthread_cond_destroy(&vocp->voc_wait);
	pthread_mutex_destroy(&vocp->voc_lock);
	vg_exec_context_del(&vocp->base);
}

int
vg_ocl_kernel_arg_alloc(vg_ocl_context_t *vocp, int slot,
			int arg, size_t size, int host)
{
	cl_mem clbuf;
	cl_int ret;
	int i, j, knum, karg;

	static int arg_map[5][8] = {
		/* hashes_out */
		{ 2, 0, -1 },
		/* z_heap */
		{ 0, 1, 1, 0, 2, 2, -1 },
		/* point_tmp */
		{ 0, 0, 2, 1, -1 },
		/* row_in */
		{ 0, 2, -1 },
		/* col_in */
		{ 0, 3, -1 },
	};

	clbuf = clCreateBuffer(vocp->voc_oclctx,
			       CL_MEM_READ_WRITE |
			       (host ? CL_MEM_ALLOC_HOST_PTR : 0),
			       size,
			       NULL,
			       &ret);
	if (!clbuf) {
		printf("Could not create argument buffer: %d\n", ret);
		return 0;
	}

	for (i = 0; i < MAX_SLOT; i++) {
		if ((i != slot) && (slot >= 0))
			continue;

		for (j = 0; arg_map[arg][j] >= 0; j += 2) {
			knum = arg_map[arg][j];
			karg = arg_map[arg][j+1];
			ret = clSetKernelArg(vocp->voc_oclkernel[i][knum],
					     karg,
					     sizeof(clbuf),
					     &clbuf);
			
			if (ret) {
				clReleaseMemObject(clbuf);
				printf("Could not set kernel argument: %d\n",
				       ret);
				return 0;
			}
		}
		vocp->voc_args[i][arg] = clbuf;
		vocp->voc_arg_size[i][arg] = size;
	}
	return 1;
}

void *
vg_ocl_map_arg_buffer(vg_ocl_context_t *vocp, int slot,
		      int arg, int rw)
{
	void *buf;
	cl_int ret;

	assert((slot >= 0) && (slot < MAX_SLOT));

	buf = clEnqueueMapBuffer(vocp->voc_oclcmdq,
				 vocp->voc_args[slot][arg],
				 CL_TRUE,
				 rw ? CL_MAP_WRITE : CL_MAP_READ,
				 0, vocp->voc_arg_size[slot][arg],
				 0, NULL,
				 NULL,
				 &ret);
	if (!buf) {
		printf("Could not map argument buffer: %d\n", ret);
		return NULL;
	}
	return buf;
}

void
vg_ocl_unmap_arg_buffer(vg_ocl_context_t *vocp, int slot,
			int arg, void *buf)
{
	cl_int ret;
	cl_event ev;

	assert((slot >= 0) && (slot < MAX_SLOT));

	ret = clEnqueueUnmapMemObject(vocp->voc_oclcmdq,
				      vocp->voc_args[slot][arg],
				      buf,
				      0, NULL,
				      &ev);
	if (ret != CL_SUCCESS) {
		printf("Could not unmap buffer: %d\n", ret);
		return;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		printf("Error waiting for event: %d\n", ret);
	}
}

int
vg_ocl_kernel_int_arg(vg_ocl_context_t *vocp, int slot,
		      int arg, int value)
{
	cl_int ret;
	int i;

	for (i = 0; i < MAX_SLOT; i++) {
		if ((i != slot) && (slot >= 0))
			continue;
		ret = clSetKernelArg(vocp->voc_oclkernel[i][0],
				     arg,
				     sizeof(value),
				     &value);
		if (ret) {
			printf("Could not set kernel argument: %d\n",
			       ret);
			return 0;
		}
	}
	return 1;
}

int
vg_ocl_kernel_dead(vg_ocl_context_t *vocp, int slot)
{
	return (vocp->voc_oclkrnwait[slot] == NULL);
}

int
vg_ocl_kernel_start(vg_ocl_context_t *vocp, int slot, int ncol, int nrow)
{
	cl_int val, ret;
	cl_event ev;
	size_t globalws[2] = { ncol, nrow };

	assert(!vocp->voc_oclkrnwait[slot]);

	val = ncol;
	ret = clSetKernelArg(vocp->voc_oclkernel[slot][1],
			     1,
			     sizeof(val),
			     &val);
	if (ret != CL_SUCCESS) {
		printf("Could not set column count for 2nd kernel: %d\n", ret);
		return 0;
	}
	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][0],
				     2,
				     NULL, globalws, NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		printf("Could not queue 1st kernel: %d\n", ret);
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		printf("Error waiting for 1st kernel: %d\n", ret);
		return 0;
	}

	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][1],
				     1,
				     NULL, &globalws[1], NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		printf("Could not queue 2nd kernel: %d\n", ret);
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		printf("Error waiting for 2nd kernel: %d\n", ret);
		return 0;
	}

	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][2],
				     2,
				     NULL, globalws, NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		printf("Could not queue 3rd kernel: %d\n", ret);
		return 0;
	}

	vocp->voc_oclkrnwait[slot] = ev;
	return 1;
}

int
vg_ocl_kernel_wait(vg_ocl_context_t *vocp, int slot)
{
	cl_event ev;
	cl_int ret;

	ev = vocp->voc_oclkrnwait[slot];
	vocp->voc_oclkrnwait[slot] = NULL;
	if (ev) {
		ret = clWaitForEvents(1, &ev);
		clReleaseEvent(ev);
		if (ret != CL_SUCCESS) {
			printf("Error waiting for event: %d\n", ret);
			return 0;
		}
	}
	return 1;
}


/*
 * Absolutely disgusting.
 * We want points in Montgomery form, and it's a lot easier to read the
 * coordinates from the structure than to export and re-montgomeryize.
 */

struct ec_point_st {
	const EC_METHOD *meth;
	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z;
	int Z_is_one;
};

INLINE void
vg_ocl_put_point(unsigned char *buf, EC_POINT *ppnt)
{
	assert(ppnt->Z_is_one);
	memcpy(buf, ppnt->X.d, 32);
	memcpy(buf + 32, ppnt->Y.d, 32);
}

void
show_elapsed(struct timeval *tv, const char *place)
{
	struct timeval now, delta;
        gettimeofday(&now, NULL);
	timersub(&now, tv, &delta);
	printf("%s spent %ld.%06lds\n", place, delta.tv_sec, delta.tv_usec);
}

void *
vg_opencl_thread(void *arg)
{
	vg_ocl_context_t *vocp = (vg_ocl_context_t *) arg;
	vg_context_t *vcp = vocp->base.vxc_vc;
	int halt = 0;
	int slot = -1;
	int rows, cols;
	unsigned long long idleu, busyu;
	double pidle;
	struct timeval tv, tvt, tvd, idle, busy;

	memset(&idle, 0, sizeof(idle));
	memset(&busy, 0, sizeof(busy));

	while (1) {
		pthread_mutex_lock(&vocp->voc_lock);
		if (halt) {
			halt = 0;
			vocp->voc_halt = 1;
		}
		if (slot != -1) {
			assert(vocp->voc_ocl_slot == slot);
			vocp->voc_ocl_slot = -1;
			slot = -1;
			pthread_cond_signal(&vocp->voc_wait);
		}
		if (vocp->voc_halt)
			break;
		if (vocp->voc_ocl_slot == -1) {
			gettimeofday(&tv, NULL);
			while (vocp->voc_ocl_slot == -1) {
				pthread_cond_wait(&vocp->voc_wait,
						  &vocp->voc_lock);
				if (vocp->voc_halt)
					goto out;
			}
			gettimeofday(&tvt, NULL);
			timersub(&tvt, &tv, &tvd);
			timeradd(&tvd, &idle, &idle);
		}
		assert(!vocp->voc_rekey);
		assert(!vocp->voc_halt);
		slot = vocp->voc_ocl_slot;
		rows = vocp->voc_ocl_rows;
		cols = vocp->voc_ocl_cols;
		pthread_mutex_unlock(&vocp->voc_lock);

		gettimeofday(&tv, NULL);
		if (!vg_ocl_kernel_start(vocp, slot, cols, rows))
			halt = 1;

		if (!vg_ocl_kernel_wait(vocp, slot))
			halt = 1;
		gettimeofday(&tvt, NULL);
		timersub(&tvt, &tv, &tvd);
		timeradd(&tvd, &busy, &busy);

		if ((vcp->vc_verbose > 1) &&
		    ((busy.tv_sec + idle.tv_sec) > 1)) {
			idleu = (1000000 * idle.tv_sec) + idle.tv_usec;
			busyu = (1000000 * busy.tv_sec) + busy.tv_usec;
			pidle = ((double) idleu) / (idleu + busyu);

			if (pidle > 0.05) {
				printf("\rGPU idle: %.2f%%"
				       "                              "
				       "                                \n",
				       100 * pidle);
			}
			memset(&idle, 0, sizeof(idle));
			memset(&busy, 0, sizeof(busy));
		}
	}
out:
	pthread_mutex_unlock(&vocp->voc_lock);
	return NULL;
}

/*
 * Address search thread main loop
 */

void *
vg_opencl_loop(vg_context_t *vcp, cl_device_id did, int worksize)
{
	int i;
	int batchsize, round;

	const BN_ULONG rekey_max = 100000000;
	BN_ULONG npoints, rekey_at;

	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT **ppbase = NULL, **pprow, *pbatchinc = NULL, *poffset = NULL;
	EC_POINT *pseek = NULL;

	unsigned char *ocl_points_in, *ocl_strides_in, *ocl_hashes_out;

	vg_ocl_context_t ctx;
	vg_ocl_context_t *vocp = &ctx;
	vg_exec_context_t *vxcp = &vocp->base;
	vg_test_func_t test_func = vcp->vc_test;

	int slot, nslots;
	int slot_busy = 0, slot_done = 0, halt = 0;
	int c = 0, output_interval = 1000;

	struct timeval tvstart;

	if (!vg_ocl_init(vcp, &ctx, did))
		return NULL;

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	/*
	 * batchsize: number of points to process in each thread
	 * worksize: number of threads per kernel
	 * nslots: number of kernels
	 */

	batchsize = 256;
	if (!worksize)
		worksize = 4096;
	nslots = 2;
	slot = 0;

	ppbase = (EC_POINT **) malloc((batchsize + worksize) *
				      sizeof(EC_POINT*));
	if (!ppbase)
		goto enomem;

	for (i = 0; i < (batchsize + worksize); i++) {
		ppbase[i] = EC_POINT_new(pgroup);
		if (!ppbase[i])
			goto enomem;
	}

	pprow = ppbase + batchsize;
	pbatchinc = EC_POINT_new(pgroup);
	poffset = EC_POINT_new(pgroup);
	pseek = EC_POINT_new(pgroup);
	if (!pbatchinc || !poffset || !pseek)
		goto enomem;

	BN_set_word(&vxcp->vxc_bntmp, batchsize);
	EC_POINT_mul(pgroup, pbatchinc, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	BN_set_word(&vxcp->vxc_bntmp, worksize * batchsize);
	EC_POINT_mul(pgroup, poffset, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, poffset, vxcp->vxc_bnctx);

	round = batchsize * worksize;

	for (i = 0; i < nslots; i++) {
		/*
		 * Each work group gets its own:
		 * - Hash output array
		 * - Point and z_heap scratch spaces
		 * - Column point array
		 */
		if (!vg_ocl_kernel_arg_alloc(vocp, i, 0, 20 * round, 1) ||
		    !vg_ocl_kernel_arg_alloc(vocp, i, 1, 32 * 2 * round, 0) ||
		    !vg_ocl_kernel_arg_alloc(vocp, i, 2, 32 * 2 * round, 0) ||
		    !vg_ocl_kernel_arg_alloc(vocp, i, 4, 32 * 2 * worksize, 1))
			goto enomem;
	}

	/* Same row point array for all instances */
	if (!vg_ocl_kernel_arg_alloc(vocp, -1, 3, 32 * 2 * batchsize, 1))
		goto enomem;

	//vg_ocl_kernel_int_arg(vocp, -1, 5, batchsize);

	npoints = 0;
	rekey_at = 0;
	vxcp->vxc_binres[0] = vcp->vc_addrtype;

	if (pthread_create(&vocp->voc_ocl_thread, NULL,
			   vg_opencl_thread, vocp))
		goto enomem;

	gettimeofday(&tvstart, NULL);

l_rekey:
	/* Generate a new random private key */
	EC_KEY_generate_key(pkey);
	npoints = 0;

	/* Determine rekey interval */
	EC_GROUP_get_order(pgroup, &vxcp->vxc_bntmp, vxcp->vxc_bnctx);
	BN_sub(&vxcp->vxc_bntmp2,
	       &vxcp->vxc_bntmp,
	       EC_KEY_get0_private_key(pkey));
	rekey_at = BN_get_word(&vxcp->vxc_bntmp2);
	if ((rekey_at == BN_MASK2) || (rekey_at > rekey_max))
		rekey_at = rekey_max;
	assert(rekey_at > 0);

	EC_POINT_copy(ppbase[0], EC_KEY_get0_public_key(pkey));

	/* Build the base array of sequential points */
	for (i = 1; i < batchsize; i++) {
		EC_POINT_add(pgroup,
			     ppbase[i],
			     ppbase[i-1],
			     pgen, vxcp->vxc_bnctx);
	}

	EC_POINTs_make_affine(pgroup, batchsize, ppbase,
			      vxcp->vxc_bnctx);

	/* Fill the sequential point array */
	ocl_points_in = (unsigned char *)
		vg_ocl_map_arg_buffer(vocp, 0, 3, 1);
	if (!ocl_points_in)
		goto enomem;
	for (i = 0; i < batchsize; i++)
		vg_ocl_put_point(ocl_points_in + (64*i), ppbase[i]);
	vg_ocl_unmap_arg_buffer(vocp, 0, 3, ocl_points_in);

	/*
	 * Set up the initial row increment table.
	 * Set the first element to pgen -- effectively
	 * skipping the exact key generated above.
	 */
	EC_POINT_copy(pprow[0], pgen);
	for (i = 1; i < worksize; i++) {
		EC_POINT_add(pgroup,
			     pprow[i],
			     pprow[i-1],
			     pbatchinc, vxcp->vxc_bnctx);
	}
	EC_POINTs_make_affine(pgroup, worksize, pprow, vxcp->vxc_bnctx);
	vxcp->vxc_delta = 1;
	npoints = 1;
	slot = 0;
	slot_busy = 0;
	slot_done = 0;

	while (1) {
		if (slot_done) {
			slot_done = 0;

			ocl_hashes_out = (unsigned char *)
				vg_ocl_map_arg_buffer(vocp, slot, 0, 0);

			for (i = 0; i < round; i++, vxcp->vxc_delta++) {
				memcpy(&vxcp->vxc_binres[1],
				       ocl_hashes_out + (20*i),
				       20);

				switch (test_func(vxcp)) {
				case 1:
					rekey_at = 0;
					i = round;
					break;
				case 2:
					halt = 1;
					i = round;
					break;
				default:
					break;
				}
			}

			vg_ocl_unmap_arg_buffer(vocp, slot, 0, ocl_hashes_out);

			c += (i + 1);
			if (!halt && (c >= output_interval)) {
				output_interval =
					vg_output_timing(vcp, c, &tvstart);
				c = 0;
			}
		}

		if (halt) {
			if (vcp->vc_verbose > 1)
				printf("Halting...");
			pthread_mutex_lock(&vocp->voc_lock);
			vocp->voc_halt = 1;
			pthread_cond_signal(&vocp->voc_wait);
			while (vocp->voc_ocl_slot != -1) {
				assert(slot_busy);
				pthread_cond_wait(&vocp->voc_wait,
						  &vocp->voc_lock);
			}
			slot_busy = 0;
			pthread_mutex_unlock(&vocp->voc_lock);
			pthread_join(vocp->voc_ocl_thread, NULL);
			if (vcp->vc_verbose > 1)
				printf("done!\n");
			break;
		}

		if ((npoints + round) < rekey_at) {
			if (npoints > 1) {
				/* Move the row increments forward */
				for (i = 0; i < worksize; i++) {
					EC_POINT_add(pgroup,
						     pprow[i],
						     pprow[i],
						     poffset,
						     vxcp->vxc_bnctx);
				}

				EC_POINTs_make_affine(pgroup, worksize, pprow,
						      vxcp->vxc_bnctx);
			}

			/* Copy the row stride array to the device */
			ocl_strides_in = (unsigned char *)
				vg_ocl_map_arg_buffer(vocp, slot, 4, 1);
			if (!ocl_strides_in)
				goto enomem;
			memset(ocl_strides_in, 0, 64*worksize);
			for (i = 0; i < worksize; i++)
				vg_ocl_put_point(ocl_strides_in + (64*i),
						 pprow[i]);
			vg_ocl_unmap_arg_buffer(vocp, slot, 4, ocl_strides_in);
			npoints += round;

			pthread_mutex_lock(&vocp->voc_lock);
			while (vocp->voc_ocl_slot != -1) {
				assert(slot_busy);
				pthread_cond_wait(&vocp->voc_wait,
						  &vocp->voc_lock);
			}

			if (vocp->voc_halt) {
				halt = 1;
			} else {
				vocp->voc_ocl_slot = slot;
				vocp->voc_ocl_cols = batchsize;
				vocp->voc_ocl_rows = worksize;
				pthread_cond_signal(&vocp->voc_wait);
				pthread_mutex_unlock(&vocp->voc_lock);

				if (slot_busy)
					slot_done = 1;
				slot_busy = 1;
				slot = (slot + 1) % nslots;
			}
			pthread_mutex_unlock(&vocp->voc_lock);
		}

		else if (slot_busy) {
			pthread_mutex_lock(&vocp->voc_lock);
			while (vocp->voc_ocl_slot != -1) {
				pthread_cond_wait(&vocp->voc_wait,
						  &vocp->voc_lock);
			}
			slot_busy = 0;
			pthread_mutex_unlock(&vocp->voc_lock);
			slot_done = 1;
		}

		else if (!rekey_at || ((npoints + round) >= rekey_at)) {
			goto l_rekey;
		}
	}

	if (0) {
	enomem:
		printf("ERROR: allocation failure?\n");
	}

	if (ppbase) {
		for (i = 0; i < (batchsize + worksize); i++)
			if (ppbase[i])
				EC_POINT_free(ppbase[i]);
		free(ppbase);
	}
	if (pbatchinc)
		EC_POINT_free(pbatchinc);

	vg_ocl_del(vocp);

	return NULL;
}




/*
 * OpenCL platform/device selection junk
 */

int
get_device_list(cl_platform_id pid, cl_device_id **list_out)
{
	cl_uint nd;
	cl_int res;
	cl_device_id *ids;
	res = clGetDeviceIDs(pid, CL_DEVICE_TYPE_ALL, 0, NULL, &nd);
	if (res != CL_SUCCESS) {
		printf("clGetDeviceIDs(0) failed: %d\n", res);
		*list_out = NULL;
		return -1;
	}
	if (nd) {
		ids = (cl_device_id *) malloc(nd * sizeof(*ids));
		if (ids == NULL) {
			printf("Could not allocate device ID list\n");
			*list_out = NULL;
			return -1;
		}
		res = clGetDeviceIDs(pid, CL_DEVICE_TYPE_ALL, nd, ids, NULL);
		if (res != CL_SUCCESS) {
			printf("clGetDeviceIDs(n) failed: %d\n", res);
			free(ids);
			*list_out = NULL;
			return -1;
		}
		*list_out = ids;
	}
	return nd;
}

void
show_devices(cl_platform_id pid, cl_device_id *ids, int nd, int base)
{
	int i;
	char nbuf[128];
	char vbuf[128];
	size_t len;
	cl_int res;

	for (i = 0; i < nd; i++) {
		res = clGetDeviceInfo(ids[i], CL_DEVICE_NAME,
				      sizeof(nbuf), nbuf, &len);
		if (res != CL_SUCCESS)
			continue;
		if (len >= sizeof(nbuf))
			len = sizeof(nbuf) - 1;
		nbuf[len] = '\0';
		res = clGetDeviceInfo(ids[i], CL_DEVICE_VENDOR,
				      sizeof(vbuf), vbuf, &len);
		if (res != CL_SUCCESS)
			continue;
		if (len >= sizeof(vbuf))
			len = sizeof(vbuf) - 1;
		vbuf[len] = '\0';
		printf("  %d: [%s] %s\n", i + base, vbuf, nbuf);
	}
}

cl_device_id
get_device(cl_platform_id pid, int num)
{
	int nd;
	cl_device_id id, *ids;

	nd = get_device_list(pid, &ids);
	if (nd < 0)
		return NULL;
	if (!nd) {
		printf("No OpenCL devices found\n");
		return NULL;
	}
	if (num < 0) {
		if (nd == 1)
			num = 0;
		else
			num = nd;
	}
	if (num < nd) {
		id = ids[num];
		free(ids);
		return id;
	}
	free(ids);
	return NULL;
}

int
get_platform_list(cl_platform_id **list_out)
{
	cl_uint np;
	cl_int res;
	cl_platform_id *ids;
	res = clGetPlatformIDs(0, NULL, &np);
	if (res != CL_SUCCESS) {
		printf("clGetPlatformIDs(0) failed: %d\n", res);
		*list_out = NULL;
		return -1;
	}
	if (np) {
		ids = (cl_platform_id *) malloc(np * sizeof(*ids));
		if (ids == NULL) {
			printf("Could not allocate platform ID list\n");
			*list_out = NULL;
			return -1;
		}
		res = clGetPlatformIDs(np, ids, NULL);
		if (res != CL_SUCCESS) {
			printf("clGetPlatformIDs(n) failed: %d\n", res);
			free(ids);
			*list_out = NULL;
			return -1;
		}
		*list_out = ids;
	}
	return np;
}

void
show_platforms(cl_platform_id *ids, int np, int base)
{
	int i;
	char nbuf[128];
	char vbuf[128];
	size_t len;
	cl_int res;

	for (i = 0; i < np; i++) {
		res = clGetPlatformInfo(ids[i], CL_PLATFORM_NAME,
					sizeof(nbuf), nbuf, &len);
		if (res != CL_SUCCESS) {
			printf("Failed to enumerate platform ID: %d\n", res);
			continue;
		}
		if (len >= sizeof(nbuf))
			len = sizeof(nbuf) - 1;
		nbuf[len] = '\0';
		res = clGetPlatformInfo(ids[i], CL_PLATFORM_VENDOR,
					sizeof(vbuf), vbuf, &len);
		if (res != CL_SUCCESS) {
			printf("Failed to enumerate platform ID: %d\n", res);
			continue;
		}
		if (len >= sizeof(vbuf))
			len = sizeof(vbuf) - 1;
		vbuf[len] = '\0';
		printf("%d: [%s] %s\n", i + base, vbuf, nbuf);
	}
}

cl_platform_id
get_platform(int num)
{
	int np;
	cl_platform_id id, *ids;

	np = get_platform_list(&ids);
	if (np < 0)
		return NULL;
	if (!np) {
		printf("No OpenCL platforms available\n");
		return NULL;
	}
	if (num < 0) {
		if (np == 1)
			num = 0;
		else
			num = np;
	}
	if (num < np) {
		id = ids[num];
		free(ids);
		return id;
	}
	free(ids);
	return NULL;
}

void
enumerate_opencl(void)
{
	cl_platform_id *pids;
	cl_device_id *dids;
	int np, nd, i;

	np = get_platform_list(&pids);
	if (!np) {
		printf("No OpenCL platforms available\n");
		return;
	}
	printf("Available OpenCL platforms:\n");
	for (i = 0; i < np; i++) {
		show_platforms(&pids[i], 1, i);
		nd = get_device_list(pids[i], &dids);
		if (!nd) {
			printf("  -- No devices\n");
		} else {
			show_devices(pids[i], dids, nd, 0);
		}
	}
}

cl_device_id
get_opencl_device(int platformidx, int deviceidx)
{
	cl_platform_id pid;
	cl_device_id did = NULL;

	pid = get_platform(platformidx);
	if (pid) {
		did = get_device(pid, deviceidx);
		if (did)
			return did;
	}
	enumerate_opencl();
	return NULL;
}



void
usage(const char *name)
{
	printf(
"oclVanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
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
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-w <worksize> Set OpenCL work size (Default: number of CPUs)\n"
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
	int opt;
	int platformidx = -1, deviceidx = -1;
	char *seedfile = NULL;
	FILE *fp = NULL;
	char **patterns;
	int verbose = 1;
	int npatterns = 0;
	int worksize = 0;
	int remove_on_match = 1;
	vg_context_t *vcp = NULL;
	cl_device_id did;
	const char *result_file = NULL;

	while ((opt = getopt(argc, argv, "vqrikNTp:d:w:h?f:o:s:")) != -1) {
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
		case 'p':
			platformidx = atoi(optarg);
			break;
		case 'd':
			deviceidx = atoi(optarg);
			break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
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

	did = get_opencl_device(platformidx, deviceidx);
	if (!did) {
		return 1;
	}

	vg_opencl_loop(vcp, did, worksize);
	return 0;
}
