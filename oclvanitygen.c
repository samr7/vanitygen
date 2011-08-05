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
#include <openssl/md5.h>

#ifdef __APPLE__
#include <OpenCL/cl.h>
#ifndef CL_CALLBACK
#define CL_CALLBACK
#endif
#else
#include <CL/cl.h>
#endif

#include "pattern.h"


const char *version = "0.16";
const int debug = 0;

#define MAX_SLOT 2
#define MAX_ARG 6
#define MAX_KERNEL 3

#define round_up_pow2(x, a) (((x) + ((a)-1)) & ~((a)-1))

/* OpenCL address searching mode */
struct _vg_ocl_context_s;
typedef int (*vg_ocl_init_t)(struct _vg_ocl_context_s *);
typedef int (*vg_ocl_check_t)(struct _vg_ocl_context_s *, int slot);

typedef struct _vg_ocl_context_s {
	vg_exec_context_t		base;
	cl_device_id			voc_ocldid;
	cl_context			voc_oclctx;
	cl_command_queue		voc_oclcmdq;
	cl_program			voc_oclprog;
	vg_ocl_init_t			voc_init_func;
	vg_ocl_init_t			voc_rekey_func;
	vg_ocl_check_t			voc_check_func;
	int				voc_quirks;
	int				voc_nslots;
	cl_kernel			voc_oclkernel[MAX_SLOT][MAX_KERNEL];
	cl_event			voc_oclkrnwait[MAX_SLOT];
	cl_mem				voc_args[MAX_SLOT][MAX_ARG];
	size_t				voc_arg_size[MAX_SLOT][MAX_ARG];

	int				voc_pattern_rewrite;
	int				voc_pattern_alloc;

	pthread_t			voc_ocl_thread;
	pthread_mutex_t			voc_lock;
	pthread_cond_t			voc_wait;
	int				voc_ocl_slot;
	int				voc_ocl_rows;
	int				voc_ocl_cols;
	int				voc_ocl_invsize;
	int				voc_halt;
	int				voc_rekey;
	int				voc_dump_done;
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
 * OpenCL debugging and support
 */

const char *
vg_ocl_strerror(cl_int ret)
{
#define OCL_STATUS(st) case st: return #st;
	switch (ret) {
		OCL_STATUS(CL_SUCCESS);
		OCL_STATUS(CL_DEVICE_NOT_FOUND);
		OCL_STATUS(CL_DEVICE_NOT_AVAILABLE);
		OCL_STATUS(CL_COMPILER_NOT_AVAILABLE);
		OCL_STATUS(CL_MEM_OBJECT_ALLOCATION_FAILURE);
		OCL_STATUS(CL_OUT_OF_RESOURCES);
		OCL_STATUS(CL_OUT_OF_HOST_MEMORY);
		OCL_STATUS(CL_PROFILING_INFO_NOT_AVAILABLE);
		OCL_STATUS(CL_MEM_COPY_OVERLAP);
		OCL_STATUS(CL_IMAGE_FORMAT_MISMATCH);
		OCL_STATUS(CL_IMAGE_FORMAT_NOT_SUPPORTED);
		OCL_STATUS(CL_BUILD_PROGRAM_FAILURE);
		OCL_STATUS(CL_MAP_FAILURE);
#if defined(CL_MISALIGNED_SUB_BUFFER_OFFSET)
		OCL_STATUS(CL_MISALIGNED_SUB_BUFFER_OFFSET);
#endif /* defined(CL_MISALIGNED_SUB_BUFFER_OFFSET) */
#if defined(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST)
		OCL_STATUS(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST);
#endif /* defined(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST) */
		OCL_STATUS(CL_INVALID_VALUE);
		OCL_STATUS(CL_INVALID_DEVICE_TYPE);
		OCL_STATUS(CL_INVALID_PLATFORM);
		OCL_STATUS(CL_INVALID_DEVICE);
		OCL_STATUS(CL_INVALID_CONTEXT);
		OCL_STATUS(CL_INVALID_QUEUE_PROPERTIES);
		OCL_STATUS(CL_INVALID_COMMAND_QUEUE);
		OCL_STATUS(CL_INVALID_HOST_PTR);
		OCL_STATUS(CL_INVALID_MEM_OBJECT);
		OCL_STATUS(CL_INVALID_IMAGE_FORMAT_DESCRIPTOR);
		OCL_STATUS(CL_INVALID_IMAGE_SIZE);
		OCL_STATUS(CL_INVALID_SAMPLER);
		OCL_STATUS(CL_INVALID_BINARY);
		OCL_STATUS(CL_INVALID_BUILD_OPTIONS);
		OCL_STATUS(CL_INVALID_PROGRAM);
		OCL_STATUS(CL_INVALID_PROGRAM_EXECUTABLE);
		OCL_STATUS(CL_INVALID_KERNEL_NAME);
		OCL_STATUS(CL_INVALID_KERNEL_DEFINITION);
		OCL_STATUS(CL_INVALID_KERNEL);
		OCL_STATUS(CL_INVALID_ARG_INDEX);
		OCL_STATUS(CL_INVALID_ARG_VALUE);
		OCL_STATUS(CL_INVALID_ARG_SIZE);
		OCL_STATUS(CL_INVALID_KERNEL_ARGS);
		OCL_STATUS(CL_INVALID_WORK_DIMENSION);
		OCL_STATUS(CL_INVALID_WORK_GROUP_SIZE);
		OCL_STATUS(CL_INVALID_WORK_ITEM_SIZE);
		OCL_STATUS(CL_INVALID_GLOBAL_OFFSET);
		OCL_STATUS(CL_INVALID_EVENT_WAIT_LIST);
		OCL_STATUS(CL_INVALID_EVENT);
		OCL_STATUS(CL_INVALID_OPERATION);
		OCL_STATUS(CL_INVALID_GL_OBJECT);
		OCL_STATUS(CL_INVALID_BUFFER_SIZE);
		OCL_STATUS(CL_INVALID_MIP_LEVEL);
		OCL_STATUS(CL_INVALID_GLOBAL_WORK_SIZE);
#if defined(CL_INVALID_PROPERTY)
		OCL_STATUS(CL_INVALID_PROPERTY);
#endif /* defined(CL_INVALID_PROPERTY) */
#undef OCL_STATUS
	default: {
		static char tmp[64];
		snprintf(tmp, sizeof(tmp), "Unknown code %d", ret);
		return tmp;
	}
	}
}

/* Get device strings, using a static buffer -- caveat emptor */
const char *
vg_ocl_platform_getstr(cl_platform_id pid, cl_platform_info param)
{
	static char platform_str[1024];
	cl_int ret;
	size_t size_ret;
	ret = clGetPlatformInfo(pid, param,
				sizeof(platform_str), platform_str,
				&size_ret);
	if (ret != CL_SUCCESS) {
		snprintf(platform_str, sizeof(platform_str),
			 "clGetPlatformInfo(%d): %s",
			 param, vg_ocl_strerror(ret));
	}
	return platform_str;
}

cl_platform_id
vg_ocl_device_getplatform(cl_device_id did)
{
	cl_int ret;
	cl_platform_id val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, CL_DEVICE_PLATFORM,
			      sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		printf("clGetDeviceInfo(CL_DEVICE_PLATFORM): %s",
		       vg_ocl_strerror(ret));
	}
	return val;
}

cl_device_type
vg_ocl_device_gettype(cl_device_id did)
{
	cl_int ret;
	cl_device_type val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, CL_DEVICE_TYPE,
			      sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		printf("clGetDeviceInfo(CL_DEVICE_TYPE): %s",
		       vg_ocl_strerror(ret));
	}
	return val;
}

const char *
vg_ocl_device_getstr(cl_device_id did, cl_device_info param)
{
	static char device_str[1024];
	cl_int ret;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param,
			      sizeof(device_str), device_str,
			      &size_ret);
	if (ret != CL_SUCCESS) {
		snprintf(device_str, sizeof(device_str),
			 "clGetDeviceInfo(%d): %s",
			 param, vg_ocl_strerror(ret));
	}
	return device_str;
}

size_t
vg_ocl_device_getsizet(cl_device_id did, cl_device_info param)
{
	cl_int ret;
	size_t val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		printf("clGetDeviceInfo(%d): %s", param, vg_ocl_strerror(ret));
	}
	return val;
}

cl_ulong
vg_ocl_device_getulong(cl_device_id did, cl_device_info param)
{
	cl_int ret;
	cl_ulong val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		printf("clGetDeviceInfo(%d): %s", param, vg_ocl_strerror(ret));
	}
	return val;
}

cl_uint
vg_ocl_device_getuint(cl_device_id did, cl_device_info param)
{
	cl_int ret;
        cl_uint val;
	size_t size_ret;
	ret = clGetDeviceInfo(did, param, sizeof(val), &val, &size_ret);
	if (ret != CL_SUCCESS) {
		printf("clGetDeviceInfo(%d): %s", param, vg_ocl_strerror(ret));
	}
	return val;
}

void
vg_ocl_dump_info(vg_ocl_context_t *vocp)
{
	cl_device_id did;
	if (vocp->base.vxc_vc && (vocp->base.vxc_vc->vc_verbose < 1))
		return;
	if (vocp->voc_dump_done)
		return;
	did = vocp->voc_ocldid;
	printf("Device: %s\n",
	       vg_ocl_device_getstr(did, CL_DEVICE_NAME));
	printf("Vendor: %s (%04x)\n",
	       vg_ocl_device_getstr(did, CL_DEVICE_VENDOR),
	       vg_ocl_device_getuint(did, CL_DEVICE_VENDOR_ID));
	printf("Driver: %s\n",
	       vg_ocl_device_getstr(did, CL_DRIVER_VERSION));
	printf("Profile: %s\n",
	       vg_ocl_device_getstr(did, CL_DEVICE_PROFILE));
	printf("Version: %s\n",
	       vg_ocl_device_getstr(did, CL_DEVICE_VERSION));
	printf("Max compute units: %"PRSIZET"d\n",
	       vg_ocl_device_getsizet(did, CL_DEVICE_MAX_COMPUTE_UNITS));
	printf("Max workgroup size: %"PRSIZET"d\n",
	       vg_ocl_device_getsizet(did, CL_DEVICE_MAX_WORK_GROUP_SIZE));
	printf("Global memory: %ld\n",
	       vg_ocl_device_getulong(did, CL_DEVICE_GLOBAL_MEM_SIZE));
	printf("Max allocation: %ld\n",
	       vg_ocl_device_getulong(did, CL_DEVICE_MAX_MEM_ALLOC_SIZE));
	vocp->voc_dump_done = 1;
}

void
vg_ocl_error(vg_ocl_context_t *vocp, int code, const char *desc)
{
	const char *err = vg_ocl_strerror(code);
	if (desc) {
		printf("%s: %s\n", desc, err);
	} else {
		printf("%s\n", err);
	}

	if (vocp && vocp->voc_ocldid)
		vg_ocl_dump_info(vocp);
}

void
vg_ocl_buildlog(vg_ocl_context_t *vocp, cl_program prog)
{
	size_t logbufsize, logsize;
	char *log;
	int off = 0;
	cl_int ret;

	ret = clGetProgramBuildInfo(prog,
				    vocp->voc_ocldid,
				    CL_PROGRAM_BUILD_LOG,
				    0, NULL,
				    &logbufsize);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(NULL, ret, "clGetProgramBuildInfo");
		return;
	}

	log = (char *) malloc(logbufsize);
	if (!log) {
		printf("Could not allocate build log buffer\n");
		return;
	}

	ret = clGetProgramBuildInfo(prog,
				    vocp->voc_ocldid,
				    CL_PROGRAM_BUILD_LOG,
				    logbufsize,
				    log,
				    &logsize);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(NULL, ret, "clGetProgramBuildInfo");

	} else {
		/* Remove leading newlines and trailing newlines/whitespace */
		log[logbufsize-1] = '\0';
		for (off = logsize - 1; off >= 0; off--) {
			if ((log[off] != '\r') &&
			    (log[off] != '\n') &&
			    (log[off] != ' ') &&
			    (log[off] != '\t') &&
			    (log[off] != '\0'))
				break;
			log[off] = '\0';
		}
		for (off = 0; off < logbufsize; off++) {
			if ((log[off] != '\r') &&
			    (log[off] != '\n'))
				break;
		}

		printf("Build log:\n%s\n", &log[off]);
	}
	free(log);
}

/*
 * OpenCL per-exec functions
 */

enum {
	VG_OCL_UNROLL_LOOPS         = (1 << 0),
	VG_OCL_EXPENSIVE_BRANCHES   = (1 << 1),
	VG_OCL_DEEP_VLIW            = (1 << 2),
	VG_OCL_AMD_BFI_INT          = (1 << 3),
	VG_OCL_NV_VERBOSE           = (1 << 4),
	VG_OCL_BROKEN               = (1 << 5),
	VG_OCL_NO_BINARIES          = (1 << 6),

	VG_OCL_OPTIMIZATIONS        = (VG_OCL_UNROLL_LOOPS |
				       VG_OCL_EXPENSIVE_BRANCHES |
				       VG_OCL_DEEP_VLIW |
				       VG_OCL_AMD_BFI_INT),

};

int
vg_ocl_get_quirks(vg_ocl_context_t *vocp)
{
	uint32_t vend;
	const char *dvn;
	unsigned int quirks = 0;

	/* Loop unrolling for devices other than CPUs */
	if (!(vg_ocl_device_gettype(vocp->voc_ocldid) & CL_DEVICE_TYPE_CPU))
		quirks |= VG_OCL_UNROLL_LOOPS;

	vend = vg_ocl_device_getuint(vocp->voc_ocldid, CL_DEVICE_VENDOR_ID);
	switch (vend) {
	case 0x10de: /* NVIDIA */
		quirks |= VG_OCL_NV_VERBOSE;
#ifdef WIN32
		if (strcmp(vg_ocl_device_getstr(vocp->voc_ocldid,
						CL_DRIVER_VERSION),
			   "270.81")) {
			printf("WARNING: Known problems with certain "
			       "NVIDIA driver versions\n"
			       "WARNING: Use version 270.81 "
			       "for best results\n");
			quirks |= VG_OCL_BROKEN;
		}
#endif
		break;
	case 0x1002: /* AMD/ATI */
		if (vg_ocl_device_gettype(vocp->voc_ocldid) &
		    CL_DEVICE_TYPE_GPU) {
			quirks |= VG_OCL_EXPENSIVE_BRANCHES;
			quirks |= VG_OCL_DEEP_VLIW;
			dvn = vg_ocl_device_getstr(vocp->voc_ocldid,
						   CL_DEVICE_EXTENSIONS);
			if (dvn && strstr(dvn, "cl_amd_media_ops"))
				quirks |= VG_OCL_AMD_BFI_INT;

			dvn = vg_ocl_device_getstr(vocp->voc_ocldid,
						   CL_DEVICE_NAME);
			if (!strcmp(dvn, "ATI RV710")) {
				quirks &= ~VG_OCL_OPTIMIZATIONS;
				quirks |= VG_OCL_NO_BINARIES;
			}
		}
		break;
	default:
		break;
	}
	return quirks;
}

int
vg_ocl_create_kernel(vg_ocl_context_t *vocp, int knum, const char *func)
{
	int i;
	cl_kernel krn;
	cl_int ret;

	for (i = 0; i < MAX_SLOT; i++) {
		krn = clCreateKernel(vocp->voc_oclprog, func, &ret);
		if (!krn) {
			printf("clCreateKernel(%d): ", i);
			vg_ocl_error(vocp, ret, NULL);
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

void
vg_ocl_hash_program(vg_ocl_context_t *vocp, const char *opts,
		    const char *program, size_t size,
		    unsigned char *hash_out)
{
	MD5_CTX ctx;
	cl_platform_id pid;
	const char *str;

	MD5_Init(&ctx);
	pid = vg_ocl_device_getplatform(vocp->voc_ocldid);
	str = vg_ocl_platform_getstr(pid, CL_PLATFORM_NAME);
	MD5_Update(&ctx, str, strlen(str) + 1);
	str = vg_ocl_platform_getstr(pid, CL_PLATFORM_VERSION);
	MD5_Update(&ctx, str, strlen(str) + 1);
	str = vg_ocl_device_getstr(vocp->voc_ocldid, CL_DEVICE_NAME);
	MD5_Update(&ctx, str, strlen(str) + 1);
	if (opts)
		MD5_Update(&ctx, opts, strlen(opts) + 1);
	if (size)
		MD5_Update(&ctx, program, size);
	MD5_Final(hash_out, &ctx);
}

typedef struct {
	unsigned char	e_ident[16];
	uint16_t	e_type;
	uint16_t	e_machine;
	uint32_t	e_version;
	uint32_t	e_entry;
	uint32_t	e_phoff;
	uint32_t	e_shoff;
	uint32_t	e_flags;
	uint16_t	e_ehsize;
	uint16_t	e_phentsize;
	uint16_t	e_phnum;
	uint16_t	e_shentsize;
	uint16_t	e_shnum;
	uint16_t	e_shstrndx;
} vg_elf32_header_t;

typedef struct {
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint32_t	sh_flags;
	uint32_t	sh_addr;
	uint32_t	sh_offset;
	uint32_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint32_t	sh_addralign;
	uint32_t	sh_entsize;
} vg_elf32_shdr_t;

int
vg_ocl_amd_patch_inner(unsigned char *binary, size_t size)
{
	vg_elf32_header_t *ehp;
	vg_elf32_shdr_t *shp, *nshp;
	uint32_t *instr;
	size_t off;
	int i, n, txt2idx, patched;

	ehp = (vg_elf32_header_t *) binary;
	if ((size < sizeof(*ehp)) ||
	    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\x64", 8) ||
	    !ehp->e_shoff)
		return 0;

	off = ehp->e_shoff + (ehp->e_shstrndx * ehp->e_shentsize);
	nshp = (vg_elf32_shdr_t *) (binary + off);
	if ((off + sizeof(*nshp)) > size)
		return 0;

	shp = (vg_elf32_shdr_t *) (binary + ehp->e_shoff);
	n = 0;
	txt2idx = 0;
	for (i = 0; i < ehp->e_shnum; i++) {
		off = nshp->sh_offset + shp[i].sh_name;
		if (((off + 6) >= size) ||
		    memcmp(binary + off, ".text", 6))
			continue;
		n++;
		if (n == 2)
			txt2idx = i;
	}
	if (n != 2)
		return 0;

	off = shp[txt2idx].sh_offset;
	instr = (uint32_t *) (binary + off);
	n = shp[txt2idx].sh_size / 4;
	patched = 0;
	for (i = 0; i < n; i += 2) {
		if (((instr[i] & 0x02001000) == 0) &&
		    ((instr[i+1] & 0x9003f000) == 0x0001a000)) {
			instr[i+1] ^= (0x0001a000 ^ 0x0000c000);
			patched++;
		}
	}

	return patched;
}

int
vg_ocl_amd_patch(vg_ocl_context_t *vocp, unsigned char *binary, size_t size)
{
	vg_context_t *vcp = vocp->base.vxc_vc;
	vg_elf32_header_t *ehp;
	unsigned char *ptr;
	size_t offset = 1;
	int ninner = 0, nrun, npatched = 0;

	ehp = (vg_elf32_header_t *) binary;
	if ((size < sizeof(*ehp)) ||
	    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\0", 8) ||
	    !ehp->e_shoff)
		return 0;

	offset = 1;
	while (offset < (size - 8)) {
		ptr = (unsigned char *) memchr(binary + offset,
					       0x7f,
					       size - offset);
		if (!ptr)
			return npatched;
		offset = ptr - binary;
		ehp = (vg_elf32_header_t *) ptr;
		if (((size - offset) < sizeof(*ehp)) ||
		    memcmp(ehp->e_ident, "\x7f" "ELF\1\1\1\x64", 8) ||
		    !ehp->e_shoff) {
			offset += 1;
			continue;
		}

		ninner++;
		nrun = vg_ocl_amd_patch_inner(ptr, size - offset);
		npatched += nrun;
		if (vcp->vc_verbose > 1)
			printf("AMD BFI_INT: patched %d instructions "
			       "in kernel %d\n",
			       nrun, ninner);
		npatched++;
		offset += 1;
	}
	return npatched;
}


int
vg_ocl_load_program(vg_context_t *vcp, vg_ocl_context_t *vocp,
		    const char *filename, const char *opts)
{
	FILE *kfp;
	char *buf, *tbuf;
	int len, fromsource = 0, patched = 0;
	size_t sz, szr;
	cl_program prog;
	cl_int ret, sts;
	unsigned char prog_hash[16];
	char bin_name[64];

	if (vcp->vc_verbose > 1)
		printf("OpenCL compiler flags: %s\n", opts ? opts : "");

	sz = 128 * 1024;
	buf = (char *) malloc(sz);
	if (!buf) {
		printf("Could not allocate program buffer\n");
		return 0;
	}

	kfp = fopen(filename, "r");
	if (!kfp) {
		printf("Error loading CL kernel: %s\n", strerror(errno));
		free(buf);
		return 0;
	}

	len = fread(buf, 1, sz, kfp);
	fclose(kfp);

	if (!len) {
		printf("Short read on CL kernel\n");
		free(buf);
		return 0;
	}

	vg_ocl_hash_program(vocp, opts, buf, len, prog_hash);
	snprintf(bin_name, sizeof(bin_name),
		 "%02x%02x%02x%02x%02x%02x%02x%02x"
		 "%02x%02x%02x%02x%02x%02x%02x%02x.oclbin",
		 prog_hash[0], prog_hash[1], prog_hash[2], prog_hash[3],
		 prog_hash[4], prog_hash[5], prog_hash[6], prog_hash[7],
		 prog_hash[8], prog_hash[9], prog_hash[10], prog_hash[11],
		 prog_hash[12], prog_hash[13], prog_hash[14], prog_hash[15]);

	if (vocp->voc_quirks & VG_OCL_NO_BINARIES) {
		kfp = NULL;
		if (vcp->vc_verbose > 1)
			printf("Binary OpenCL programs disabled\n");
	} else {
		kfp = fopen(bin_name, "rb");
	}

	if (!kfp) {
		/* No binary available, create with source */
		fromsource = 1;
		sz = len;
		prog = clCreateProgramWithSource(vocp->voc_oclctx,
						 1, (const char **) &buf, &sz,
						 &ret);
	} else {
		if (vcp->vc_verbose > 1)
			printf("Loading kernel binary %s\n", bin_name);
		szr = 0;
		while (!feof(kfp)) {
			len = fread(buf + szr, 1, sz - szr, kfp);
			if (!len) {
				printf("Short read on CL kernel binary\n");
				fclose(kfp);
				free(buf);
				return 0;
			}
			szr += len;
			if (szr == sz) {
				tbuf = (char *) realloc(buf, sz*2);
				if (!tbuf) {
					printf("Could not expand CL kernel "
					       "binary buffer\n");
					fclose(kfp);
					free(buf);
					return 0;
				}
				buf = tbuf;
				sz *= 2;
			}
		}
		fclose(kfp);
	rebuild:
		prog = clCreateProgramWithBinary(vocp->voc_oclctx,
						 1, &vocp->voc_ocldid,
						 &szr,
						 (const unsigned char **) &buf,
						 &sts,
						 &ret);
	}
	free(buf);
	if (!prog) {
		vg_ocl_error(vocp, ret, "clCreateProgramWithSource");
		return 0;
	}

	if (vcp->vc_verbose > 0) {
		if (fromsource && !patched) {
			printf("Compiling kernel...");
			fflush(stdout);
		}
	}
	ret = clBuildProgram(prog, 1, &vocp->voc_ocldid, opts, NULL, NULL);
	if (ret != CL_SUCCESS) {
		if ((vcp->vc_verbose > 0) && fromsource && !patched)
			printf("failure.\n");
		vg_ocl_error(NULL, ret, "clBuildProgram");
	} else if ((vcp->vc_verbose > 0) && fromsource && !patched) {
		printf("done!\n");
	}
	if ((ret != CL_SUCCESS) ||
	    ((vcp->vc_verbose > 1) && fromsource && !patched)) {
		vg_ocl_buildlog(vocp, prog);
	}
	if (ret != CL_SUCCESS) {
		vg_ocl_dump_info(vocp);
		clReleaseProgram(prog);
		return 0;
	}

	if (fromsource && !(vocp->voc_quirks & VG_OCL_NO_BINARIES)) {
		ret = clGetProgramInfo(prog,
				       CL_PROGRAM_BINARY_SIZES,
				       sizeof(szr), &szr,
				       &sz);
		if (ret != CL_SUCCESS) {
			vg_ocl_error(vocp, ret,
				     "WARNING: clGetProgramInfo(BINARY_SIZES)");
			goto out;
		}
		if (sz == 0) {
			printf("WARNING: zero-length CL kernel binary\n");
			goto out;
		}

		buf = (char *) malloc(szr);
		if (!buf) {
			printf("WARNING: Could not allocate %"PRSIZET"d bytes "
			       "for CL binary\n",
			       szr);
			goto out;
		}

		ret = clGetProgramInfo(prog,
				       CL_PROGRAM_BINARIES,
				       sizeof(buf), &buf,
				       &sz);
		if (ret != CL_SUCCESS) {
			vg_ocl_error(vocp, ret,
				     "WARNING: clGetProgramInfo(BINARIES)");
			free(buf);
			goto out;
		}

		if ((vocp->voc_quirks & VG_OCL_AMD_BFI_INT) && !patched) {
			patched = vg_ocl_amd_patch(vocp,
						   (unsigned char *) buf, szr);
			if (patched > 0) {
				if (vcp->vc_verbose > 1)
					printf("AMD BFI_INT patch complete\n");
				clReleaseProgram(prog);
				goto rebuild;
			}
			printf("WARNING: AMD BFI_INT patching failed\n");
			if (patched < 0) {
				/* Program was incompletely modified */
				free(buf);
				goto out;
			}
		}

		kfp = fopen(bin_name, "wb");
		if (!kfp) {
			printf("WARNING: could not save CL kernel binary: %s\n",
			       strerror(errno));
		} else {
			sz = fwrite(buf, 1, szr, kfp);
			fclose(kfp);
			if (sz != szr) {
				printf("WARNING: short write on CL kernel "
				       "binary file: expected "
				       "%"PRSIZET"d, got %"PRSIZET"d\n",
				       szr, sz);
				unlink(bin_name);
			}
		}
		free(buf);
	}

out:
	vocp->voc_oclprog = prog;
	if (!vg_ocl_create_kernel(vocp, 0, "ec_add_grid") ||
	    !vg_ocl_create_kernel(vocp, 1, "heap_invert")) {
		clReleaseProgram(vocp->voc_oclprog);
		vocp->voc_oclprog = NULL;
		return 0;
	}

	return 1;
}

void CL_CALLBACK
vg_ocl_context_callback(const char *errinfo,
			const void *private_info,
			size_t cb,
			void *user_data)
{
	printf("vg_ocl_context_callback error: %s\n", errinfo);
}

int
vg_ocl_init(vg_context_t *vcp, vg_ocl_context_t *vocp, cl_device_id did,
	    int safe_mode)
{
	cl_int ret;
	char optbuf[128];
	int end = 0;

	memset(vocp, 0, sizeof(*vocp));
	vg_exec_context_init(vcp, &vocp->base);

	pthread_mutex_init(&vocp->voc_lock, NULL);
	pthread_cond_init(&vocp->voc_wait, NULL);
	vocp->voc_ocl_slot = -1;

	vocp->voc_ocldid = did;

	if (vcp->vc_verbose > 1)
		vg_ocl_dump_info(vocp);

	vocp->voc_quirks = vg_ocl_get_quirks(vocp);

	if ((vocp->voc_quirks & VG_OCL_BROKEN) && (vcp->vc_verbose > 0)) {
		char yesbuf[16];
		printf("Type 'yes' to continue: ");
		fflush(stdout);
		if (!fgets(yesbuf, sizeof(yesbuf), stdin) ||
		    strncmp(yesbuf, "yes", 3))
			exit(1);
	}

	vocp->voc_oclctx = clCreateContext(NULL,
					   1, &did,
					   vg_ocl_context_callback,
					   NULL,
					   &ret);
	if (!vocp->voc_oclctx) {
		vg_ocl_error(vocp, ret, "clCreateContext");
		return 0;
	}

	vocp->voc_oclcmdq = clCreateCommandQueue(vocp->voc_oclctx,
						 vocp->voc_ocldid,
						 0, &ret);
	if (!vocp->voc_oclcmdq) {
		vg_ocl_error(vocp, ret, "clCreateCommandQueue");
		return 0;
	}

	if (safe_mode)
		vocp->voc_quirks &= ~VG_OCL_OPTIMIZATIONS;

	end = 0;
	optbuf[end] = '\0';
	if (vocp->voc_quirks & VG_OCL_UNROLL_LOOPS)
		end += snprintf(optbuf + end, sizeof(optbuf) - end,
				"-DUNROLL_MAX=16 ");
	if (vocp->voc_quirks & VG_OCL_EXPENSIVE_BRANCHES)
		end += snprintf(optbuf + end, sizeof(optbuf) - end,
				"-DVERY_EXPENSIVE_BRANCHES ");
	if (vocp->voc_quirks & VG_OCL_DEEP_VLIW)
		end += snprintf(optbuf + end, sizeof(optbuf) - end,
				"-DDEEP_VLIW ");
	if (vocp->voc_quirks & VG_OCL_AMD_BFI_INT)
		end += snprintf(optbuf + end, sizeof(optbuf) - end,
				"-DAMD_BFI_INT ");
	if (vocp->voc_quirks & VG_OCL_NV_VERBOSE)
		end += snprintf(optbuf + end, sizeof(optbuf) - end,
				"-cl-nv-verbose ");

	if (!vg_ocl_load_program(vcp, vocp, "calc_addrs.cl", optbuf))
		return 0;
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

static int vg_ocl_arg_map[][8] = {
	/* hashes_out / found */
	{ 2, 0, -1 },
	/* z_heap */
	{ 0, 1, 1, 0, 2, 2, -1 },
	/* point_tmp */
	{ 0, 0, 2, 1, -1 },
	/* row_in */
	{ 0, 2, -1 },
	/* col_in */
	{ 0, 3, -1 },
	/* target_table */
	{ 2, 3, -1 },
};

int
vg_ocl_kernel_arg_alloc(vg_ocl_context_t *vocp, int slot,
			int arg, size_t size, int host)
{
	cl_mem clbuf;
	cl_int ret;
	int i, j, knum, karg;

	for (i = 0; i < MAX_SLOT; i++) {
		if ((i != slot) && (slot >= 0))
			continue;
		if (vocp->voc_args[i][arg]) {
			clReleaseMemObject(vocp->voc_args[i][arg]);
			vocp->voc_args[i][arg] = NULL;
			vocp->voc_arg_size[i][arg] = 0;
		}
	}

	clbuf = clCreateBuffer(vocp->voc_oclctx,
			       CL_MEM_READ_WRITE |
			       (host ? CL_MEM_ALLOC_HOST_PTR : 0),
			       size,
			       NULL,
			       &ret);
	if (!clbuf) {
		printf("clCreateBuffer(%d,%d): ", slot, arg);
		vg_ocl_error(vocp, ret, NULL);
		return 0;
	}

	for (i = 0; i < MAX_SLOT; i++) {
		if ((i != slot) && (slot >= 0))
			continue;

		clRetainMemObject(clbuf);
		vocp->voc_args[i][arg] = clbuf;
		vocp->voc_arg_size[i][arg] = size;

		for (j = 0; vg_ocl_arg_map[arg][j] >= 0; j += 2) {
			knum = vg_ocl_arg_map[arg][j];
			karg = vg_ocl_arg_map[arg][j+1];
			ret = clSetKernelArg(vocp->voc_oclkernel[i][knum],
					     karg,
					     sizeof(clbuf),
					     &clbuf);
			
			if (ret) {
				printf("clSetKernelArg(%d,%d): ", knum, karg);
				vg_ocl_error(vocp, ret, NULL);
				return 0;
			}
		}
	}

	clReleaseMemObject(clbuf);
	return 1;
}

int
vg_ocl_copyout_arg(vg_ocl_context_t *vocp, int wslot, int arg,
		   void *buffer, size_t size)
{
	cl_int slot, ret;

	slot = (wslot < 0) ? 0 : wslot;

	assert((slot >= 0) && (slot < MAX_SLOT));
	assert(size <= vocp->voc_arg_size[slot][arg]);

	ret = clEnqueueWriteBuffer(vocp->voc_oclcmdq,
				   vocp->voc_args[slot][arg],
				   CL_TRUE,
				   0, size,
				   buffer,
				   0, NULL,
				   NULL);
			
	if (ret) {
		printf("clEnqueueWriteBuffer(%d): ", arg);
		vg_ocl_error(vocp, ret, NULL);
		return 0;
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
				 (rw == 2) ? (CL_MAP_READ|CL_MAP_WRITE)
				           : (rw ? CL_MAP_WRITE : CL_MAP_READ),
				 0, vocp->voc_arg_size[slot][arg],
				 0, NULL,
				 NULL,
				 &ret);
	if (!buf) {
		printf("clEnqueueMapBuffer(%d): ", arg);
		vg_ocl_error(vocp, ret, NULL);
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
		printf("clEnqueueUnmapMemObject(%d): ", arg);
		vg_ocl_error(vocp, ret, NULL);
		return;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		printf("clWaitForEvent(clUnmapMemObject,%d): ", arg);
		vg_ocl_error(vocp, ret, NULL);
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
		ret = clSetKernelArg(vocp->voc_oclkernel[i][2],
				     arg,
				     sizeof(value),
				     &value);
		if (ret) {
			printf("clSetKernelArg(%d): ", arg);
			vg_ocl_error(vocp, ret, NULL);
			return 0;
		}
	}
	return 1;
}

int
vg_ocl_kernel_buffer_arg(vg_ocl_context_t *vocp, int slot,
			 int arg, void *value, size_t size)
{
	cl_int ret;
	int i, j, knum, karg;

	for (i = 0; i < MAX_SLOT; i++) {
		if ((i != slot) && (slot >= 0))
			continue;
		for (j = 0; vg_ocl_arg_map[arg][j] >= 0; j += 2) {
			knum = vg_ocl_arg_map[arg][j];
			karg = vg_ocl_arg_map[arg][j+1];
			ret = clSetKernelArg(vocp->voc_oclkernel[i][knum],
					     karg,
					     size,
					     value);
			if (ret) {
				printf("clSetKernelArg(%d,%d): ", knum, karg);
				vg_ocl_error(vocp, ret, NULL);
				return 0;
			}
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
vg_ocl_kernel_start(vg_ocl_context_t *vocp, int slot, int ncol, int nrow,
		    int invsize)
{
	cl_int val, ret;
	cl_event ev;
	size_t globalws[2] = { ncol, nrow };
	size_t invws = (ncol * nrow) / invsize;

	assert(!vocp->voc_oclkrnwait[slot]);

	val = invsize;
	ret = clSetKernelArg(vocp->voc_oclkernel[slot][1],
			     1,
			     sizeof(val),
			     &val);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clSetKernelArg(ncol)");
		return 0;
	}
	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][0],
				     2,
				     NULL, globalws, NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clEnqueueNDRange(0)");
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clWaitForEvents(NDRange,0)");
		return 0;
	}

	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][1],
				     1,
				     NULL, &invws, NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clEnqueueNDRange(1)");
		return 0;
	}

	ret = clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clWaitForEvents(NDRange,1)");
		return 0;
	}

	ret = clEnqueueNDRangeKernel(vocp->voc_oclcmdq,
				     vocp->voc_oclkernel[slot][2],
				     2,
				     NULL, globalws, NULL,
				     0, NULL,
				     &ev);
	if (ret != CL_SUCCESS) {
		vg_ocl_error(vocp, ret, "clEnqueueNDRange(2)");
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
			vg_ocl_error(vocp, ret, "clWaitForEvents(NDRange,e)");
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

#define ACCESS_BUNDLE 1024
#define ACCESS_STRIDE (ACCESS_BUNDLE/8)

INLINE void
vg_ocl_put_point_tpa(unsigned char *buf, int cell, EC_POINT *ppnt)
{
	uint8_t pntbuf[64];
	int start, i;

	vg_ocl_put_point(pntbuf, ppnt);

	start = ((((2 * cell) / ACCESS_STRIDE) * ACCESS_BUNDLE) +
		 (cell % (ACCESS_STRIDE/2)));
	for (i = 0; i < 8; i++)
		memcpy(buf + 4*(start + i*ACCESS_STRIDE),
		       pntbuf+(i*4),
		       4);
	for (i = 0; i < 8; i++)
		memcpy(buf + 4*(start + (ACCESS_STRIDE/2) + (i*ACCESS_STRIDE)),
		       pntbuf+32+(i*4),
		       4);
}

void
show_elapsed(struct timeval *tv, const char *place)
{
	struct timeval now, delta;
        gettimeofday(&now, NULL);
	timersub(&now, tv, &delta);
	printf("%s spent %ld.%06lds\n", place, delta.tv_sec, delta.tv_usec);
}


/*
 * GPU address matching methods
 *
 * gethash: GPU computes and returns all address hashes.
 *  + Works with any matching method, including regular expressions.
 *  - The CPU will not be able to keep up with mid- to high-end GPUs.
 *
 * prefix: GPU computes hash, searches a range list, and discards.
 *  + Fast, minimal work for CPU.
 */

int
vg_ocl_gethash_check(vg_ocl_context_t *vocp, int slot)
{
	vg_exec_context_t *vxcp = &vocp->base;
	vg_context_t *vcp = vocp->base.vxc_vc;
	vg_test_func_t test_func = vcp->vc_test;
	unsigned char *ocl_hashes_out;
	int i, res = 0, round;

	ocl_hashes_out = (unsigned char *)
		vg_ocl_map_arg_buffer(vocp, slot, 0, 0);

	round = vocp->voc_ocl_cols * vocp->voc_ocl_rows;

	for (i = 0; i < round; i++, vxcp->vxc_delta++) {
		memcpy(&vxcp->vxc_binres[1],
		       ocl_hashes_out + (20*i),
		       20);

		res = test_func(vxcp);
		if (res)
			break;
	}

	vg_ocl_unmap_arg_buffer(vocp, slot, 0, ocl_hashes_out);
	return res;
}

int
vg_ocl_gethash_init(vg_ocl_context_t *vocp)
{
	int i;

	if (!vg_ocl_create_kernel(vocp, 2, "hash_ec_point_get"))
		return 0;

	for (i = 0; i < vocp->voc_nslots; i++) {
		/* Each slot gets its own hash output buffer */
		if (!vg_ocl_kernel_arg_alloc(vocp, i, 0,
					     20 *
					     vocp->voc_ocl_rows *
					     vocp->voc_ocl_cols, 1))
			return 0;
	}

	vocp->voc_rekey_func = NULL;
	vocp->voc_check_func = vg_ocl_gethash_check;
	return 1;
}


static int
vg_ocl_prefix_rekey(vg_ocl_context_t *vocp)
{
	vg_context_t *vcp = vocp->base.vxc_vc;
	unsigned char *ocl_targets_in;
	uint32_t *ocl_found_out;
	int i;

	/* Set the found indicator for each slot to -1 */
	for (i = 0; i < vocp->voc_nslots; i++) {
		ocl_found_out = (uint32_t *)
			vg_ocl_map_arg_buffer(vocp, i, 0, 1);
		ocl_found_out[0] = 0xffffffff;
		vg_ocl_unmap_arg_buffer(vocp, i, 0, ocl_found_out);
	}

	if (vocp->voc_pattern_rewrite) {
		/* Count number of range records */
		i = vg_context_hash160_sort(vcp, NULL);
		if (!i) {
			printf("No range records available, exiting\n");
			return 0;
		}

		if (i > vocp->voc_pattern_alloc) {
			/* (re)allocate target buffer */
			if (!vg_ocl_kernel_arg_alloc(vocp, -1, 5, 40 * i, 0))
				return 0;
			vocp->voc_pattern_alloc = i;
		}

		/* Write range records */
		ocl_targets_in = (unsigned char *)
			vg_ocl_map_arg_buffer(vocp, 0, 5, 1);
		vg_context_hash160_sort(vcp, ocl_targets_in);
		vg_ocl_unmap_arg_buffer(vocp, 0, 5, ocl_targets_in);
		vg_ocl_kernel_int_arg(vocp, -1, 4, i);

		vocp->voc_pattern_rewrite = 0;
	}
	return 1;
}

static int
vg_ocl_prefix_check(vg_ocl_context_t *vocp, int slot)
{
	vg_exec_context_t *vxcp = &vocp->base;
	vg_context_t *vcp = vocp->base.vxc_vc;
	vg_test_func_t test_func = vcp->vc_test;
	uint32_t *ocl_found_out;
	uint32_t found_delta;
	int orig_delta, tablesize;
	int res = 0;

	/* Retrieve the found indicator */
	ocl_found_out = (uint32_t *)
		vg_ocl_map_arg_buffer(vocp, slot, 0, 2);
	found_delta = ocl_found_out[0];

	if (found_delta != 0xffffffff) {
		/* GPU code claims match, verify with CPU version */
		orig_delta = vxcp->vxc_delta;
		vxcp->vxc_delta += found_delta;
		vg_exec_context_calc_address(vxcp);
		res = test_func(vxcp);
		if (res == 0) {
			/*
			 * The match was not found in
			 * the pattern list.  Hmm.
			 */
			tablesize = ocl_found_out[2];
			printf("Match idx: %d\n", ocl_found_out[1]);
			printf("CPU hash: ");
			dumphex(vxcp->vxc_binres + 1, 20);
			printf("GPU hash: ");
			dumphex((unsigned char *) (ocl_found_out + 2), 20);
			printf("Found delta: %d "
			       "Start delta: %d\n",
			       found_delta, orig_delta);
			res = 1;
		}
		vocp->voc_pattern_rewrite = 1;
	} else {
		vxcp->vxc_delta += (vocp->voc_ocl_cols * vocp->voc_ocl_rows);
	}

	vg_ocl_unmap_arg_buffer(vocp, slot, 0, ocl_found_out);
	return res;
}

int
vg_ocl_prefix_init(vg_ocl_context_t *vocp)
{
	int i;

	if (!vg_ocl_create_kernel(vocp, 2, "hash_ec_point_search_prefix"))
		return 0;

	for (i = 0; i < vocp->voc_nslots; i++) {
		if (!vg_ocl_kernel_arg_alloc(vocp, i, 0, 28, 1))
			return 0;
	}
	vocp->voc_rekey_func = vg_ocl_prefix_rekey;
	vocp->voc_check_func = vg_ocl_prefix_check;
	vocp->voc_pattern_rewrite = 1;
	vocp->voc_pattern_alloc = 0;
	return 1;
}


int
vg_ocl_config_pattern(vg_ocl_context_t *vocp)
{
	vg_context_t *vcp = vocp->base.vxc_vc;
	int i;

	i = vg_context_hash160_sort(vcp, NULL);
	if (i > 0) {
		if (vcp->vc_verbose > 1)
			printf("Using OpenCL prefix matcher\n");
		/* Configure for prefix matching */
		return vg_ocl_prefix_init(vocp);
	}

	if (vcp->vc_verbose > 0)
		printf("WARNING: Using CPU pattern matcher\n");
	return vg_ocl_gethash_init(vocp);
}


void *
vg_opencl_thread(void *arg)
{
	vg_ocl_context_t *vocp = (vg_ocl_context_t *) arg;
	vg_context_t *vcp = vocp->base.vxc_vc;
	int halt = 0;
	int slot = -1;
	int rows, cols, invsize;
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
		invsize = vocp->voc_ocl_invsize;
		pthread_mutex_unlock(&vocp->voc_lock);

		gettimeofday(&tv, NULL);
		if (!vg_ocl_kernel_start(vocp, slot, cols, rows, invsize))
			halt = 1;

		if (!vg_ocl_kernel_wait(vocp, slot))
			halt = 1;

		if (vcp->vc_verbose > 1) {
			gettimeofday(&tvt, NULL);
			timersub(&tvt, &tv, &tvd);
			timeradd(&tvd, &busy, &busy);
			if ((busy.tv_sec + idle.tv_sec) > 1) {
				idleu = (1000000 * idle.tv_sec) + idle.tv_usec;
				busyu = (1000000 * busy.tv_sec) + busy.tv_usec;
				pidle = ((double) idleu) / (idleu + busyu);

				if (pidle > 0.01) {
					printf("\rGPU idle: %.2f%%"
					       "                              "
				       "                                \n",
					       100 * pidle);
				}
				memset(&idle, 0, sizeof(idle));
				memset(&busy, 0, sizeof(busy));
			}
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
vg_opencl_loop(vg_context_t *vcp, cl_device_id did, int safe_mode,
	       int worksize, int nthreads, int nrows, int ncols, int invsize)
{
	int i;
	int round, full_threads, wsmult;
	cl_ulong memsize, allocsize;

	const BN_ULONG rekey_max = 100000000;
	BN_ULONG npoints, rekey_at;

	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	EC_POINT **ppbase = NULL, **pprow, *pbatchinc = NULL, *poffset = NULL;
	EC_POINT *pseek = NULL;

	unsigned char *ocl_points_in, *ocl_strides_in;

	vg_ocl_context_t ctx;
	vg_ocl_context_t *vocp = &ctx;
	vg_exec_context_t *vxcp = &vocp->base;

	int slot, nslots;
	int slot_busy = 0, slot_done = 0, halt = 0;
	int c = 0, output_interval = 1000;

	struct timeval tvstart;

	if (!vg_ocl_init(vcp, &ctx, did, safe_mode))
		return NULL;

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	/*
	 * nrows: number of point rows per job
	 * ncols: number of point columns per job
	 * invsize: number of modular inversion tasks per job
	 *    (each task performs (nrows*ncols)/invsize inversions)
	 * nslots: number of kernels
	 *    (create two, keep one running while we service the other or wait)
	 */

	if (!nthreads) {
		/* Pick nthreads sufficient to saturate one compute unit */
		if (vg_ocl_device_gettype(vocp->voc_ocldid) &
		    CL_DEVICE_TYPE_CPU)
			nthreads = 1;
		else
			nthreads = vg_ocl_device_getsizet(vocp->voc_ocldid,
					CL_DEVICE_MAX_WORK_GROUP_SIZE);
	}

	full_threads = vg_ocl_device_getsizet(vocp->voc_ocldid,
					      CL_DEVICE_MAX_COMPUTE_UNITS);
	full_threads *= nthreads;

	/*
	 * The work size should be set to a point of diminishing
	 * returns for the batch size of the heap_invert kernel.
	 * Each value added to the batch trades one complete modular
	 * inversion for four multiply operations.
	 * Selection of a work size depends on the throughput ratio of
	 * the multiply and modular inversion operations.
	 *
	 * The measured value for the OpenSSL implementations on my CPU
	 * is 80:1.  This causes heap_invert to break even with batches
	 * of 20, and receive 10% incremental returns at 200.  The CPU
	 * work size is therefore set to 256.
	 *
	 * The ratio on most GPUs with the oclvanitygen implementations
	 * is closer to 500:1, and larger batches are required for
	 * good performance.
	 */
	if (!worksize) {
		if (vg_ocl_device_gettype(vocp->voc_ocldid) &
		    CL_DEVICE_TYPE_GPU)
			worksize = 2048;
		else
			worksize = 256;
	}

	if (!ncols) {
		memsize = vg_ocl_device_getulong(vocp->voc_ocldid,
					CL_DEVICE_GLOBAL_MEM_SIZE);
		allocsize = vg_ocl_device_getulong(vocp->voc_ocldid,
					CL_DEVICE_MAX_MEM_ALLOC_SIZE);
		memsize /= 2;
		ncols = full_threads;
		nrows = 1;
		/* Find row and column counts close to sqrt(full_threads) */
		while ((ncols > nrows) && !(ncols & 1)) {
			ncols /= 2;
			nrows *= 2;
		}

		/*
		 * Increase row & column counts to satisfy work size
		 * multiplier or fill available memory.
		 */
		wsmult = 1;
		while ((!worksize || (wsmult < worksize)) &&
		       ((ncols * nrows * 2 * 128) < memsize) &&
		       ((ncols * nrows * 2 * 64) < allocsize)) {
			if (ncols > nrows)
				nrows *= 2;
			else
				ncols *= 2;
			wsmult *= 2;
		}
	}

	round = nrows * ncols;

	if (!invsize) {
		invsize = 1;
		while (!(round % (invsize << 1)) &&
		       ((round / invsize) > full_threads))
			invsize <<= 1;
	}

	if (vcp->vc_verbose > 1) {
		printf("Grid size: %dx%d\n", ncols, nrows);
		printf("Modular inverse: %d threads, %d ops each\n",
		       round/invsize, invsize);
	}

	if ((round % invsize) || (invsize & (invsize-1))) {
		if (vcp->vc_verbose <= 1) {
			printf("Grid size: %dx%d\n", ncols, nrows);
			printf("Modular inverse: %d threads, %d ops each\n",
			       round/invsize, invsize);
		}
		if (round % invsize)
			printf("Modular inverse work size must "
			       "evenly divide points\n");
		else
			printf("Modular inverse work per task (%d) "
			       "must be a power of 2\n", invsize);
		goto out;
	}

	nslots = 2;
	slot = 0;
	vocp->voc_ocl_rows = nrows;
	vocp->voc_ocl_cols = ncols;
	vocp->voc_ocl_invsize = invsize;
	vocp->voc_nslots = nslots;

	ppbase = (EC_POINT **) malloc((nrows + ncols) *
				      sizeof(EC_POINT*));
	if (!ppbase)
		goto enomem;

	for (i = 0; i < (nrows + ncols); i++) {
		ppbase[i] = EC_POINT_new(pgroup);
		if (!ppbase[i])
			goto enomem;
	}

	pprow = ppbase + ncols;
	pbatchinc = EC_POINT_new(pgroup);
	poffset = EC_POINT_new(pgroup);
	pseek = EC_POINT_new(pgroup);
	if (!pbatchinc || !poffset || !pseek)
		goto enomem;

	BN_set_word(&vxcp->vxc_bntmp, ncols);
	EC_POINT_mul(pgroup, pbatchinc, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	BN_set_word(&vxcp->vxc_bntmp, round);
	EC_POINT_mul(pgroup, poffset, &vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, poffset, vxcp->vxc_bnctx);

	if (!vg_ocl_config_pattern(vocp))
		goto enomem;

	for (i = 0; i < nslots; i++) {
		/*
		 * Each work group gets its own:
		 * - Column point array
		 */
		if (!vg_ocl_kernel_arg_alloc(vocp, i, 4, 32 * 2 * nrows, 1))
			goto enomem;
	}

	/*
	 * All instances share:
	 * - The z_heap and point scratch spaces
	 * - The row point array
	 */
	if (!vg_ocl_kernel_arg_alloc(vocp, -1, 1,
			     round_up_pow2(32 * 2 * round, 4096), 0) ||
	    !vg_ocl_kernel_arg_alloc(vocp, -1, 2,
			     round_up_pow2(32 * 2 * round, 4096), 0) ||
	    !vg_ocl_kernel_arg_alloc(vocp, -1, 3,
			     round_up_pow2(32 * 2 * ncols, 4096), 1))
		goto enomem;

	npoints = 0;
	rekey_at = 0;
	vxcp->vxc_binres[0] = vcp->vc_addrtype;

	if (pthread_create(&vocp->voc_ocl_thread, NULL,
			   vg_opencl_thread, vocp))
		goto enomem;

	gettimeofday(&tvstart, NULL);

l_rekey:
	if (vocp->voc_rekey_func &&
	    !vocp->voc_rekey_func(vocp))
		goto enomem;

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
	for (i = 1; i < ncols; i++) {
		EC_POINT_add(pgroup,
			     ppbase[i],
			     ppbase[i-1],
			     pgen, vxcp->vxc_bnctx);
	}

	EC_POINTs_make_affine(pgroup, ncols, ppbase, vxcp->vxc_bnctx);

	/* Fill the sequential point array */
	ocl_points_in = (unsigned char *)
		vg_ocl_map_arg_buffer(vocp, 0, 3, 1);
	if (!ocl_points_in)
		goto enomem;
	for (i = 0; i < ncols; i++)
		vg_ocl_put_point_tpa(ocl_points_in, i, ppbase[i]);
	vg_ocl_unmap_arg_buffer(vocp, 0, 3, ocl_points_in);

	/*
	 * Set up the initial row increment table.
	 * Set the first element to pgen -- effectively
	 * skipping the exact key generated above.
	 */
	EC_POINT_copy(pprow[0], pgen);
	for (i = 1; i < nrows; i++) {
		EC_POINT_add(pgroup,
			     pprow[i],
			     pprow[i-1],
			     pbatchinc, vxcp->vxc_bnctx);
	}
	EC_POINTs_make_affine(pgroup, nrows, pprow, vxcp->vxc_bnctx);
	vxcp->vxc_delta = 1;
	npoints = 1;
	slot = 0;
	slot_busy = 0;
	slot_done = 0;

	while (1) {
		if (slot_done) {
			assert(rekey_at > 0);
			slot_done = 0;

			/* Call the result check function */
			switch (vocp->voc_check_func(vocp, slot)) {
			case 1:
				rekey_at = 0;
				break;
			case 2:
				halt = 1;
				break;
			default:
				break;
			}

			c += round;
			if (!halt && (c >= output_interval)) {
				output_interval =
					vg_output_timing(vcp, c, &tvstart);
				c = 0;
			}
		}

		if (halt)
			break;

		if ((npoints + round) < rekey_at) {
			if (npoints > 1) {
				/* Move the row increments forward */
				for (i = 0; i < nrows; i++) {
					EC_POINT_add(pgroup,
						     pprow[i],
						     pprow[i],
						     poffset,
						     vxcp->vxc_bnctx);
				}

				EC_POINTs_make_affine(pgroup, nrows, pprow,
						      vxcp->vxc_bnctx);
			}

			/* Copy the row stride array to the device */
			ocl_strides_in = (unsigned char *)
				vg_ocl_map_arg_buffer(vocp, slot, 4, 1);
			if (!ocl_strides_in)
				goto enomem;
			memset(ocl_strides_in, 0, 64*nrows);
			for (i = 0; i < nrows; i++)
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
				pthread_mutex_unlock(&vocp->voc_lock);
				halt = 1;
				break;
			}

			vocp->voc_ocl_slot = slot;
			pthread_cond_signal(&vocp->voc_wait);
			pthread_mutex_unlock(&vocp->voc_lock);

			slot_done = slot_busy;
			slot_busy = 1;
			slot = (slot + 1) % nslots;

		} else { 
			if (slot_busy) {
				pthread_mutex_lock(&vocp->voc_lock);
				while (vocp->voc_ocl_slot != -1) {
					assert(vocp->voc_ocl_slot ==
					       ((slot + nslots - 1) % nslots));
					pthread_cond_wait(&vocp->voc_wait,
							  &vocp->voc_lock);
				}
				pthread_mutex_unlock(&vocp->voc_lock);
				slot_busy = 0;
				slot_done = 1;
			}

			if (!rekey_at ||
			    (!slot_done && ((npoints + round) >= rekey_at)))
				goto l_rekey;
		}
	}

	if (0) {
	enomem:
		printf("ERROR: allocation failure?\n");
	}

out:
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
	}

	if (ppbase) {
		for (i = 0; i < (nrows + ncols); i++)
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
		vg_ocl_error(NULL, res, "clGetDeviceIDs(0)");
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
			vg_ocl_error(NULL, res, "clGetDeviceIDs(n)");
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
		vg_ocl_error(NULL, res, "clGetPlatformIDs(0)");
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
			vg_ocl_error(NULL, res, "clGetPlatformIDs(n)");
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
			vg_ocl_error(NULL, res, "clGetPlatformInfo(NAME)");
			continue;
		}
		if (len >= sizeof(nbuf))
			len = sizeof(nbuf) - 1;
		nbuf[len] = '\0';
		res = clGetPlatformInfo(ids[i], CL_PLATFORM_VENDOR,
					sizeof(vbuf), vbuf, &len);
		if (res != CL_SUCCESS) {
			vg_ocl_error(NULL, res, "clGetPlatformInfo(VENDOR)");
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
"Usage: %s [-vqrikNTS] [-d <device>] [-f <filename>|-] [<pattern>...]\n"
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
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-S            Safe mode, disable OpenCL loop unrolling optimizations\n"
"-w <worksize> Set work items per thread in a work unit\n"
"-t <threads>  Set target thread count per multiprocessor\n"
"-g <x>x<y>    Set grid size\n"
"-b <invsize>  Set modular inverse ops per thread\n"
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
	char **patterns, *pend;
	int verbose = 1;
	int npatterns = 0;
	int nthreads = 0;
	int worksize = 0;
	int nrows = 0, ncols = 0;
	int invsize = 0;
	int remove_on_match = 1;
	int safe_mode = 0;
	vg_context_t *vcp = NULL;
	cl_device_id did;
	const char *result_file = NULL;

	while ((opt = getopt(argc, argv,
			     "vqrikNTX:p:d:w:t:g:b:Sh?f:o:s:")) != -1) {
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
		case 'p':
			platformidx = atoi(optarg);
			break;
		case 'd':
			deviceidx = atoi(optarg);
			break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
				printf("Invalid work size '%s'\n", optarg);
				return 1;
			}
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				printf("Invalid thread count '%s'\n", optarg);
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
				printf("Invalid grid size '%s'\n", optarg);
				return 1;
			}
			break;
		case 'b':
			invsize = atoi(optarg);
			if (!invsize) {
				printf("Invalid modular inverse size '%s'\n",
				       optarg);
				return 1;
			}
			if (invsize & (invsize - 1)) {
				printf("Modular inverse size must be "
				       "a power of 2\n");
				return 1;
			}
			break;
		case 'S':
			safe_mode = 1;
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

	vg_opencl_loop(vcp, did, safe_mode,
		       worksize, nthreads, nrows, ncols, invsize);
	return 0;
}
