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

#include <windows.h>
#include <stdio.h>
#include <pthread.h> 
#include "winglue.h"

int
count_processors(void)
{
	typedef BOOL (WINAPI *LPFN_GLPI)(
		PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
	LPFN_GLPI glpi;
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL, ptr;
	DWORD size = 0, count = 0, pos = 0, i, ret;

	glpi = (LPFN_GLPI) GetProcAddress(GetModuleHandle(TEXT("kernel32")),
					  "GetLogicalProcessorInformation");
	if (!glpi)
		return -1;

	while (1) {
		ret = glpi(buffer, &size);
		if (ret)
			break;
		if (buffer)
			free(buffer);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return -1;
		buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION) malloc(size);
		if (!buffer)
			return -1;
	}

	for (ptr = buffer;
	     (pos + sizeof(*ptr)) <= size;
	     ptr++, pos += sizeof(*ptr)) {
		switch (ptr->Relationship) {
		case RelationProcessorCore:
			for (i = ptr->ProcessorMask; i != 0; i >>= 1) {
				if (i & 1)
					count++;
			}
			break;
		default:
			break;
		}
	}

	if (buffer)
		free(buffer);
	return count;
}


/*
 * struct timeval compatibility for Win32
 */

#define TIMESPEC_TO_FILETIME_OFFSET \
	  ( ((unsigned __int64) 27111902 << 32) + \
	    (unsigned __int64) 3577643008 )

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;

	if (NULL != tv) {
		GetSystemTimeAsFileTime(&ft);

		tv->tv_sec = (int) ((*(unsigned __int64 *) &ft -
				     TIMESPEC_TO_FILETIME_OFFSET) /
				    10000000);
		tv->tv_usec = (int) ((*(unsigned __int64 *) &ft - 
				      TIMESPEC_TO_FILETIME_OFFSET -
				      ((unsigned __int64) tv->tv_sec *
				       (unsigned __int64) 10000000)) / 10);
	}

	return 0;
}

void
timeradd(struct timeval *a, struct timeval *b, struct timeval *result)
{
	result->tv_sec = a->tv_sec + b->tv_sec;
	result->tv_usec = a->tv_usec + b->tv_usec;
	if (result->tv_usec > 10000000) {
		result->tv_sec++;
		result->tv_usec -= 1000000;
	}
}

void
timersub(struct timeval *a, struct timeval *b, struct timeval *result)
{
	result->tv_sec = a->tv_sec - b->tv_sec;
	result->tv_usec = a->tv_usec - b->tv_usec;
	if (result->tv_usec < 0) {
		result->tv_sec--;
		result->tv_usec += 1000000;
	}
}

/*
 * getopt() for Win32 -- public domain ripped from codeproject.com
 */

TCHAR *optarg = NULL;
int optind = 0;

int getopt(int argc, TCHAR *argv[], TCHAR *optstring)
{
	static TCHAR *next = NULL;
	TCHAR c;
	TCHAR *cp;

	if (optind == 0)
		next = NULL;

	optarg = NULL;

	if (next == NULL || *next == _T('\0'))
	{
		if (optind == 0)
			optind++;

		if (optind >= argc || argv[optind][0] != _T('-') || argv[optind][1] == _T('\0'))
		{
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return EOF;
		}

		if (_tcscmp(argv[optind], _T("--")) == 0)
		{
			optind++;
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return EOF;
		}

		next = argv[optind];
		next++;		// skip past -
		optind++;
	}

	c = *next++;
	cp = _tcschr(optstring, c);

	if (cp == NULL || c == _T(':'))
		return _T('?');

	cp++;
	if (*cp == _T(':'))
	{
		if (*next != _T('\0'))
		{
			optarg = next;
			next = NULL;
		}
		else if (optind < argc)
		{
			optarg = argv[optind];
			optind++;
		}
		else
		{
			return _T('?');
		}
	}

	return c;
}

/*
 * If ptw32 is being linked in as a static library, make sure that
 * its process attach function gets called before main().
 */
#if defined(PTW32_STATIC_LIB)

int __cdecl __initptw32(void);

#if defined(_MSC_VER)
class __constructme { public: __constructme() { __initptw32(); } } __vg_pinit;
#define CONSTRUCTOR_TYPE __cdecl
#elif defined(__GNUC__)
#define CONSTRUCTOR_TYPE __cdecl __attribute__((constructor))
#else
#error "Unknown compiler -- can't mark constructor"
#endif

int CONSTRUCTOR_TYPE
__initptw32(void)
{
	pthread_win32_process_attach_np();
	return 0;
}
#endif  /* defined(PTW32_STATIC_LIB) */
