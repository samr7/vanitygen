#include <tchar.h>
#include <time.h>
#include <windows.h> 

#define INLINE
#define snprintf _snprintf


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
			count++;
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

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone;

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (NULL != tv) {
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		tmpres -= DELTA_EPOCH_IN_MICROSECS; 
		tmpres /= 10;
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	return 0;
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

TCHAR *optarg;
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
#pragma section(".CRT$XIC",long,read)
int __cdecl __initptw32(void);
#define _CRTALLOC(x) __declspec(allocate(x))
_CRTALLOC(".CRT$XIC")
static int (*pinit)(void) = __initptw32;
int __cdecl
__initptw32(void)
{
	pthread_win32_process_attach_np();
	return 0;
}
#endif  /* defined(PTW32_STATIC_LIB) */
