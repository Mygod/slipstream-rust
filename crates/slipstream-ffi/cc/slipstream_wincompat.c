#ifdef _WIN32

#include "wincompat.h"

#include <windows.h>

int wintimeofday(struct timeval* tv, struct timezone* tz)
{
    static const unsigned long long windows_unix_epoch_delta = 116444736000000000ULL;
    FILETIME filetime;
    ULARGE_INTEGER ticks;

    (void)tz;

    if (tv == NULL) {
        return -1;
    }

    GetSystemTimeAsFileTime(&filetime);
    ticks.LowPart = filetime.dwLowDateTime;
    ticks.HighPart = filetime.dwHighDateTime;

    if (ticks.QuadPart < windows_unix_epoch_delta) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
        return 0;
    }

    ticks.QuadPart -= windows_unix_epoch_delta;
    tv->tv_sec = (long)(ticks.QuadPart / 10000000ULL);
    tv->tv_usec = (long)((ticks.QuadPart % 10000000ULL) / 10ULL);
    return 0;
}

#endif
