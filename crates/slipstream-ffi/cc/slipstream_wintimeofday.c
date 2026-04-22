#ifdef _WINDOWS

#include "wincompat.h"

#include <Windows.h>
#include <stdint.h>

int wintimeofday(struct timeval *tv, struct timezone *tz)
{
    if (tv != NULL) {
        FILETIME ft;
        uint64_t tmp;
        static const uint64_t EPOCH_DIFF = 116444736000000000ULL;

        GetSystemTimeAsFileTime(&ft);
        tmp = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        tmp -= EPOCH_DIFF;
        tv->tv_sec = (long)(tmp / 10000000ULL);
        tv->tv_usec = (long)((tmp % 10000000ULL) / 10);
    }

    if (tz != NULL) {
        TIME_ZONE_INFORMATION tzinfo;
        GetTimeZoneInformation(&tzinfo);
        tz->tz_minuteswest = tzinfo.Bias;
        tz->tz_dsttime = 0;
    }

    return 0;
}

#endif
