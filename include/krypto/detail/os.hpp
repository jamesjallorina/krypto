// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/common.hpp>

#include <cstdio>
#include <ctime>
#include <functional>
#include <string>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <sys/syscall.h> //Use gettid() syscall under linux to get thread id
#include <unistd.h>
#include <chrono>

namespace krypto
{
namespace detail
{
namespace os
{

inline krypto::log_clock::time_point now()
{
    return log_clock::now();
}

inline std::tm localtime(const std::time_t &time_tt)
{
    std::tm tm;
    localtime_r(&time_tt, &tm);

    return tm;
}

inline std::tm localtime()
{
    std::time_t now_t = time(nullptr);
    return localtime(now_t);
}


inline std::tm gmtime(const std::time_t &time_tt)
{
    std::tm tm;
    gmtime_r(&time_tt, &tm);

    return tm;
}

inline std::tm gmtime()
{
    std::time_t now_t = time(nullptr);
    return gmtime(now_t);
}

inline bool operator==(const std::tm& tm1, const std::tm& tm2)
{
    return (tm1.tm_sec == tm2.tm_sec &&
            tm1.tm_min == tm2.tm_min &&
            tm1.tm_hour == tm2.tm_hour &&
            tm1.tm_mday == tm2.tm_mday &&
            tm1.tm_mon == tm2.tm_mon &&
            tm1.tm_year == tm2.tm_year &&
            tm1.tm_isdst == tm2.tm_isdst);
}

inline bool operator!=(const std::tm& tm1, const std::tm& tm2)
{
    return !(tm1 == tm2);
}

#define KRYPTO_EOL "\n"

KRYPTO_CONSTEXPR static const char* eol = KRYPTO_EOL;
KRYPTO_CONSTEXPR static int eol_size = sizeof(KRYPTO_EOL) - 1;

inline int fopen_s(FILE** fp, const filename_t& filename, const filename_t& mode)
{
    *fp = fopen((filename.c_str()), mode.c_str());
    return *fp == nullptr;
}

inline int remove(const filename_t &filename)
{
    return std::remove(filename.c_str());
}

inline int rename(const filename_t& filename1, const filename_t& filename2)
{
    return std::rename(filename1.c_str(), filename2.c_str());
}


//Return if file exists
inline bool file_exists(const filename_t& filename)
{
    //common linux/unix all have the stat system call
    struct stat buffer;
    return (stat (filename.c_str(), &buffer) == 0);
}




//Return file size according to open FILE* object
inline size_t filesize(FILE *f)
{
	if (f == nullptr)
		throw krypto_ex("Failed getting file size. fd is null");

	int fd = fileno(f);
	//64 bits(but not in osx, where fstat64 is deprecated)
#if !defined(__APPLE__) && (defined(__x86_64__) || defined(__ppc64__)) 
	struct stat64 st;
	if (fstat64(fd, &st) == 0)
		return st.st_size;	
#else // unix 32 bits or osx	
	struct stat st;
	if (fstat(fd, &st) == 0)
		return st.st_size;	
#endif
	throw krypto_ex("Failed getting file size from fd", errno);
}




//Return utc offset in minutes or throw krypto_ex on failure
inline int utc_minutes_offset(const std::tm& tm = detail::os::localtime())
{
    return static_cast<int>(tm.tm_gmtoff / 60);
}

//Return current thread id as size_t
//It exists because the std::this_thread::get_id() is much slower(espcially under VS 2013)
inline size_t thread_id()
{
#ifdef __linux__
# if defined(__ANDROID__) && defined(__ANDROID_API__) && (__ANDROID_API__ < 21)
#  define SYS_gettid __NR_gettid
# endif
    return  static_cast<size_t>(syscall(SYS_gettid));
#else //Default to standard C++11 (OSX and other Unix)
    return static_cast<size_t>(std::hash<std::thread::id>()(std::this_thread::get_id()));
#endif
}

#define KRYPTO_FILENAME_T(s) s
inline std::string filename_to_str(const filename_t& filename)
{
    return filename;
}

} // namespace os
} // namespace detail
} // namespace krypto