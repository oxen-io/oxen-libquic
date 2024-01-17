#pragma once

#if defined(_WIN32) || defined(WIN32)
#define LIBQUICINET_EXPORT __declspec(dllexport)
#else
#define LIBQUICINET_EXPORT __attribute__((visibility("default")))
#endif
#define LIBQUICINET_C_API extern "C" LIBQUICINET_EXPORT
