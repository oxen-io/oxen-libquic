include(ExternalProject)

function(enable_lto)
  if(IPO_ENABLED)
    set_target_properties(${ARGN} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
  endif()
endfunction()

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

# Force shared libs off for any libraries we build inside here so that if we build a shared lib we
# don't end up with a libspdlog.so or whatever that would need to be distributed alongside the
# libquic.so
set(BUILD_SHARED_LIBS OFF)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

include(build_external)
include(add_static_target)
include(system_or_submodule)

find_package(Git)
if(GIT_FOUND)
    message(STATUS "Checking submodules")
    include(check_submodule)
    check_submodule(oxen-logging fmt spdlog)
    check_submodule(oxen-encoding)
endif()

if(NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
endif()

if(NOT TARGET ngtcp2::ngtcp2)
    pkg_check_modules(NGTCP2 libngtcp2>=1.1.0 IMPORTED_TARGET REQUIRED)
    add_library(ngtcp2 INTERFACE)
    target_link_libraries(ngtcp2 INTERFACE PkgConfig::NGTCP2)
    add_library(ngtcp2::ngtcp2 ALIAS ngtcp2)
endif()

if(NOT TARGET ngtcp2::crypto_gnutls)
    pkg_check_modules(NGTCP2_GNUTLS libngtcp2_crypto_gnutls>=1.1.0 IMPORTED_TARGET REQUIRED)
    add_library(ngtcp2_crypto_gnutls INTERFACE)
    target_link_libraries(ngtcp2_crypto_gnutls INTERFACE ngtcp2::ngtcp2 PkgConfig::NGTCP2_GNUTLS)
    add_library(ngtcp2::crypto_gnutls ALIAS ngtcp2_crypto_gnutls)
endif()

# oxen-logging
if (NOT TARGET oxen::logging)
    if(BUILD_STATIC_DEPS)
        set(OXEN_LOGGING_FORCE_SUBMODULES ON CACHE INTERNAL "")
    endif()
    system_or_submodule(OXENLOGGING oxen-logging liboxen-logging>=1.2.0 oxen-logging)
    if(OXENLOGGING_FOUND)
        # If we load oxen-logging via system lib then we won't necessarily have fmt/spdlog targets,
        # but this script will give us them:
        include(oxen-logging/cmake/load_fmt_spdlog.cmake)

        add_library(oxen-logging-fmt-spdlog INTERFACE)
        target_link_libraries(oxen-logging-fmt-spdlog INTERFACE oxen-logging ${OXEN_LOGGING_FMT_TARGET} ${OXEN_LOGGING_SPDLOG_TARGET})
        add_library(oxen::logging ALIAS oxen-logging-fmt-spdlog)
    endif()
endif()

# oxenc
if (NOT TARGET oxenc)
    system_or_submodule(OXENC oxenc liboxenc>=1.4.0 oxen-encoding)
endif()

# libevent
if(NOT TARGET libevent::core)
    add_library(libevent_core INTERFACE)
    pkg_check_modules(LIBEVENT_core libevent_core>=2.1 IMPORTED_TARGET REQUIRED)
    target_link_libraries(libevent_core INTERFACE PkgConfig::LIBEVENT_core)
    add_library(libevent::core ALIAS libevent_core)

    add_library(libevent_threads INTERFACE)
    if(NOT WIN32)
        pkg_check_modules(LIBEVENT_pthreads libevent_pthreads>=2.1 IMPORTED_TARGET REQUIRED)
        target_link_libraries(libevent_threads INTERFACE PkgConfig::LIBEVENT_pthreads)
    endif()
    add_library(libevent::threads ALIAS libevent_threads)
endif()

# gnutls
if(NOT TARGET gnutls::gnutls)
    add_library(gnutls INTERFACE)
    pkg_check_modules(GNUTLS gnutls>=3.7.2 IMPORTED_TARGET REQUIRED)
    target_link_libraries(gnutls INTERFACE PkgConfig::GNUTLS)
    add_library(gnutls::gnutls ALIAS gnutls)
endif()

if(NOT TARGET nettle::nettle)
    add_library(nettle INTERFACE)
    pkg_check_modules(NETTLE nettle IMPORTED_TARGET REQUIRED)
    target_link_libraries(nettle INTERFACE PkgConfig::NETTLE)
    add_library(nettle::nettle ALIAS nettle)
endif()
