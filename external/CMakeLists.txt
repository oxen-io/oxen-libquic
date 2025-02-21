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
    check_submodule(ngtcp2)
    check_submodule(oxen-logging fmt spdlog)
    check_submodule(oxen-encoding)
endif()

if(NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
endif()

if(NOT BUILD_STATIC_DEPS)
    pkg_check_modules(NGTCP2 libngtcp2>=1.1.0 IMPORTED_TARGET)
    if(NGTCP2_FOUND)
        pkg_check_modules(NGTCP2_GNUTLS libngtcp2_crypto_gnutls>=1.1.0 IMPORTED_TARGET)
        if(NGTCP2_GNUTLS_FOUND)
            add_library(ngtcp2 INTERFACE)
            add_library(ngtcp2_crypto INTERFACE)
            target_link_libraries(ngtcp2 INTERFACE PkgConfig::NGTCP2)
            add_library(ngtcp2::ngtcp2 ALIAS ngtcp2)

            target_link_libraries(ngtcp2_crypto INTERFACE ngtcp2::ngtcp2 PkgConfig::NGTCP2_GNUTLS)
            add_library(ngtcp2::crypto ALIAS ngtcp2_crypto)
        endif()
    endif()
endif()

if(NOT NGTCP2_FOUND OR NOT NGTCP2_GNUTLS_FOUND)
# ngtcp2
    set(ENABLE_GNUTLS ON CACHE BOOL "")
    set(ENABLE_OPENSSL OFF CACHE BOOL "")
    set(ENABLE_STATIC_LIB ON CACHE BOOL "")
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "")
    set(ENABLE_LIB_ONLY OFF CACHE BOOL "")
    set(BUILD_TESTING OFF CACHE BOOL "")

    add_subdirectory(ngtcp2 EXCLUDE_FROM_ALL)
    add_library(ngtcp2::ngtcp2 ALIAS ngtcp2_static)  # Base ngtcp2 (no crypto)
    add_library(ngtcp2_crypto INTERFACE)
    if(BUILD_STATIC_DEPS AND TARGET gnutls::gnutls)
        target_link_libraries(ngtcp2_crypto_gnutls_static PUBLIC gnutls::gnutls)
    endif()
    target_link_libraries(ngtcp2_crypto
        INTERFACE
        ngtcp2::ngtcp2
        ngtcp2_crypto_gnutls_static)
    add_library(ngtcp2::crypto
        ALIAS
        ngtcp2_crypto)  # ngtcp2 crypto (and implicitly base ngtcp2)
endif()

# oxen-logging
if (NOT TARGET oxen::logging)
    message(STATUS "Target oxen::logging not found; using submodule")
    if(BUILD_STATIC_DEPS)
        set(OXEN_LOGGING_FORCE_SUBMODULES ON CACHE INTERNAL "")
    endif()
    add_subdirectory(oxen-logging)
else()
    message(STATUS "Target oxen::logging already found!")
endif()
oxen_logging_add_source_dir("${PROJECT_SOURCE_DIR}")

# oxenc
if (NOT TARGET oxenc)
    system_or_submodule(OXENC oxenc liboxenc>=1.2.0 oxen-encoding)
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
