include(ExternalProject)

function(enable_lto)
  if(IPO_ENABLED)
    set_target_properties(${ARGN} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
  endif()
endfunction()

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

include(build_external)
include(add_static_target)
include(system_or_submodule)

set(LOCAL_MIRROR "" CACHE STRING "local mirror path/URL for lib downloads")

find_package(Git)
if(GIT_FOUND)
    message(STATUS "Checking submodules")
    include(check_submodule)
    check_submodule(ngtcp2)
    check_submodule(oxen-logging fmt spdlog)
    check_submodule(oxen-encoding)
endif()

find_package(PkgConfig REQUIRED)

# ngtcp2
set(ENABLE_GNUTLS ON CACHE BOOL "")
set(ENABLE_OPENSSL OFF CACHE BOOL "")
set(ENABLE_STATIC_LIB ON CACHE BOOL "")
set(ENABLE_SHARED_LIB OFF CACHE BOOL "")
set(ENABLE_LIB_ONLY OFF CACHE BOOL "")

add_subdirectory(ngtcp2 EXCLUDE_FROM_ALL)
add_library(ngtcp2::ngtcp2 ALIAS ngtcp2_static)  # Base ngtcp2 (no crypto)
add_library(ngtcp2_crypto INTERFACE)
target_link_libraries(ngtcp2_crypto 
    INTERFACE
    ngtcp2::ngtcp2
    ngtcp2_crypto_gnutls_static)
add_library(ngtcp2::crypto
    ALIAS 
    ngtcp2_crypto)  # ngtcp2 crypto (and implicitly base ngtcp2)

# oxen-logging
set(OXEN_LOGGING_SOURCE_ROOT "${PROJECT_SOURCE_DIR}" CACHE INTERNAL "")
add_subdirectory(oxen-logging)

# oxenc
system_or_submodule(OXENC oxenc liboxenc>=1.0.4 oxen-encoding)

# libevent
foreach(libevent_x core pthreads)
    add_library(libevent_${libevent_x} INTERFACE)
    pkg_check_modules(LIBEVENT_${libevent_x} libevent_${libevent_x}>=2.1 IMPORTED_TARGET)
    target_link_libraries(libevent_${libevent_x} INTERFACE PkgConfig::LIBEVENT_${libevent_x})
    add_library(libevent::${libevent_x} ALIAS libevent_${libevent_x})
endforeach()

# gnutls
add_library(gnutls INTERFACE)
pkg_check_modules(GNUTLS gnutls>=3.7.2 IMPORTED_TARGET)
target_link_libraries(gnutls INTERFACE PkgConfig::GNUTLS)
add_library(gnutls::gnutls ALIAS gnutls)
