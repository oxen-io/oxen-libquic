include(ExternalProject)

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
    check_submodule(libuv)
    check_submodule(uvw)
endif()

find_package(PkgConfig REQUIRED)

system_or_submodule(LIBUV uv_a libuv>=1.43.0 libuv)

add_library(uvw INTERFACE)
target_include_directories(uvw INTERFACE uvw/src)
target_link_libraries(uvw INTERFACE uv_a::uv_a)

set(GNUTLS_VERSION 
    3.7.2 
    CACHE STRING "gnutls version")
set(GNUTLS_MIRROR 
    ${LOCAL_MIRROR} https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7
    CACHE STRING "gnutls mirror")
set(GNUTLS_SOURCE
    gnutls-${GNUTLS_VERSION}.tar.xz)
set(GNUTLS_HASH
    SHA512=5d01d561a05379da71e4847e30ba13c2abe09f7a5c4359fd539d8bd19abad0ce87120f82ee7b6264e787bd3edbc5ae16beffa892983cbc3d59f11a1811c10329
    CACHE STRING "gnutls source hash")

build_external(gnutls
    CONFIGURE_COMMAND ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-tests --disable-doc
    BUILD_COMMAND make -j)
add_static_target(gnutls gnutls-external gnutls.a)

# ngtcp2 needs some massaging to build nicely:
include(ngtcp2_lib)
add_ngtcp2_lib()
