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

system_or_submodule(LIBUV uv_a libuv>=1.44.2 libuv)

add_library(uvw INTERFACE)
target_include_directories(uvw INTERFACE uvw/src)
target_link_libraries(uvw INTERFACE uv_a::uv_a)

set(GNUTLS_VERSION 
    3.7.2 
    CACHE STRING "gnutls version")
set(GNUTLS_MIRROR 
    ${LOCAL_MIRROR} https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7/
    CACHE STRING "gnutls mirror")
set(GNUTLS_SOURCE
    gnutls-${GNUTLS_VERSION}.tar.gz)
set(GNUTLS_HASH
    SHA512=94a4836d12ec96437ee299707caeac317cbb3e84bb2259c62132b4817d0c8a38ec08cb01fc8f5f54dfc0dd6698040ca94e6a6afdd8802823a9940c48eeae1fd8
    CACHE STRING "gnutls source hash")

build_external(gnutls
    CONFIGURE_COMMAND ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-tests --disable-doc
    BUILD_COMMAND make -j)
add_static_target(gnutls gnutls-external gnutls.a)

# ngtcp2 needs some massaging to build nicely:
include(ngtcp2_lib)
add_ngtcp2_lib()
