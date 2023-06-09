set(CMAKE_SYSTEM_VERSION 6.0)

# the minimum windows version, set to 6 rn because supporting older windows is hell
set(_winver 0x0600)
add_definitions(-D_WIN32_WINNT=${_winver})

# target environment on the build host system
# second one is for non-root installs
set(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_PATHS})

add_definitions("-DWINNT_CROSS_COMPILE")

# modify default behavior of FIND_XXX() commands
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# cross compilers to use
if($ENV{COMPILER} MATCHES "clang")
    set(USING_CLANG ON)
    set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-clang)
    set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-clang++)
else()
    set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc${TOOLCHAIN_SUFFIX})
    set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++${TOOLCHAIN_SUFFIX})
endif()

set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
set(ARCH_TRIPLET ${CROSS_TARGET})
