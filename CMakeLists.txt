cmake_minimum_required(VERSION 3.13)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

option(BUILD_SHARED_LIBS "Build as shared library" OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LANGS C CXX)
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
	foreach(lang ${LANGS})
    	if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      		message(STATUS "Enabling ccache for ${lang}")
      		set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    	endif()
  endforeach()
endif()

project(libquicinet 
    VERSION 0.0.5
    DESCRIPTION "Modular QUIC library for stream and connection management"
    LANGUAGES ${LANGS})

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

option(WITH_LTO "enable lto on compile time" OFF)
if(WITH_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
    if(IPO_ENABLED)
        message(STATUS "LTO enabled")
    else()
        message(WARNING "LTO not supported by compiler: ${ipo_error}")
    endif()
else()
    message(STATUS "LTO disabled")
    set(IPO_ENABLED OFF)
endif()

set(IPO_ENABLED OFF)
if(IPO_ENABLED AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

include(GNUInstallDirs)
include(combine_archives)

# Interface target for any general includes, flags, etc. that is meant to be inherited publicly.
add_library(common INTERFACE)
# Interface target for internal flags, include paths, etc. that are PRIVATE for project source
# compilation, but not for potential external targets that depend on us.
add_library(internal INTERFACE)

target_include_directories(common INTERFACE include)
target_include_directories(internal INTERFACE include/quic)

if(WARNINGS_AS_ERRORS)
    target_compile_options(internal INTERFACE -Werror)
endif()

add_subdirectory(external)
add_subdirectory(src)
add_subdirectory(tests)

