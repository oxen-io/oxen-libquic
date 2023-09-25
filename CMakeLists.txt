cmake_minimum_required(VERSION 3.13...3.25)

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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_STATIC_DEPS "Download, build, and statically link against core dependencies" OFF)

set(default_lto ON)
if(WIN32 OR BUILD_STATIC_DEPS)
    set(default_lto OFF)
endif()
option(WITH_LTO "Compile with Link-time Optimization" ${default_lto})
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

if(BUILD_STATIC_DEPS)
  include(cmake/StaticBuild.cmake)
endif()

# Interface target for any general includes, flags, etc. that is meant to be inherited publicly.
add_library(common INTERFACE)
# Interface target for internal flags, include paths, etc. that are PRIVATE for project source
# compilation, but not for potential external targets that depend on us.
add_library(internal INTERFACE)

include(cmake/check_for_std_filesystem.cmake)
target_link_libraries(common INTERFACE filesystem)

target_include_directories(common INTERFACE include)
target_include_directories(internal INTERFACE include/quic)

option(WARNINGS_AS_ERRORS "treat all warnings as errors. turn off for development, on for release" OFF)
option(LIBQUIC_WARN_DEPRECATED "warn deprecated" ON)

set(warning_flags -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function -Werror=vla)
if (LIBQUIC_WARN_DEPRECATED)
    list(APPEND warning_flags -Wdeprecated-declarations)
else()
    list(APPEND warning_flags -Wno-deprecated-declarations)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND warning_flags -Wno-unknown-warning-option)
endif()
if (WARNINGS_AS_ERRORS)
    list(APPEND warning_flags -Werror)
endif()
add_library(internal-warnings INTERFACE)
target_compile_options(internal-warnings INTERFACE "$<$<OR:$<COMPILE_LANGUAGE:CXX>,$<COMPILE_LANGUAGE:C>>:${warning_flags}>")
target_link_libraries(internal INTERFACE internal-warnings)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(libquic_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(libquic_IS_TOPLEVEL_PROJECT FALSE)
endif()

option(BUILD_TESTS "Build libquic test suite and programs" ${libquic_IS_TOPLEVEL_PROJECT})

add_subdirectory(external)
add_subdirectory(src)

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
