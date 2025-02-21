cmake_minimum_required(VERSION 3.13...3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

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

project(libquic
    VERSION 1.2.0
    DESCRIPTION "Modular QUIC library for stream and connection management"
    LANGUAGES ${LANGS})

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(libquic_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(libquic_IS_TOPLEVEL_PROJECT FALSE)
endif()

option(BUILD_SHARED_LIBS "Build as shared library" OFF)
option(BUILD_STATIC_DEPS "Download, build, and statically link against core dependencies" OFF)
option(WARNINGS_AS_ERRORS "treat all warnings as errors. turn off for development, on for release" OFF)
option(LIBQUIC_WARN_DEPRECATED "warn deprecated" ON)
option(LIBQUIC_BUILD_TESTS "Build libquic test suite" ${libquic_IS_TOPLEVEL_PROJECT})
option(LIBQUIC_BUILD_SPEEDTEST "Build libquic speedtest programs" ${libquic_IS_TOPLEVEL_PROJECT})

# This is mainly useful for system packaging to create libquic.so.x.y instead of just libquic.so:
option(LIBQUIC_VERSION_SO "Add the project major/minor version into the shared library filename" OFF)

if (libquic_IS_TOPLEVEL_PROJECT OR BUILD_SHARED_LIBS)
    set(libquic_INSTALL_DEFAULT ON)
else()
    set(libquic_INSTALL_DEFAULT OFF)
endif()
option(LIBQUIC_INSTALL "Add quic libraries/headers/programs to cmake install target; defaults to ON if BUILD_SHARED_LIBS is enabled or we are the top-level project" ${libquic_INSTALL_DEFAULT})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
add_library(libquic_external INTERFACE)

# Interface target for internal flags, include paths, etc. that are PRIVATE for project source
# compilation, but not for potential external targets that depend on us.
add_library(libquic_internal INTERFACE)

configure_file(liboxenquic.pc.in liboxenquic.pc @ONLY)

include(cmake/check_for_std_filesystem.cmake)
target_link_libraries(libquic_external INTERFACE filesystem)

target_include_directories(libquic_external INTERFACE include)
target_include_directories(libquic_internal INTERFACE include/oxen/quic)

if(TARGET libquic_static_deps)
    target_link_libraries(libquic_internal INTERFACE libquic_static_deps)
endif()

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
    list(APPEND warning_flags -Werror -Wno-error=array-bounds) # CI fix for experimental/sid builds
endif()
add_library(libquic_internal-warnings INTERFACE)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 11.0.0)
    target_compile_options(libquic_internal-warnings INTERFACE -fconcepts)
endif()

target_compile_options(libquic_internal-warnings INTERFACE "$<$<OR:$<COMPILE_LANGUAGE:CXX>,$<COMPILE_LANGUAGE:C>>:${warning_flags}>")
target_link_libraries(libquic_internal INTERFACE libquic_internal-warnings)

add_subdirectory(external)
add_subdirectory(src)

if(LIBQUIC_BUILD_TESTS OR LIBQUIC_BUILD_SPEEDTEST)
    add_subdirectory(tests)
endif()

if(LIBQUIC_INSTALL)
    install(
        DIRECTORY include/oxen ${CMAKE_CURRENT_BINARY_DIR}/include/oxen
        TYPE INCLUDE
        FILES_MATCHING PATTERN *.hpp
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/liboxenquic.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif()
