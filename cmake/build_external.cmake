include(ExternalProject)

# Builds a target; takes the target name (e.g. "readline") and builds it in an external project with
# target name suffixed with `_external`.  Its upper-case value is used to get the download details
# (from the variables set above).  The following options are supported and passed through to
# ExternalProject_Add if specified.  If omitted, these defaults are used:
set(build_def_DEPENDS "")
set(build_def_PATCH_COMMAND "")
set(build_def_CONFIGURE_COMMAND ./configure --disable-shared)
set(build_def_BUILD_COMMAND make)
set(build_def_INSTALL_COMMAND make install)
set(build_def_BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/lib___TARGET___.a ${DEPS_DESTDIR}/include/___TARGET___.h)

function(expand_urls output source_file)
  	set(expanded)
  	foreach(mirror ${ARGN})
    	list(APPEND expanded "${mirror}/${source_file}")
  	endforeach()
  	set(${output} "${expanded}" PARENT_SCOPE)
endfunction()

function(build_external target)
  	set(options DEPENDS PATCH_COMMAND CONFIGURE_COMMAND BUILD_COMMAND INSTALL_COMMAND BUILD_BYPRODUCTS)
  	cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "${options}")
  	foreach(o ${options})
    	if(NOT DEFINED arg_${o})
      		set(arg_${o} ${build_def_${o}})
    	endif()
  	endforeach()
  	string(REPLACE ___TARGET___ ${target} arg_BUILD_BYPRODUCTS "${arg_BUILD_BYPRODUCTS}")

	string(TOUPPER "${target}" prefix)
	expand_urls(urls ${${prefix}_SOURCE} ${${prefix}_MIRROR})
	ExternalProject_Add("${target}_external"
		DEPENDS ${arg_DEPENDS}
		BUILD_IN_SOURCE ON
		PREFIX ${DEPS_SOURCEDIR}
		URL ${urls}
		URL_HASH ${${prefix}_HASH}
		DOWNLOAD_NO_PROGRESS ON
		PATCH_COMMAND ${arg_PATCH_COMMAND}
		CONFIGURE_COMMAND ${arg_CONFIGURE_COMMAND}
		BUILD_COMMAND ${arg_BUILD_COMMAND}
		INSTALL_COMMAND ${arg_INSTALL_COMMAND}
		BUILD_BYPRODUCTS ${arg_BUILD_BYPRODUCTS})
endfunction()
