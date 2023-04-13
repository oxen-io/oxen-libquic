function(add_static_target target ext_target libname)
	add_library(${target} STATIC IMPORTED GLOBAL)
	add_dependencies(${target} ${ext_target})
	set_target_properties(${target} PROPERTIES
		IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
	)
endfunction()
