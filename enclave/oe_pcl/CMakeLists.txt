# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OE_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(EDL_DIR ${PROJECT_SOURCE_DIR}/include/openenclave/edl)

set(NIPX ".nipx")
set(NIPD ".nipd")
set(NIPRODT ".niprod")

#just as in Makefile

file(GLOB PCL_ASM_SRC "crypto/*.s")
file(GLOB PCL_CRYPTO_SRC "crypto/*.c")
#file(GLOB PCL_UNSEAL_SRC "unseal/*.c")
set(PCL_SRC_LIST pcl_entry.c)
list(APPEND PCL_SRC_LIST
	pcl_mem.c
	${PCL_CRYPTO_SRC}
	${PCL_ASM_SRC}
	#	${PCL_UNSEAL_SRC}
	)
#set(PCL_OBJ_FILES "pcl_entry.c.o" "pcl_mem.c.o")

set(PCL_OBJ_DIR ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/oepcl.dir)
#set(PCL_ENTRY_OBJ ${PCL_OBJ_DIR}/pcl_entry.c.o)

#set(PCL_MEM_OBJ ${PCL_OBJ_DIR}/pcl_mem.c.o)

# add target
add_enclave_library(oepcl STATIC pcl_entry.c pcl_mem.c)
#custom command output --> .c.o files and rename-section to nipx nipd
#add_custom_command(
#  TARGET oepcl
#  POST_BUILD
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_ENTRY_OBJ} --rename-section .text=${NIPX}
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_ENTRY_OBJ} --rename-section .data=${NIPD}
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_ENTRY_OBJ} --rename-section .rodata=${NIPRODT})

#add_custom_command(
#  TARGET oepcl
#  POST_BUILD
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_MEM_OBJ} --rename-section .text=${NIPX}
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_MEM_OBJ} --rename-section .data=${NIPD}
#  COMMAND ${CMAKE_OBJCOPY} ${PCL_MEM_OBJ} --rename-section .rodata=${NIPRODT})

enclave_include_directories(oepcl PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(oepcl PUBLIC oe_includes)

foreach( sourcefile IN LISTS PCL_SRC_LIST )
	string( REPLACE ".c" ".c.o" src_obj ${sourcefile} )
	add_custom_command(
		TARGET oepcl
		POST_BUILD
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .text=${NIPX}
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .data=${NIPD}
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .rodata=${NIPRODT})
endforeach( sourcefile )

foreach( sourcefile IN LISTS PCL_ASM_SRC )
	string( REPLACE ".s" ".o" src_obj ${sourcefile} )
	add_custom_command(
		TARGET oepcl
		POST_BUILD
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .text=${NIPX}
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .data=${NIPD}
		COMMAND ${CMAKE_OBJCOPY} ${src_obj} --rename-section .rodata=${NIPRODT})
endforeach( sourcefile )

enclave_enable_code_coverage(oepcl)

#enclave_link_libraries(oepcl PUBLIC oembedtls)
enclave_include_directories(oepcl PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(oepcl PUBLIC oe_includes)

if (OE_SGX)
  enclave_compile_options(
    oepcl
    PUBLIC
    -fPIE
    -nostdinc
    -fstack-protector-strong
    -fvisibility=hidden
    # Preserve frame-pointer in Release mode to enable oe_backtrace.
    #-fno-omit-frame-pointer
    # Put each function or data in its own section.
    # This allows aggressively eliminating unused code.
    # "The default without -fpic is 'initial-exec'; with -fpic the
    # default is 'global-dynamic'."
    # https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html#Code-Gen-Options
    #
    # Enclaves are linked using -pie and therefore global-dynamic is
    # too conservative. Of the two efficient static thread-local
    # storage models, inital-exec and local-exec, we choose the most
    # optimal one.
    -ftls-model=local-exec
    # Disable builtin functions for enclaves, but only in our build.
    #
    # We do this to work-around compiler bugs (see #1429) due to our
    # redefinition of `memmove` to `oe_memmove` causing an undefined
    # symbol error when a built-in was inlined. However, we only do
    # this for our code as we don't want to force these flags on the
    # user. There are valid reasons for an end user to use built-ins.
    $<BUILD_INTERFACE:-fno-builtin-malloc
    -fno-builtin-calloc
    -fno-builtin>)
elseif (OE_TRUSTZONE)
  enclave_compile_options(oepcl PUBLIC -fvisibility=hidden ${OE_TZ_TA_C_FLAGS})
endif ()

enclave_compile_options(oepcl INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

#enclave_compile_options(oepcl INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

#maybe_build_using_clangw(oepcl)

#if (CMAKE_C_COMPILER_ID MATCHES GNU)
# enclave_compile_options(oepcl PRIVATE -Wjump-misses-init)
#endif ()

set_enclave_property(TARGET oepcl PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oepcl
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
