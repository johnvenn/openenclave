# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oeencrypt encryptip.c)

target_include_directories(oeencrypt PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_compile_options(oeencrypt PRIVATE -mrdrnd)
target_link_libraries(oeencrypt oehostmr)

# assemble into proper collector dir
set_property(TARGET oeencrypt PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(
    TARGETS oeencrypt
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT OEHOSTVERIFY)
