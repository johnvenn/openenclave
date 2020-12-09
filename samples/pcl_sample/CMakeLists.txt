# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Configure the cmake to use customized compilation toolchain.
  # This package has to be added before `project()`.
  find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
endif ()

project("Protected Code Loader Sample" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/pcl.conf private.pem
  COMMAND openenclave::oesign sign -e enclave/enclave -c
          ${CMAKE_SOURCE_DIR}/enclave/pcl.conf -k private.pem)

#Encrypt Enclave
add_custom_command(
  OUTPUT enclave/enclave.enc
  DEPENDS enclave
  COMMAND openenclave::oeencrypt -i enclave/enclave -o enclave/enclave.enc -k
		  ${CMAKE_SOURCE_DIR}/enclave/debug_mock_128bit_key.bin -d)

add_custom_command(
  OUTPUT enclave/enclave.enc.signed
  DEPENDS enclave enclave/pcl.conf private.pem
  COMMAND openenclave::oesign sign -e enclave/enclave.enc -c
	     ${CMAKE_SOURCE_DIR}/enclave/pcl.conf -k private.pem)

add_custom_target(encrypt ALL DEPENDS enclave/enclave.enc)

#add_custom_target(sign ALL DEPENDS enclave/enclave.signed)
add_custom_target(sign ALL DEPENDS enclave/enclave.signed enclave/enclave.enc.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS pcl_host sign
    COMMAND pcl_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS pcl_host sign
  COMMAND pcl_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
