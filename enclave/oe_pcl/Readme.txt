1. header files of openssl
to use OE PCL for sgx, you must using openssl for those header files:
cmake .. -DBUILD_OPENSSL=ON -DCMAKE_BUILD_TYPE=Debug

2. header files in corelibc
header files in openssl relies on corelibc headers, also need to 
include corelibc headers under ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc

