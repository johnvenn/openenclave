to use OE PCL for sgx, you must using openssl for those header files:
cmake .. -DBUILD_OPENSSL=ON -DCMAKE_BUILD_TYPE=Debug
