cmake_minimum_required (VERSION 3.13)

project(GenPrivateKey)
add_executable (GenPrivateKey GenPrivateKey.cpp)
target_link_libraries(GenPrivateKey ${OPENSSL_CRYPTO_LIBRARY})
