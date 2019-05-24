cmake_minimum_required (VERSION 3.13)

project(Hash)
add_executable (Hash Hash.cpp)
target_link_libraries(Hash ${OPENSSL_CRYPTO_LIBRARY})
