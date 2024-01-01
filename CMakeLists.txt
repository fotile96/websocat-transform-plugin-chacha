cmake_minimum_required(VERSION 3.26)
project(websocat-plugin)

find_library(cryptopp NAMES cryptopp)

add_library(foo SHARED foo.cpp)
target_link_libraries(foo -static-libstdc++ libcryptopp.a)
