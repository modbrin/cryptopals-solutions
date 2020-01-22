cmake_minimum_required(VERSION 3.15)
project(cryptopals)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

# detect source files, link to openssl and copy inputs near target executable
function(BUILD_SET SET_NAME)
	add_executable(${SET_NAME} ${SET_NAME}/${SET_NAME}_runner.cpp)
	target_link_libraries(${SET_NAME} OpenSSL::Crypto)
	file(GLOB INPUT_FILES "${SET_NAME}/*.txt")
	file(COPY ${INPUT_FILES} DESTINATION ${CMAKE_BINARY_DIR}/${SET_NAME})
endfunction(BUILD_SET)

BUILD_SET("set_1")
BUILD_SET("set_2")