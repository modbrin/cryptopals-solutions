cmake_minimum_required(VERSION 3.15)
project(cryptopals)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

# detect source files, link to openssl and copy inputs near target executable
function(BUILD_SET SET_NAME)
	add_executable(${SET_NAME} ${SET_NAME}_src/${SET_NAME}_runner.cpp)
	target_link_libraries(${SET_NAME} OpenSSL::Crypto)
	file(GLOB INPUT_FILES_${SET_NAME} ${SET_NAME}_src/*.txt)
	file(COPY ${INPUT_FILES_${SET_NAME}} DESTINATION ${CMAKE_BINARY_DIR}/${SET_NAME}_src)
endfunction(BUILD_SET)

BUILD_SET(set_1)
BUILD_SET(set_2)