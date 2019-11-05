cmake_minimum_required(VERSION 3.5)

project(fastca LANGUAGES CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Botan REQUIRED)
include_directories(SYSTEM ${BOTAN_INCLUDE_DIRS})

add_executable(fastca main.cpp)
target_link_libraries(fastca ${BOTAN_LIBRARIES})