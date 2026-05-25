cmake_minimum_required(VERSION 3.18)
project(cross-sdk-cpp-agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(AUN_CORE_ROOT "/workspace/aun-core" CACHE PATH "AUN C++ SDK root")
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory("${AUN_CORE_ROOT}" "${CMAKE_BINARY_DIR}/aun-core" EXCLUDE_FROM_ALL)

add_executable(cross-sdk-cpp-agent main.cpp)
target_link_libraries(cross-sdk-cpp-agent PRIVATE aun-core)
