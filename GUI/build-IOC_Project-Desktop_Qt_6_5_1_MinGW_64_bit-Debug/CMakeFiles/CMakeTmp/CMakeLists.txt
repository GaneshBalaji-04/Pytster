cmake_minimum_required(VERSION 3.24.2.0)
cmake_policy(SET CMP0126 OLD)
project(CMAKE_TRY_COMPILE CXX)
set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES "")
set(CMAKE_VERBOSE_MAKEFILE 1)
set(CMAKE_CXX_FLAGS "-DQT_QML_DEBUG")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILE_DEFINITIONS}")
set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EXE_LINKER_FLAGS}")
include_directories(${INCLUDE_DIRECTORIES})
set(CMAKE_SUPPRESS_REGENERATION 1)
link_directories(${LINK_DIRECTORIES})
add_definitions([==[-v]==])
cmake_policy(SET CMP0065 NEW)
cmake_policy(SET CMP0083 OLD)
include("${CMAKE_ROOT}/Modules/Internal/HeaderpadWorkaround.cmake")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "C:/IOC project/build-IOC_Project-Desktop_Qt_6_5_1_MinGW_64_bit-Debug/CMakeFiles/CMakeTmp")
add_executable(cmTC_c39b9 "C:/Qt/Tools/CMake_64/share/cmake-3.24/Modules/CMakeCXXCompilerABI.cpp")
target_link_libraries(cmTC_c39b9 ${LINK_LIBRARIES})
