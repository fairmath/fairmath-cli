cmake_minimum_required(VERSION 3.22)

project(fairmath_cli CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(OpenFHE CONFIG REQUIRED)

if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
link_libraries(${OpenFHE_SHARED_LIBRARIES})

find_package(Boost REQUIRED COMPONENTS program_options)
add_executable(fairmath_cli fairmath_cli.cpp)

target_link_libraries(fairmath_cli -ltcmalloc_minimal -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free ${Boost_PROGRAM_OPTIONS_LIBRARY})

