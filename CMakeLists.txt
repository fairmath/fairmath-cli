cmake_minimum_required(VERSION 3.22)

project(fairmath-keygen CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(OpenFHE CONFIG REQUIRED)
find_path(NLOHMANN_JSON_INCLUDE_DIRS "nlohmann/adl_serializer.hpp")

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

include_directories(
    ${OPENMP_INCLUDES} 
    ${OpenFHE_INCLUDE} 
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
    ${NLOHMANN_JSON_INCLUDE_DIRS}
    )

find_package(Boost REQUIRED COMPONENTS program_options)
add_executable(fairmath-keygen fairmathCli.cpp)

target_include_directories(fairmath-keygen PRIVATE ${NLOHMANN_JSON_INCLUDE_DIRS})
target_link_libraries(fairmath-keygen PRIVATE ${OpenFHE_LIBRARIES} Boost::program_options -ltcmalloc_minimal -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free)

