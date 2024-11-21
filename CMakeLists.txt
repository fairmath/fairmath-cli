cmake_minimum_required(VERSION 3.22)

project(fairmath-keygen CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "\${ORIGIN}/lib")

find_package(OpenMP)
find_package(Boost REQUIRED COMPONENTS program_options)
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
    ${OpenFHE_INCLUDE} 
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
    ${NLOHMANN_JSON_INCLUDE_DIRS}
)

set(SOURCES 
    src/fairmathCli.cpp
)

add_executable(fairmath-keygen ${SOURCES})

if (OpenMP_CXX_FOUND)
    message(STATUS "FOUND OpenMP: ${OpenMP_CXX_LIBRARIES}")
    message(STATUS "FOUND OpenMP Dir: ${OpenMP_libomp_LIBRARY}")

    #workaround for macos github actions
    set(lib_openmp_path "${OpenMP_libomp_LIBRARY}")
    cmake_path(GET lib_openmp_path PARENT_PATH OMP_LINK_DIR)

    target_link_directories(fairmath-keygen PRIVATE ${OMP_LINK_DIR})
endif()

target_include_directories(fairmath-keygen PRIVATE ${NLOHMANN_JSON_INCLUDE_DIRS})
target_link_libraries(fairmath-keygen PRIVATE ${OpenFHE_LIBRARIES} Boost::program_options)

install(TARGETS fairmath-keygen DESTINATION install)
