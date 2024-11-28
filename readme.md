# Fairmath CLI Application

## Description
This application is supposed to use within the FHE app runner provided by fairmath computer actor. It is responsible for FHE key generation and encryption/decryption of user's data. This application relying on OpenFHE library to generate keys and making encryption.

## How To Build
* Install CMake 3.22(or above), gcc or clang 
* Install OpenMP(this is not necessary but highly recommended)
* Clone vcpkg repo and install binary

```shell
$ git clone https://github.com/microsoft/vcpkg.git
$ cd vcpkg && ./bootstrap-vcpkg.sh
```

* Add the following env vars
```shell
$ export VCPKG_ROOT=/path/to/cloned/vcpkg/repo
$ export PATH=$VCPKG_ROOT:$PATH
```

You may also to add these variables to your `.bashrc` file for convenience.
* Clone `fairmath-cli` repository
```shell
$ git clone https://github.com/fairmath/fairmath-cli
```
* Configure cmake and build the project. You should specify vcpkg path, build type and directory for cmake generated file. 
```shell
$ VCPKG_ROOT=/path/to/cloned/vcpkg/repo BUILD_TYPE=Release BIN_DIR=rel cmake --preset=base && cmake --build BUILD/rel
```
All files will be located in `BUILD` directory. You can omit VCPKG_ROOT variable if the one was defined previously(e.g. in the `.bashrc` file)
Also it is possible to create user defined presets for CMake.
Just create the following file in the root of the repository 
CMakeUserPresets.json:
```json
{
    "version": 2,
    "configurePresets": [
      {
        "name": "dbg",
        "inherits": "base",
        "environment": {
          "VCPKG_ROOT": "/path/to/cloned/vcpkg/repo",
          "BUILD_TYPE": "Debug",
          "BIN_DIR": "dbg"
        }
      },
      {
        "name": "rel",
        "inherits": "base",
        "environment": {
          "VCPKG_ROOT": "/path/to/cloned/vcpkg/repo",
          "BUILD_TYPE": "Release",
          "BIN_DIR": "rel"
        }
      }
    ]
}
```
Since that you are able to run the following command to build release configuration
```shell
$ cmake --preset=rel && cmake --build BUILD/rel
```
Change rel to dbg to build a debug configuration.

The very first build could take a time because of vcpkg will build 3rd party libraries for this project. Next builds will be mush faster since 3rd party libraries will be already built and cached.

* Installation
Run cmake install to gather all binary files related to the build.
```shell
$ cmake --install BUILD/rel
```
If you are using provided `CMakeUserPresets.json` then build will be installed to the `BUILD/install` directory.
