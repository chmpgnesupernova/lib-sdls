cmake_minimum_required(VERSION 3.16)
project(lib_sdls VERSION 0.1.0 LANGUAGES C)

# Ground side SDLP library, loaded by the Python ground system through ctypes.
add_library(sdls SHARED
  src/sdlp/tc_sdlp_my.c
  src/sdlp/tm_sdlp_my.c)

target_include_directories(sdls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(sdls PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON
  VERSION   ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_options(sdls PRIVATE -Wall -Wextra)
