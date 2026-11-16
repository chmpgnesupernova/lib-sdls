cmake_minimum_required(VERSION 3.16)
project(lib_sdls VERSION 0.1.0 LANGUAGES C)

# Ground side SDLP library, loaded by the Python ground system through ctypes.
add_library(sdls SHARED
  src/sdlp/tc_sdlp_my.c
  src/sdlp/tm_sdlp_my.c
  src/sa/sa_default.c
  src/sa/sa_shm_my.c
  src/sdls/sechdr_my.c)

target_include_directories(sdls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# SA/Key DB in POSIX shared memory: process-shared mutex (pthread), shm_open (librt on
# glibc older than 2.34; newer glibc has it in libc and librt is an empty stub).
find_package(Threads REQUIRED)
find_library(RT_LIBRARY rt)
target_link_libraries(sdls PRIVATE Threads::Threads)
if(RT_LIBRARY)
  target_link_libraries(sdls PRIVATE ${RT_LIBRARY})
endif()

set_target_properties(sdls PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON
  VERSION   ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_options(sdls PRIVATE -Wall -Wextra)

# Python ctypes tests in test/ (run with: ctest --test-dir build --output-on-failure)
enable_testing()
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME python_sdlp
    COMMAND ${Python3_EXECUTABLE} -m unittest discover -s ${CMAKE_CURRENT_SOURCE_DIR}/test -v)
  set_tests_properties(python_sdlp PROPERTIES ENVIRONMENT "SDLS_LIB=$<TARGET_FILE:sdls>")
endif()
