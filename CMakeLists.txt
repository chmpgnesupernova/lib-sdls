cmake_minimum_required(VERSION 3.16)
project(lib_sdls VERSION 0.2.0 LANGUAGES C)

# Ground side SDLP/SDLS library, loaded by the Python ground system through ctypes.

# --- crypto backend -------------------------------------------------------------------------
# One backend file implements src/crypto/crypto_my.h. A partner implementation adds its own
# file and a value here; nothing outside src/crypto changes.
set(SDLS_CRYPTO_BACKEND "wolfssl" CACHE STRING "Crypto backend (wolfssl)")
set_property(CACHE SDLS_CRYPTO_BACKEND PROPERTY STRINGS wolfssl)

if(SDLS_CRYPTO_BACKEND STREQUAL "wolfssl")
  # wolfSSL built with: --enable-aesgcm --enable-mlkem --enable-mldsa (HKDF is on by default).
  # Point WOLFSSL_ROOT (or CMAKE_PREFIX_PATH / PKG_CONFIG_PATH) at a non system install.
  set(WOLFSSL_ROOT "" CACHE PATH "wolfSSL install prefix (optional)")
  if(WOLFSSL_ROOT)
    list(APPEND CMAKE_PREFIX_PATH ${WOLFSSL_ROOT})
  endif()
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(WOLFSSL QUIET IMPORTED_TARGET wolfssl)
  endif()
  if(TARGET PkgConfig::WOLFSSL)
    set(SDLS_CRYPTO_LIBS PkgConfig::WOLFSSL)
  else()
    find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h REQUIRED)
    find_library(WOLFSSL_LIBRARY wolfssl REQUIRED)
    add_library(sdls_wolfssl INTERFACE)
    target_include_directories(sdls_wolfssl INTERFACE ${WOLFSSL_INCLUDE_DIR})
    target_link_libraries(sdls_wolfssl INTERFACE ${WOLFSSL_LIBRARY})
    set(SDLS_CRYPTO_LIBS sdls_wolfssl)
  endif()
  set(SDLS_CRYPTO_SOURCES src/crypto/crypto_wolfssl.c src/crypto/crypto_registry.c)
else()
  message(FATAL_ERROR "Unknown SDLS_CRYPTO_BACKEND '${SDLS_CRYPTO_BACKEND}'")
endif()

# --- libsdls.so -----------------------------------------------------------------------------
add_library(sdls SHARED
  src/sdlp/tc_sdlp_my.c
  src/sdlp/tm_sdlp_my.c
  src/sa/sa_default.c
  src/sa/sa_shm_my.c
  src/sdls/sechdr_my.c
  src/sdls/sdls_my.c
  src/ep/ep_my.c
  ${SDLS_CRYPTO_SOURCES})

target_include_directories(sdls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# SA/Key DB in POSIX shared memory: process-shared mutex (pthread), shm_open (librt on
# glibc older than 2.34; newer glibc has it in libc and librt is an empty stub).
find_package(Threads REQUIRED)
find_library(RT_LIBRARY rt)
target_link_libraries(sdls PRIVATE Threads::Threads ${SDLS_CRYPTO_LIBS})
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

# --- tests ----------------------------------------------------------------------------------
# libsdls_satsim.so: test only stand-in for the satellite crypto (ML-KEM key pair and decaps,
# ML-DSA verify, AES-GCM), built from the same backend the satellite is expected to use.
# Python ctypes tests in test/ (run with: ctest --test-dir build --output-on-failure)
option(SDLS_BUILD_TESTS "Build the test satellite library and register the Python tests" ON)
if(SDLS_BUILD_TESTS)
  add_library(sdls_satsim SHARED test/satsim/satsim.c ${SDLS_CRYPTO_SOURCES})
  target_include_directories(sdls_satsim PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                                 ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(sdls_satsim PRIVATE Threads::Threads ${SDLS_CRYPTO_LIBS})
  set_target_properties(sdls_satsim PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)
  target_compile_options(sdls_satsim PRIVATE -Wall -Wextra)

  enable_testing()
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME python_sdlp
      COMMAND ${Python3_EXECUTABLE} -m unittest discover -s ${CMAKE_CURRENT_SOURCE_DIR}/test -v)
    set_tests_properties(python_sdlp PROPERTIES ENVIRONMENT
      "SDLS_LIB=$<TARGET_FILE:sdls>;SDLS_SATSIM_LIB=$<TARGET_FILE:sdls_satsim>")
  endif()
endif()
