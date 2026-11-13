# CMake generated Testfile for 
# Source directory: /home/yujin/lib_sdls
# Build directory: /home/yujin/lib_sdls
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(python_sdlp "/usr/bin/python3" "-m" "unittest" "discover" "-s" "/home/yujin/lib_sdls/test" "-v")
set_tests_properties(python_sdlp PROPERTIES  ENVIRONMENT "SDLS_LIB=/home/yujin/lib_sdls/libsdls.so.0.1.0" _BACKTRACE_TRIPLES "/home/yujin/lib_sdls/CMakeLists.txt;24;add_test;/home/yujin/lib_sdls/CMakeLists.txt;0;")
