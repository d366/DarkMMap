mkdir ..\Build
cd ..\Build
cmake .. -G"MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug -DASMJIT_BUILD_LIBRARY=1 -DASMJIT_BUILD_TEST=1
cd ..\Util
