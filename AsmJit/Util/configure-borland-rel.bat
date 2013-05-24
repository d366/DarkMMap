mkdir ..\Build
cd ..\Build
cmake .. -G"Borland Makefiles" -DCMAKE_BUILD_TYPE=Release -DASMJIT_BUILD_LIBRARY=1 -DASMJIT_BUILD_TEST=1
cd ..\Util
