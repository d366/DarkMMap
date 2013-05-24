# Reguire minimum version of CMake
CMake_Minimum_Required(VERSION 2.6)

# AsmJit project - Need to use both C and C++
Project(AsmJit C CXX)

# If ASMJIT_DIR is not specified, assume that we are building it from here
If(NOT ASMJIT_DIR)
  Set(ASMJIT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
EndIf()

# AsmJit C++ sources
Set(ASMJIT_SOURCES
  AsmJit/AssemblerX86X64.cpp
  AsmJit/CodeGenerator.cpp
  AsmJit/Compiler.cpp
  AsmJit/CompilerX86X64.cpp
  AsmJit/CpuInfo.cpp
  AsmJit/Defs.cpp
  AsmJit/DefsX86X64.cpp
  AsmJit/Logger.cpp
  AsmJit/MemoryManager.cpp
  AsmJit/MemoryMarker.cpp
  AsmJit/OperandX86X64.cpp
  AsmJit/Platform.cpp
  AsmJit/Util.cpp
)

# AsmJit C++ headers
Set(ASMJIT_HEADERS
  AsmJit/ApiBegin.h
  AsmJit/ApiEnd.h
  AsmJit/AsmJit.h
  AsmJit/Assembler.h
  AsmJit/AssemblerX86X64.h
  AsmJit/Build.h
  AsmJit/CodeGenerator.h
  AsmJit/Compiler.h
  AsmJit/CompilerX86X64.h
  AsmJit/Config.h
  AsmJit/CpuInfo.h
  AsmJit/Defs.h
  AsmJit/DefsX86X64.h
  AsmJit/Logger.h
  AsmJit/MemoryManager.h
  AsmJit/MemoryMarker.h
  AsmJit/Operand.h
  AsmJit/OperandX86X64.h
  AsmJit/Platform.h
  AsmJit/Util.h
  AsmJit/Util_p.h
)

# Include AsmJit to be able to use #include <AsmJit/...>
Include_Directories(${ASMJIT_DIR})

# pthread library is needed for non-windows OSes.
If(NOT WIN32)
  Link_Libraries(pthread)
EndIf()

# Build-Type.
If(${CMAKE_BUILD_TYPE})
  If(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    Add_Definitions(-DASMJIT_DEBUG)
  Else()
    Add_Definitions(-DASMJIT_NO_DEBUG)
  EndIf()
EndIf()

# Build AsmJit shared library?
If(ASMJIT_BUILD_LIBRARY)
  Add_Library(AsmJit SHARED ${ASMJIT_SOURCES} ${ASMJIT_HEADERS})
  Install(TARGETS AsmJit DESTINATION lib${LIB_SUFFIX})

  # Install header files.
  ForEach(i ${ASMJIT_HEADERS})
    Get_Filename_Component(path ${i} PATH)
    Install(FILES ${i} DESTINATION "include/${path}")
  EndForEach(i)
EndIf()

# Build AsmJit test executables?
If(ASMJIT_BUILD_TEST)
  Set(ASMJIT_TEST_FILES
    testcorecpu
    testcoresize
    testdummy
    testfuncalign
    testfunccall1
    testfunccall2
    testfunccall3
    testfuncmanyargs
    testfuncmemcpy
    testfuncrecursive1
    testfuncret
    testjit
    testjump1
    testmem1
    testopcode
    testspecial1
    testspecial2
    testspecial3
    testspecial4
    testtrampoline
    testvar2
    testvar3
    testvar4
    testvar5
  )

  ForEach(file ${ASMJIT_TEST_FILES})
    Add_Executable(${file} Test/${file}.cpp)
    Target_Link_Libraries(${file} AsmJit)
  EndForEach(file)
EndIf()
