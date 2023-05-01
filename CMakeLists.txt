# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.15)

#[[
get_cmake_property(_variableNames VARIABLES)
list (SORT _variableNames)
foreach (_variableName ${_variableNames})
    message(STATUS "${_variableName}=${${_variableName}}")
endforeach()
]]
project ("Sliver-CPPImplant2")
set(CMAKE_CXX_STANDARD 20)
cmake_policy(SET CMP0091 NEW)
add_compile_definitions("NOMINMAX" "SODIUM_STATIC" "_CRT_SECURE_NO_WARNINGS" "CURL_STATICLIB" "SECURITY_WIN32")

include_directories(Include)

###protobuf
find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS src/common.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS src/sliver.proto)

###libsodium
find_library(
  LIBSODIUM
  libsodium.lib
  REQUIRED)

### cpr
find_package(cpr REQUIRED)

### botan
find_library(BOTAN botan.lib REQUIRED)

if($ENV{BUILD_DLL})
add_library (Sliver-CPPImplant2 SHARED "src/Sliver-CPPImplant.cpp" src/common.pb.cc src/sliver.pb.cc  "src/CryptoUtils.cpp"    "src/constants.cpp" "src/Base64.cpp" "src/Encoders.cpp" "src/CipherContext.cpp"  "src/Beacon.cpp"  "src/HttpClient.cpp" "src/evasion.cpp" "src/execute.cpp" "src/ExecuteAssembly.cpp" "src/extensions.cpp" "src/globals.cpp" "src/Handlers_Utils.cpp" "src/MemoryModule.cpp" "src/NamedPipeClient.cpp" "src/NamedPipeConn.cpp" "src/NamedPipeListener.cpp" "src/Os.cpp" "src/systemHandlers.cpp" "src/TCPClient.cpp" "src/TCPConn.cpp" "src/TCPListener.cpp" "src/Token.cpp" "src/filesystem.cpp" "src/pivotHandlers.cpp" "src/Pivots.cpp" "src/Sliver-CPPImplant.cpp")
else()
    add_executable (Sliver-CPPImplant2 "src/Sliver-CPPImplant.cpp" src/common.pb.cc src/sliver.pb.cc  "src/CryptoUtils.cpp"    "src/constants.cpp" "src/Base64.cpp" "src/Encoders.cpp" "src/CipherContext.cpp"  "src/Beacon.cpp"  "src/HttpClient.cpp" "src/evasion.cpp" "src/execute.cpp" "src/ExecuteAssembly.cpp" "src/extensions.cpp" "src/globals.cpp" "src/Handlers_Utils.cpp" "src/MemoryModule.cpp" "src/NamedPipeClient.cpp" "src/NamedPipeConn.cpp" "src/NamedPipeListener.cpp" "src/Os.cpp" "src/systemHandlers.cpp" "src/TCPClient.cpp" "src/TCPConn.cpp" "src/TCPListener.cpp" "src/Token.cpp" "src/filesystem.cpp" "src/pivotHandlers.cpp" "src/Pivots.cpp" "src/Sliver-CPPImplant.cpp" "Include/Utils.h" "src/Utils.cpp")
endif()
set_property(TARGET Sliver-CPPImplant2 PROPERTY
             MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(Sliver-CPPImplant2 ${Protobuf_LIBRARIES} ${LIBSODIUM} ${BOTAN} cpr::cpr Ws2_32.lib Wldap32.lib Normaliz.lib Crypt32.lib Secur32.lib Ntdll.dll netapi32.lib)

# Include sub-projects.

