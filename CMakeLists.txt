# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.15)

project ("Sliver-CPPImplant2")
set(CMAKE_CXX_STANDARD 20)
cmake_policy(SET CMP0091 NEW)
add_compile_definitions("SODIUM_STATIC" "_CRT_SECURE_NO_WARNINGS" "CURL_STATICLIB" "SECURITY_WIN32")

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

add_executable (Sliver-CPPImplant2 "src/Sliver-CPPImplant2.cpp" src/common.pb.cc src/sliver.pb.cc       "src/CryptoUtils.cpp"    "src/constants.cpp")

set_property(TARGET Sliver-CPPImplant2 PROPERTY
             MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")

target_link_libraries(Sliver-CPPImplant2 ${Protobuf_LIBRARIES} ${LIBSODIUM} ${BOTAN} cpr::cpr)

# Include sub-projects.

