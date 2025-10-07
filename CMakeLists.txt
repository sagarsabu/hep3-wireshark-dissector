cmake_minimum_required(VERSION 3.20.0)
project(
  hep3-dissector
  VERSION 0.1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBWIRESHARK REQUIRED wireshark)

add_library(hep3-dissector SHARED src/hep3.cpp)

target_compile_options(hep3-dissector PRIVATE -Wall -Werror -Wextra -Wpedantic)

target_link_libraries(hep3-dissector PRIVATE ${LIBWIRESHARK_LIBRARIES})

target_include_directories(hep3-dissector PRIVATE ${LIBWIRESHARK_INCLUDE_DIRS})
if(DEFINED ENV{WIRESHARK_DEV_DIR})
  target_include_directories(hep3-dissector SYSTEM PRIVATE "$ENV{WIRESHARK_DEV_DIR}/include/wireshark")
endif()
