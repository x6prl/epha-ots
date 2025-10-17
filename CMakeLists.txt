cmake_minimum_required(VERSION 3.13)
project(epha-ots C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -mavx2 -Wall -Wextra -pthread")

# Build options
option(JS_MINIFY "Use minified JavaScript assets" OFF)
option(FILELOG "Enable logging into a file" OFF)
option(SYSLOG "Enable syslog logging" ON)

# Try pkg-config first
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
  pkg_check_modules(MHD libmicrohttpd)
endif()

add_executable(epha-ots server.c)
target_compile_definitions(epha-ots PRIVATE
  $<$<BOOL:${JS_MINIFY}>:JS_MINIFY=1>
  $<$<BOOL:${FILELOG}>:FILELOG=1>
  $<$<BOOL:${SYSLOG}>:SYSLOG=1>
  $<$<CONFIG:Debug>:DEBUG=1>
)

if (MHD_FOUND)
  target_include_directories(epha-ots PRIVATE ${MHD_INCLUDE_DIRS})
  target_link_directories(epha-ots PRIVATE ${MHD_LIBRARY_DIRS})
  target_link_libraries(epha-ots PRIVATE ${MHD_LIBRARIES})
else()
  find_library(MHD_LIB microhttpd)
  if (NOT MHD_LIB)
    message(FATAL_ERROR "libmicrohttpd not found. Install libmicrohttpd-dev.")
  endif()
  target_link_libraries(epha-ots PRIVATE ${MHD_LIB})
endif()
