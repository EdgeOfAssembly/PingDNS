cmake_minimum_required(VERSION 3.10)
project(PingDNS)

# Set C++ standard to C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set optimization level to -O2 for Release build
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

# Find and configure required libraries
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCAP REQUIRED libcap)

# Manually find GeoIP headers and libraries
find_path(GeoIP_INCLUDE_DIR GeoIP.h
  PATHS /usr/include /usr/local/include
)

find_library(GeoIP_LIBRARY
  NAMES GeoIP
  PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64
)

# Check if GeoIP headers and library were found
if(NOT GeoIP_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find GeoIP headers (GeoIP.h)")
endif()

if(NOT GeoIP_LIBRARY)
  message(FATAL_ERROR "Could not find GeoIP library (libGeoIP)")
endif()

# Include directories for the libraries
include_directories(${CURL_INCLUDE_DIRS} ${GeoIP_INCLUDE_DIR} ${LIBCAP_INCLUDE_DIRS})

# Specify source files
set(SOURCES pingdns.cpp)

# Create the executable
add_executable(pingdns ${SOURCES})

# Link against the required libraries
target_link_libraries(pingdns ${CURL_LIBRARIES} ${GeoIP_LIBRARY} ${LIBCAP_LIBRARIES})

# Strip debug info from the binary in Release build
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET pingdns POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:pingdns>
        COMMENT "Stripping debug symbols from pingdns"
    )
endif()