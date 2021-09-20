# vim: set ai ts=4 expandtab:
# ::=========================================================================::
# Build for flamethrower
# ::=========================================================================::

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(CMAKE_VERBOSE_MAKEFILE ON)

# The following must be set BEFORE doing project() or enable_language().
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type defined; defaulting to 'Debug'")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
            "The type of build. Possible values are: Debug, Release, RelWithDebInfo and MinSizeRel.")
endif()
# ::-------------------------------------------------------------------------::

project(flamethrower VERSION 0.12.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

message(STATUS "The host system is: ${CMAKE_HOST_SYSTEM}.")
message(STATUS "Project base dir is: ${CMAKE_SOURCE_DIR}")

# Just for debugging when adding a new platform/compiler.  If you need to export
# compiler identity info into the project consider using: `include(WriteCompilerDetectionHeader)`
if (FLAME_BUILD_SHOW_CXX)
    message(STATUS "The detected C++ compiler supports these language features:")
    foreach(i ${CMAKE_CXX_COMPILE_FEATURES})
        message(STATUS "    ${i}")
    endforeach()
endif()

# Global for all targets
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall)

# ::-------------------------------------------------------------------------::
# Find and setup all dependencies BEFORE declaring targets.
# ::-------------------------------------------------------------------------:: 

find_package(Threads REQUIRED)

find_package(PkgConfig)

include(sanitizer)

pkg_search_module(LIBLDNS REQUIRED libldns ldns)
pkg_check_modules(LIBUV REQUIRED libuv>=1.23)
pkg_check_modules(LIBGNUTLS REQUIRED gnutls>=3.3)

option(DOH_ENABLE "Enable DNS over HTTPS (DoH) support" OFF)
option(USE_HTTP_PARSER "Use http_parse library instead of url_parse" OFF)
if (DOH_ENABLE)
    pkg_search_module(LIBNGHTTP2 REQUIRED nghttp2 libnghttp2)
    message(STATUS "DNS over HTTPS (DoH) support is enabled")
    add_definitions(-DDOH_ENABLE)
else ()
    message(STATUS "DNS over HTTPS (DoH) support is disabled")
endif()
if (USE_HTTP_PARSER)
    add_definitions(-DUSE_HTTP_PARSER)
endif()

pkg_search_module(CATCH QUIET catch2>=2.3 catch>=2.3)
pkg_check_modules(LIBDOCOPT docopt)
find_package(nlohmann_json QUIET 3.7.3)
find_package(httplib QUIET)

# ::-------------------------------------------------------------------------:: 
# BUILD TARGETS
# ::-------------------------------------------------------------------------:: 

if (NOT LIBDOCOPT_FOUND)
    set(LIBDOCOPT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rd/docopt.cpp")
    set(LIBDOCOPT_LIBRARIES docopt)
    add_library(docopt STATIC 3rd/docopt.cpp/docopt.cpp)
    target_include_directories(docopt PUBLIC ${LIBDOCOPT_INCLUDE_DIRS})
endif()

if (NOT USE_HTTP_PARSER)
    set(LIBURL_PARSER_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rd/url-parser")
    set(LIBURL_PARSER_LIBRARIES url_parser)
    add_library(url_parser STATIC 3rd/url-parser/url_parser.c)
    target_include_directories(url_parser PUBLIC ${LIBURL_PARSER_INCLUDE_DIRS})
else()
    find_file(HTTP_PARSER_H NAMES http_parser.h)
    find_library(HTTP_PARSER_LIBRARY NAMES http_parser)
    if (NOT HTTP_PARSER_H OR NOT HTTP_PARSER_LIBRARY)
        status(FATAL "http_parser library development files not found")
    endif()
    set(LIBURL_PARSER_LIBRARIES ${HTTP_PARSER_LIBRARY})
endif()

if (NOT nlohmann_json_FOUND)
    message(STATUS "Using bundled nlohmann_json library")
    set (nlohmann_json_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rd/json")
else()
    set (nlohmann_json_LIBRARIES nlohmann_json::nlohmann_json)
endif()

if (NOT httplib_FOUND)
    message(STATUS "Using bundled cpp-httplib library")
    set (httplib_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/3rd/cpp-httplib")
else()
    set (httplib_LIBRARIES httplib::httplib)
endif()


set(flamecore_src
    flame/metrics.cpp
    flame/metrics.h
    flame/query.cpp
    flame/query.h
    flame/target.h
    flame/trafgen.cpp
    flame/trafgen.h
    flame/tcpsession.cpp
    flame/tcpsession.h
    flame/tcptlssession.cpp
    flame/tcptlssession.h
    flame/utils.cpp
    flame/utils.h
    )

set(flamecore_dirs
    PUBLIC ${LIBUV_INCLUDE_DIRS}
    PUBLIC ${LIBLDNS_INCLUDE_DIRS}
    PUBLIC ${LIBGNUTLS_INCLUDE_DIRS}
    PUBLIC ${LIBURL_PARSER_INCLUDE_DIRS}
    PUBLIC ${nlohmann_json_INCLUDE_DIRS}
    PUBLIC "${CMAKE_SOURCE_DIR}/3rd/uvw"
    )

set(flamecore_libs
    PRIVATE ${LIBUV_LDFLAGS}
    PRIVATE ${LIBUV_LIBRARIES}
    PRIVATE ${LIBLDNS_LDFLAGS}
    PRIVATE ${LIBLDNS_LIBRARIES}
    PRIVATE ${LIBGNUTLS_LDFLAGS}
    PRIVATE ${LIBGNUTLS_LIBRARIES}
    )

set(flame_execs
    flame/main.cpp
    )

set(flame_dirs
    PUBLIC ${LIBDOCOPT_INCLUDE_DIRS}
    PUBLIC ${httplib_INCLUDE_DIRS}
    )

if (DOH_ENABLE)
    set(flamecore_src 
        ${flamecore_src}
        flame/http.h
        flame/httpssession.cpp
        flame/httpssession.h
        3rd/base64url/base64.cpp
        )

    set(flamecore_dirs
        ${flamecore_dirs}
        PUBLIC ${LIBNGHTTP2_INCLUDE_DIRS}
        PUBLIC "${CMAKE_SOURCE_DIR}/3rd/base64url"
        )

    set(flamecore_libs
        ${flamecore_libs}
        PRIVATE ${LIBNGHTTP2_LDFLAGS}
        PRIVATE ${LIBNGHTTP2_LIBRARIES}
        )
endif()

add_library(flamecore ${flamecore_src})

target_include_directories(flamecore ${flamecore_dirs})

target_link_libraries(flamecore ${flamecore_libs})

add_executable(flame ${flame_execs})

target_include_directories(flame ${flame_dirs})

target_link_libraries(flame
        PRIVATE flamecore
        PRIVATE ${LIBUV_LDFLAGS}
        PRIVATE ${LIBUV_LIBRARIES}
        PRIVATE ${LIBDOCOPT_LDFLAGS}
        PRIVATE ${LIBDOCOPT_LIBRARIES}
        PRIVATE ${LIBURL_PARSER_LIBRARIES}
        PRIVATE ${nlohmann_json_LIBRARIES}
        PRIVATE ${httplib_LIBRARIES}
        PRIVATE Threads::Threads
        )

add_executable(tests
        tests/main.cpp
        )

if (NOT CATCH_FOUND)
    message(STATUS "Using bundled catch2")
    target_include_directories(tests SYSTEM
        PRIVATE "${CMAKE_SOURCE_DIR}/3rd/catch"
        )
endif()

target_include_directories(tests
        PRIVATE "${CMAKE_SOURCE_DIR}/tests"
        PRIVATE "${CMAKE_SOURCE_DIR}/flame"
        )

target_link_libraries(tests
        PRIVATE flamecore
        )

install(TARGETS flame flamecore
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib${LIB_SUFFIX}
        ARCHIVE DESTINATION lib/static)
