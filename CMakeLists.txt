cmake_minimum_required(VERSION 3.16)
project(Production rslvd VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /WX)
    add_definitions(-D_WIN32_WINNT=0x0601)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Build type specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
    if(NOT MSVC)
        add_compile_options(-g -O0 -fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-DNDEBUG)
    if(NOT MSVC)
        add_compile_options(-O3 -march=native -flto)
        add_link_options(-flto)
    endif()
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(src)

# Source files
set(SOURCES
    src/main.cpp
    src/rslvd.cpp
    src/dns_packet.cpp
    src/dns_record.cpp
    src/cache/dns_cache.cpp
    src/security/rate_limiter.cpp
    src/security/acl.cpp
    src/security/auth_manager.cpp
    src/monitoring/logger.cpp
    src/monitoring/metrics.cpp
    src/config/config_manager.cpp
    src/utils/thread_pool.cpp
    src/utils/crypto_utils.cpp
    src/utils/utils.cpp
)

# Header files
set(HEADERS
    src/rslvd.h
    src/dns_packet.h
    src/dns_record.h
    src/cache/dns_cache.h
    src/security/rate_limiter.h
    src/security/acl.h
    src/security/auth_manager.h
    src/monitoring/logger.h
    src/monitoring/metrics.h
    src/config/config_manager.h
    src/utils/thread_pool.h
    src/utils/crypto_utils.h
    src/utils/utils.h
)

# Create executable
add_executable(rslvd ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(rslvd 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Threads::Threads
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(rslvd ws2_32 wsock32)
endif()

# Installation
install(TARGETS rslvd DESTINATION bin)
install(DIRECTORY config/ DESTINATION etc/rslvd)
install(FILES README.md DESTINATION share/doc/rslvd)

# Create directories for runtime
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/logs)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/config/zones)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/config/keys)

# Copy configuration files
configure_file(config/rslvd.conf ${CMAKE_BINARY_DIR}/config/rslvd.conf COPYONLY)
configure_file(config/acl.conf ${CMAKE_BINARY_DIR}/config/acl.conf COPYONLY)

# Testing (optional)
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Documentation (optional)
option(BUILD_DOCS "Build documentation" OFF)
if(BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
                      ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
        add_custom_target(docs
            ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen" VERBATIM
        )
    endif()
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "production-rslvd")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Production-ready DNS Server")
set(CPACK_PACKAGE_VENDOR "DNS Server Project")
set(CPACK_PACKAGE_CONTACT "admin@example.com")

if(WIN32)
    set(CPACK_GENERATOR "NSIS")
else()
    set(CPACK_GENERATOR "DEB;RPM")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libc6")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl-libs, glibc")
endif()

include(CPack)
