cmake_minimum_required(VERSION 3.20)

project(sysmon
    VERSION 1.0.0
    DESCRIPTION "Linux System Monitoring & Analytics Platform"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SYSMON_BUILD_DAEMON    "Build the sysmond collection daemon (needs libpqxx, Boost)" ON)
option(SYSMON_BUILD_DASHBOARD "Build the Qt 6 dashboard (needs Qt6, libpqxx)"             ON)
option(SYSMON_BUILD_TESTS     "Build the GoogleTest unit tests"                           ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(WARNING "sysmon reads /proc and /sys and is only supported on Linux.")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)

add_subdirectory(src)

if(SYSMON_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

include(GNUInstallDirs)
install(FILES config/sysmon.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmon)
install(FILES sql/schema.sql     DESTINATION ${CMAKE_INSTALL_DATADIR}/sysmon)
