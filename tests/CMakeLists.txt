find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

add_executable(sysmon_tests
    test_parsers.cpp
    test_collectors.cpp
    test_thread_pool.cpp
    test_security.cpp
    test_config_json.cpp
)
target_link_libraries(sysmon_tests PRIVATE sysmon_core GTest::gtest_main)
target_compile_definitions(sysmon_tests PRIVATE SYSMON_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

include(GoogleTest)
gtest_discover_tests(sysmon_tests)
