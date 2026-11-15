# ---------------------------------------------------------------------------
# sysmon_core: dependency-free library (parsers, collectors, detection, JSON).
# Everything here is unit-testable without PostgreSQL, Boost or Qt.
# ---------------------------------------------------------------------------
add_library(sysmon_core STATIC
    core/config.cpp
    core/parsers.cpp
    core/json.cpp
    collectors/cpu_collector.cpp
    collectors/memory_collector.cpp
    collectors/disk_collector.cpp
    collectors/network_collector.cpp
    collectors/process_collector.cpp
    security/security_detector.cpp
    security/alert_manager.cpp
    security/auth_log_monitor.cpp
)
target_include_directories(sysmon_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sysmon_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# sysmon_db: PostgreSQL persistence + analytics queries (libpqxx).
# ---------------------------------------------------------------------------
if(SYSMON_BUILD_DAEMON OR SYSMON_BUILD_DASHBOARD)
    find_package(libpqxx CONFIG QUIET)
    if(TARGET libpqxx::pqxx)
        set(SYSMON_PQXX_TARGET libpqxx::pqxx)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(PQXX REQUIRED IMPORTED_TARGET libpqxx)
        set(SYSMON_PQXX_TARGET PkgConfig::PQXX)
    endif()

    add_library(sysmon_db STATIC db/database.cpp)
    target_link_libraries(sysmon_db PUBLIC sysmon_core ${SYSMON_PQXX_TARGET})
endif()

# ---------------------------------------------------------------------------
# sysmond: multithreaded collection engine + Boost.Asio live stream server.
# ---------------------------------------------------------------------------
if(SYSMON_BUILD_DAEMON)
    if(POLICY CMP0167)
        cmake_policy(SET CMP0167 NEW)
    endif()
    find_package(Boost 1.74 REQUIRED)

    add_executable(sysmond
        daemon/main.cpp
        daemon/engine.cpp
        daemon/live_server.cpp
    )
    target_link_libraries(sysmond PRIVATE sysmon_db Boost::headers)
    install(TARGETS sysmond RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---------------------------------------------------------------------------
# sysmon-dashboard: Qt 6 analytics dashboard.
# ---------------------------------------------------------------------------
if(SYSMON_BUILD_DASHBOARD)
    add_subdirectory(dashboard)
endif()
