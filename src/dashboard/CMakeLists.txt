find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Charts Network)

set(CMAKE_AUTOMOC ON)

add_executable(sysmon-dashboard
    main.cpp
    format.hpp
    widgets.hpp
    widgets.cpp
    live_client.hpp
    live_client.cpp
    live_view.hpp
    live_view.cpp
    history_view.hpp
    history_view.cpp
    process_view.hpp
    process_view.cpp
    event_view.hpp
    event_view.cpp
    main_window.hpp
    main_window.cpp
)
target_link_libraries(sysmon-dashboard PRIVATE sysmon_db Qt6::Widgets Qt6::Charts Qt6::Network)

install(TARGETS sysmon-dashboard RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
