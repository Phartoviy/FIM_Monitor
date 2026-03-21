 
cmake_minimum_required(VERSION 3.16)

project(integrity_monitor VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(integrity_monitor
    src/main.cpp
    src/config_manager.cpp
    src/file_scanner.cpp
    src/hash_engine.cpp
    src/baseline_storage.cpp
    src/integrity_analyzer.cpp
    src/threat_classifier.cpp
    src/report_generator.cpp
    src/utils.cpp
)

target_include_directories(integrity_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

install(TARGETS integrity_monitor DESTINATION bin)

#install(FILES
#    config/integrity_monitor.conf
#    DESTINATION etc/integrity_monitor
#)
