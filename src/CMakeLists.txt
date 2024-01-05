cmake_minimum_required(VERSION 3.26)

set(VCPKG_TARGET_TRIPLET "x86-windows-static")
project(SafeDiscShim VERSION 0.1.0
        DESCRIPTION ""
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

add_library(${PROJECT_NAME} SHARED
        dllmain.cpp
        pch.cpp
        pch.h
        hooks.cpp
        hooks.h
        secdrv_ioctl.h
        secdrv_ioctl.cpp
        logging.cpp
        logging.h
        process.cpp
        process.h)
target_precompile_headers(${PROJECT_NAME} PRIVATE pch.h)
set_property(TARGET ${PROJECT_NAME} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_NAME "drvmgt")

find_package(spdlog CONFIG REQUIRED)
find_package(minhook CONFIG REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE ntdll spdlog::spdlog minhook::minhook )
