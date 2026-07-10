cmake_minimum_required(VERSION 3.16)
project(intellicrack_bridge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_X64 "Build 64-bit plugin" ON)

set(X64DBG_SDK_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/x64dbg/pluginsdk" CACHE PATH "Path to x64dbg plugin SDK")

if(NOT EXISTS "${X64DBG_SDK_PATH}")
    message(WARNING "x64dbg plugin SDK not found at ${X64DBG_SDK_PATH}")
    message(STATUS "Attempting to find SDK in release directory...")
    set(X64DBG_SDK_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/x64dbg/release/pluginsdk")
endif()

if(NOT EXISTS "${X64DBG_SDK_PATH}")
    message(FATAL_ERROR
        "x64dbg plugin SDK not found. Please either:\n"
        "1. Set X64DBG_SDK_PATH to the correct location\n"
        "2. Ensure x64dbg is installed in tools/x64dbg/\n"
        "Expected location: ${X64DBG_SDK_PATH}"
    )
endif()

set(SOURCES
    intellicrack_bridge.cpp
    pipe_server.cpp
    command_handler.cpp
)

set(HEADERS
    intellicrack_bridge.h
    pipe_server.h
    command_handler.h
)

if(BUILD_X64)
    set(TARGET_NAME "intellicrack_bridge_x64")
    set(PLUGIN_EXT ".dp64")
    set(ARCH_DIR "x64")
    add_definitions(-DBUILD_X64)
    set(X64DBG_LIB_PATH "${X64DBG_SDK_PATH}/x64dbg.lib")
    set(X64DBG_BRIDGE_LIB "${X64DBG_SDK_PATH}/x64bridge.lib")
else()
    set(TARGET_NAME "intellicrack_bridge_x32")
    set(PLUGIN_EXT ".dp32")
    set(ARCH_DIR "x32")
    set(X64DBG_LIB_PATH "${X64DBG_SDK_PATH}/x32dbg.lib")
    set(X64DBG_BRIDGE_LIB "${X64DBG_SDK_PATH}/x32bridge.lib")
endif()

add_library(${TARGET_NAME} SHARED ${SOURCES} ${HEADERS})

target_include_directories(${TARGET_NAME} PRIVATE
    ${X64DBG_SDK_PATH}
    ${X64DBG_SDK_PATH}/_scriptapi
    ${X64DBG_SDK_PATH}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${TARGET_NAME} PRIVATE
    ${X64DBG_LIB_PATH}
    ${X64DBG_BRIDGE_LIB}
)

target_compile_definitions(${TARGET_NAME} PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
)

if(MSVC)
    target_compile_options(${TARGET_NAME} PRIVATE
        /W4
        /WX-
        /permissive-
        /Zc:__cplusplus
    )

    set_target_properties(${TARGET_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

set_target_properties(${TARGET_NAME} PROPERTIES
    OUTPUT_NAME "${TARGET_NAME}"
    SUFFIX "${PLUGIN_EXT}"
    PREFIX ""
)

set(PLUGIN_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set_target_properties(${TARGET_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PLUGIN_BIN_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${PLUGIN_BIN_DIR}"
)

foreach(OUTPUTCONFIG IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${PLUGIN_BIN_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${PLUGIN_BIN_DIR}"
    )
endforeach()

set(PLUGIN_INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/x64dbg/release/${ARCH_DIR}/plugins")

install(TARGETS ${TARGET_NAME}
    RUNTIME DESTINATION "${PLUGIN_INSTALL_DIR}"
    LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}"
)

message(STATUS "")
message(STATUS "Intellicrack Bridge Plugin Configuration:")
message(STATUS "  Target: ${TARGET_NAME}${PLUGIN_EXT}")
message(STATUS "  Architecture: ${ARCH_DIR}")
message(STATUS "  SDK Path: ${X64DBG_SDK_PATH}")
message(STATUS "  Install Dir: ${PLUGIN_INSTALL_DIR}")
message(STATUS "")
