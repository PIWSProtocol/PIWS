# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(ServerAdd VERSION 3.6.5 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_SERVERADD)
    set(SEAL_BUILD_SERVERADD ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.6.5 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_SERVERADD)
    add_executable(serveradd)

    target_sources(serveradd
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/examples.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(serveradd PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(serveradd PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
