cmake_minimum_required(VERSION 3.30)
project(Intrudex_Client VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-only enforcement
if(NOT WIN32)
    message(FATAL_ERROR "This project is only intended for Windows. Build aborted.")
endif()

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

# Clean build directory before each build
add_custom_target(clean_build_dir ALL
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_SOURCE_DIR}/build"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/build"
        COMMENT "Cleaning build directory..."
)

# Main executable
add_executable(${PROJECT_NAME}
        src/main.cpp
        src/sysmon_manager.cpp
        src/SysmonCollector.cpp
        header/HttpClient.h
        src/HttpClient.cpp
)

# Link Windows Event API
target_link_libraries(${PROJECT_NAME}
        PRIVATE
        winhttp
        wevtapi
        advapi32
        shell32
        user32
)

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/headers
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

# Compiler options
target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

# Make main target depend on clean_build_dir
add_dependencies(${PROJECT_NAME} clean_build_dir)

# --- [DLL Copying Section] ---
# Detect MinGW DLLs and copy them next to the EXE
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    get_filename_component(MINGW_BIN "${CMAKE_CXX_COMPILER}" DIRECTORY)

    set(MINGW_DLLS
            libstdc++-6
            libgcc_s_seh-1
            libwinpthread-1
    )

    foreach(DLL IN LISTS MINGW_DLLS)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${MINGW_BIN}/${DLL}.dll"
                $<TARGET_FILE_DIR:${PROJECT_NAME}>
                COMMENT "Copying ${DLL}.dll"
        )
    endforeach()
endif()

# --- [Copy assets and config folders] ---
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/assets"
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets"
        COMMENT "Copying assets to build folder"
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/config"
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config"
        COMMENT "Copying config to build folder"
)