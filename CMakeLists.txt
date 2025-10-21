cmake_minimum_required(VERSION 3.15)
project(veh_patch_project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Output directories (MSVC multi-config will place under build/<config> by default,
# but these make local builds predictable too)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(veh_patch_smart SHARED src/veh_patch_smart.cpp)
set_target_properties(veh_patch_smart PROPERTIES OUTPUT_NAME "veh_patch_smart")
