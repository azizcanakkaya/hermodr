cmake_minimum_required(VERSION 3.10)

project(hermodr)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CJSON REQUIRED libcjson)

set(SOURCE_FILES
    hermodr.c)

add_executable(hermodr ${SOURCE_FILES})

target_include_directories(hermodr PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_libraries(hermodr ${CJSON_LIBRARIES})