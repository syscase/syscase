cmake_minimum_required(VERSION 3.0)

project(afl C)

add_compile_options(-O3 -funroll-loops -fgnu89-inline -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include_directories(
  ${PROJECT_SOURCE_DIR}/include/
)

set(APP_SOURCES src/app/main.c)
file(GLOB_RECURSE LIB_SOURCES src/afl/**.c)

add_executable(${PROJECT_NAME} ${APP_SOURCES})

set(LIBRARY_NAME afl_core)
add_library(${LIBRARY_NAME} STATIC ${LIB_SOURCES})
target_link_libraries(${PROJECT_NAME} ${LIBRARY_NAME})
target_link_libraries(${PROJECT_NAME} ${CMAKE_DL_LIBS})
target_link_libraries(${PROJECT_NAME} uuid)
