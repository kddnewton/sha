cmake_minimum_required(VERSION 3.10)
project(SHA C)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -pedantic -Wconversion -Wunused -Wshadow -Wstrict-prototypes -Wmissing-prototypes)
endif()

add_library(libsha STATIC src/sha.c)
set_target_properties(libsha PROPERTIES OUTPUT_NAME sha)
target_include_directories(libsha PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_executable(sha src/main.c)
target_link_libraries(sha libsha)

add_executable(test test/main.c)
target_link_libraries(test libsha)

add_custom_target(test_all
    COMMENT "test test/"
    COMMAND ${CMAKE_COMMAND} -E env $<TARGET_FILE:test> ${CMAKE_CURRENT_SOURCE_DIR}/test
    DEPENDS test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
