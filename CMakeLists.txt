cmake_minimum_required(VERSION 3.10.0)
project(rtp VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 23)

## Rtp lib
# TODO allow dynmaic/static linking via option
# add_library(rtp
#  src/RtpPacket.cpp)

# target_include_directories(rtp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)


## Compiler warnings
include(cmake/CompilerWarnings.cmake)

option(WARNINGS_AS_ERRORS "Treat warnings as errors" ON)

add_library(project_warnings INTERFACE)

project_set_project_warnings(
  project_warnings                                          # project_name (target to decorate)
  ${WARNINGS_AS_ERRORS}                                       # WARNINGS_AS_ERRORS
  "/W4;/WX"                                                   # MSVC_WARNINGS (use defaults in the function)
  "-Wall;-Wextra;-Wpedantic;-Werror"                          # CLANG_WARNINGS (defaults)
  "-Wall;-Wextra;-Wpedantic;-Werror"                          # GCC_WARNINGS (defaults)
  ""                                                          # CUDA_WARNINGS (defaults)
)

# Couldn't get sanitizers to work on windows, disabling them for now.
if(NOT WIN32)
include(cmake/Sanitizers.cmake)

option(ENABLE_SANITIZER_ADDRESS "Enable AddressSanitizer" ON)
option(ENABLE_SANITIZER_LEAK "Enable LeakSanitizer" OFF)
option(ENABLE_SANITIZER_UNDEFINED_BEHAVIOR "Enable UBSan" ON)
option(ENABLE_SANITIZER_THREAD "Enable ThreadSanitizer" OFF)
option(ENABLE_SANITIZER_MEMORY "Enable MemorySanitizer" OFF)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(ENABLE_SANITIZER_ADDRESS OFF)
  set(ENABLE_SANITIZER_LEAK OFF)
  set(ENABLE_SANITIZER_UNDEFINED_BEHAVIOR OFF)
  set(ENABLE_SANITIZER_THREAD OFF)
  set(ENABLE_SANITIZER_MEMORY OFF)
endif()

#Interface to carry sanitizer flags
add_library(project_sanitizers INTERFACE)

project_enable_sanitizers(
    project_sanitizers 
    ${ENABLE_SANITIZER_ADDRESS}
    ${ENABLE_SANITIZER_LEAK}
    ${ENABLE_SANITIZER_UNDEFINED_BEHAVIOR}
    ${ENABLE_SANITIZER_THREAD}
    ${ENABLE_SANITIZER_MEMORY}
)

endif()


##Tests
option(RTPCPP_ENABLE_TESTS "Enable tests" ON)
if(RTPCPP_ENABLE_TESTS)
    include(third_party/catch2.cmake)
    add_executable(rtp_test tests/parse_rtp.cpp)

    target_link_libraries(rtp_test PRIVATE Catch2::Catch2WithMain)
    
endif()


