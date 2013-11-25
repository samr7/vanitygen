cmake_minimum_required(VERSION 2.6)

project(vanitygen)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DEBUG OFF)
set(USE_OPENCL OFF)

if (DEBUG)
    set(OFLAGS "-ggdb3")
else (DEBUG)
    set(OFLAGS "-O4 -march=native")
endif (DEBUG)

set(CMAKE_C_FLAGS "${OFLAGS} -Wall")

find_package(Threads REQUIRED)

set(LIBS
    pcre
    crypto
    m
    dl
    z
    ${CMAKE_THREAD_LIBS_INIT}
)

add_executable(vanitygen
    vanitygen.c
    pattern.c
    util.c
)
target_link_libraries(vanitygen
    ${LIBS}
)

add_executable(keyconv
    keyconv.c
    util.c
)
target_link_libraries(keyconv
    ${LIBS}
)

find_package(OpenCL)
if (OPENCL_FOUND AND USE_OPENCL)
    include_directories(${OPENCL_INCLUDE_DIRS})

    add_executable(oclvanitygen
        oclvanitygen.c
        oclengine.c
        pattern.c
        util.c
    )
    target_link_libraries(oclvanitygen
        ${LIBS}
        ${OPENCL_LIBRARIES}
    )

    add_executable(oclvanityminer
        oclvanityminer.c
        oclengine.c
        pattern.c
        util.c
    )
    target_link_libraries(oclvanityminer
        ${LIBS}
        ${OPENCL_LIBRARIES}
        curl
    )
endif (OPENCL_FOUND AND USE_OPENCL)
