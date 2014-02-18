# Martin Konrad <kon...@ikp.tu-darmstadt.de>
# License: GPLv2/v3
#
# Try to find libpcre (Perl Compatible Regular Expressions)
#
# Once done this will define
#
# PCRE_FOUND - system has libpcre
# PCRE_INCLUDE_DIR - the libpcre include directory
# PCRE_LIBRARY - where to find libpcre
# PCRE_LIBRARIES - Link these to use libpcre

if(PCRE_INCLUDE_DIR AND PCRE_LIBRARIES)
        # in cache already
        set(LIBUSB_FOUND TRUE)
else(PCRE_INCLUDE_DIR AND PCRE_LIBRARIES)
        if(NOT WIN32)
                # use pkg-config to get the directories and then use these values
                # in the FIND_PATH() and FIND_LIBRARY() calls
                find_package(PkgConfig)
                pkg_check_modules(PC_PCRE libpcre)
        endif(NOT WIN32)

        find_path(PCRE_INCLUDE_DIR
                NAMES
                        pcre.h
                HINTS
                        ${PCRE_PKG_INCLUDE_DIRS}
                PATHS
                        /usr/include
                        /usr/local/include
        )

        find_library(PCRE_LIBRARY
                NAMES
                        pcre
                HINTS
                        ${PCRE_PKG_LIBRARY_DIRS}
                PATHS
                        /usr/lib
                        /usr/local/lib
        )

        set(PCRE_LIBRARIES ${PCRE_LIBRARY})

        # handle the QUIETLY AND REQUIRED arguments AND set PCRE_FOUND to TRUE if
        # all listed variables are TRUE
        # include(${CMAKE_CURRENT_LIST_DIR}/FindPackageHandleStandardArgs.cmake)
        include(FindPackageHandleStandardArgs)
        find_package_handle_standard_args(PCRE DEFAULT_MSG PCRE_LIBRARY PCRE_INCLUDE_DIR)

        mark_as_advanced(PCRE_INCLUDE_DIR PCRE_LIBRARY)
endif(PCRE_INCLUDE_DIR AND PCRE_LIBRARIES)
