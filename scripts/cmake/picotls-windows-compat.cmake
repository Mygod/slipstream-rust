# picotls' CMake target omits the Windows-only compatibility source that its
# Visual Studio projects include in picotls-core.
if(WIN32)
    set(_slipstream_picotls_wincompat_dir "${CMAKE_CURRENT_SOURCE_DIR}/picotlsvs/picotls")
    include_directories("${_slipstream_picotls_wincompat_dir}")

    cmake_language(
        DEFER
        DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        CALL target_sources picotls-core PRIVATE "${_slipstream_picotls_wincompat_dir}/wintimeofday.c"
    )
endif()
