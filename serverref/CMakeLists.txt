cmake_minimum_required(VERSION 3.16)
project(ese_server_ref LANGUAGES CXX)

add_library(ese_server_protocol STATIC
    ../srchybrid/EseServerProtocol.cpp ../srchybrid/EseServerAuth.cpp ../srchybrid/EseServerPublication.cpp
    ../srchybrid/EseServerDescriptor.cpp
    ../srchybrid/EseRendezvousV2.cpp
    ../libkad6/src/kad6_tags.cpp ../libkad6/src/kad6_address.cpp)
target_include_directories(ese_server_protocol PUBLIC ../srchybrid)
target_include_directories(ese_server_protocol PRIVATE ../libkad6/include)
target_compile_features(ese_server_protocol PUBLIC cxx_std_17)
if(MSVC)
    target_compile_options(ese_server_protocol PRIVATE /W4 /WX)
else()
    target_compile_options(ese_server_protocol PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_server_frame ../tests/server_interop/test_server_frame.cpp)
    target_link_libraries(test_server_frame PRIVATE ese_server_protocol)
    if(MSVC)
        target_compile_options(test_server_frame PRIVATE /W4 /WX)
    else()
        target_compile_options(test_server_frame PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME DS-03-frame COMMAND test_server_frame
        "${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/server_interop/frame")
    add_executable(test_peer_binding ../tools/quic/test_channel_binding.cpp ../srchybrid/EseChannelBinding.cpp)
    target_include_directories(test_peer_binding PRIVATE ../srchybrid)
    target_compile_features(test_peer_binding PRIVATE cxx_std_17)
    add_test(NAME existing-peer-binding COMMAND test_peer_binding)
    add_executable(test_publication ../tests/server_interop/test_publication.cpp PublicationStore.cpp)
    target_include_directories(test_publication PRIVATE .)
    target_link_libraries(test_publication PRIVATE ese_server_protocol)
    if(MSVC)
        target_compile_options(test_publication PRIVATE /W4 /WX)
    else()
        target_compile_options(test_publication PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME publication-atomic COMMAND test_publication)
endif()

set(ESE_QUIC_RELEASE_ROOT "" CACHE PATH "Verified signed Windows x64 QUIC dependency root")
if(ESE_QUIC_RELEASE_ROOT)
    if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "The signed dependency root targets Windows x64")
    endif()
    get_filename_component(ESE_QUIC_RELEASE_ROOT "${ESE_QUIC_RELEASE_ROOT}" ABSOLUTE)
    execute_process(COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File
        "${CMAKE_CURRENT_SOURCE_DIR}/../tools/verify_quic_release_dependencies.ps1"
        -Root "${ESE_QUIC_RELEASE_ROOT}" -Architecture x64
        RESULT_VARIABLE checked_quic)
    if(NOT checked_quic STREQUAL "0")
        message(FATAL_ERROR "The signed QUIC dependency root failed verification")
    endif()

    add_library(ese_server_tls STATIC ServerTls.cpp)
    target_include_directories(ese_server_tls PUBLIC . "${ESE_QUIC_RELEASE_ROOT}/include-x64")
    target_link_libraries(ese_server_tls PUBLIC ese_server_protocol "${ESE_QUIC_RELEASE_ROOT}/gnutls-x64.lib")
    if(MSVC)
        target_compile_options(ese_server_tls PRIVATE /W4 /WX)
    endif()

    add_executable(ese-server-ref main.cpp ServerSession.cpp ServerIndex.cpp PublicationStore.cpp)
    target_link_libraries(ese-server-ref PRIVATE ese_server_tls ws2_32)
    if(MSVC)
        target_compile_options(ese-server-ref PRIVATE /W4 /WX)
    endif()
    file(GLOB runtime_dlls "${ESE_QUIC_RELEASE_ROOT}/runtime-x64/*.dll")
    add_custom_command(TARGET ese-server-ref POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        copy_if_different ${runtime_dlls} "$<TARGET_FILE_DIR:ese-server-ref>")

    if(BUILD_TESTING)
        add_executable(test_server_tls ../tests/server_interop/test_server_tls.cpp)
        target_link_libraries(test_server_tls PRIVATE ese_server_tls ws2_32)
        if(MSVC)
            target_compile_options(test_server_tls PRIVATE /W4 /WX)
        endif()
        add_custom_command(TARGET test_server_tls POST_BUILD COMMAND ${CMAKE_COMMAND} -E
            copy_if_different ${runtime_dlls} "$<TARGET_FILE_DIR:test_server_tls>")
        add_test(NAME server-tls-loopback COMMAND test_server_tls
            "${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/server_interop/auth")
        set_tests_properties(server-tls-loopback PROPERTIES TIMEOUT 30)
        add_executable(test_rendezvous ../tests/server_interop/test_rendezvous.cpp)
        target_link_libraries(test_rendezvous PRIVATE ese_server_tls)
        if(MSVC)
            target_compile_options(test_rendezvous PRIVATE /W4 /WX)
        endif()
        add_test(NAME DS-11-rendezvous-codec COMMAND test_rendezvous
            "${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/server_interop/rdv")
        set(ESE_SERVER_INTEROP_PYTHON "" CACHE FILEPATH "Python with pyOpenSSL for the independent reference test")
        if(ESE_SERVER_INTEROP_PYTHON)
            add_test(NAME server-reference-login COMMAND "${ESE_SERVER_INTEROP_PYTHON}"
                "${CMAKE_CURRENT_SOURCE_DIR}/../tests/server_interop/test_reference_server.py"
                "$<TARGET_FILE:ese-server-ref>")
            set_tests_properties(server-reference-login PROPERTIES TIMEOUT 30)
        endif()
    endif()
endif()
