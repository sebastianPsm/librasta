if(ENABLE_RASTA_TLS)
    find_package(WolfSSL REQUIRED)
    include(CheckSymbolExists)
    check_symbol_exists(wolfSSL_set_tls13_secret_cb "wolfssl/ssl.h" WOLFSSL_SET_TLS13_SECRET_CB_EXISTS)
    if(WOLFSSL_SET_TLS13_SECRET_CB_EXISTS)
        add_compile_definitions("-DWOLFSSL_SET_TLS13_SECRET_CB_EXISTS")
        message("Found method wolfSSL_set_tls 13_secret_cb - can provide TLS keys for debugging!")
    else()
        message("Could not find method wolfSSL_set_tls 13_secret_cb - cannot provide TLS keys for debugging!")
    endif(WOLFSSL_SET_TLS13_SECRET_CB_EXISTS)
endif(ENABLE_RASTA_TLS)

if(ENABLE_RASTA_OPAQUE)
    find_package(sodium REQUIRED)
endif()

# Target name
set(target rasta)

include_directories(rasta/headers)

# RaSTA headers
set(RASTA_HDRS
    rasta/headers/config.h
    rasta/headers/dictionary.h
    rasta/headers/event_system.h
    rasta/headers/fifo.h
    rasta/headers/logging.h
    rasta/headers/rasta_new.h
    rasta/headers/rasta_red_multiplexer.h
    rasta/headers/rastacrc.h
    rasta/headers/rastadeferqueue.h
    rasta/headers/rastafactory.h
    rasta/headers/rastahandle.h
    rasta/headers/rasta_lib.h
    rasta/headers/rastamd4.h
    rasta/headers/rastamodule.h
    rasta/headers/rastaredundancy_new.h
    rasta/headers/rastautil.h
    rasta/headers/rmemory.h
    rasta/headers/udp.h
    rasta/headers/tcp.h
    rasta/headers/rasta_transport_callbacks.h
    rasta/headers/types.h
    rasta/headers/bsd_utils.h
    rasta/headers/ssl_utils.h
    rasta/headers/rastablake2.h
    rasta/headers/rastasiphash24.h
    rasta/headers/rastahashing.h
    rasta/headers/key_exchange.h
)

set(RASTA_SRCS
    # RaSTA sources
    rasta/c/config.c
    rasta/c/dictionary.c
    rasta/c/event_system.c
    rasta/c/fifo.c
    rasta/c/logging.c
    rasta/c/rasta_new.c
    rasta/c/rasta_red_multiplexer.c
    rasta/c/rastacrc.c
    rasta/c/rastadeferqueue.c
    rasta/c/rastafactory.c
    rasta/c/rastahandle.c
    rasta/c/rastamd4.c
    rasta/c/rastamodule.c
    rasta/c/rasta_lib.c
    rasta/c/rastaredundancy_new.c
    rasta/c/rastautil.c
    rasta/c/rmemory.c
    rasta/c/udp.c
    rasta/c/tcp.c
    rasta/c/bsd_utils.c
    rasta/c/ssl_utils.c
    rasta/c/rastablake2.c
    rasta/c/rastasiphash24.c
    rasta/c/rastahashing.c
    rasta/c/key_exchange.c)

if(ENABLE_RASTA_TLS)
    set(RASTA_VARIANTS udp tcp dtls tls)
else()
    set(RASTA_VARIANTS udp tcp)
endif(ENABLE_RASTA_TLS)

foreach(RASTA_VARIANT ${RASTA_VARIANTS})

    # Shared object for RaSTA protocol
    add_library(${target}_${RASTA_VARIANT} SHARED ${RASTA_SRCS})

    # Link system libraries for librasta
    target_link_libraries(${target}_${RASTA_VARIANT} rt pthread)

    set_property(TARGET ${target}_${RASTA_VARIANT}
        PROPERTY PUBLIC_HEADER
        ${RASTA_HDRS}
        ${SCI_HDRS})

    # if USE_OPENSSL parameter is passed to cmake or if architecture is ARM -> use openssl md4 implementation
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm" OR ${USE_OPENSSL})
        message("Using OpenSSL MD4 implementation (only standard IV)")

        # define flag to use openssl in rastamd4
        target_compile_definitions(${target}_${RASTA_VARIANT} PUBLIC USE_OPENSSL)
        # link libcrypto
        target_link_libraries(${target}_${RASTA_VARIANT} crypto)
    else()
        message("Using rasta-c MD4 implementation")
    endif()

    #
    # Project options
    #

    set_target_properties(${target}_${RASTA_VARIANT}
        PROPERTIES
        ${DEFAULT_PROJECT_OPTIONS}
    )

    #
    # Include directories
    #

    target_include_directories(${target}_${RASTA_VARIANT}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/rasta/headers
        ${CMAKE_CURRENT_SOURCE_DIR}/sci/headers

        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/rasta/headers>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sci/headers>
    )

    #
    # Compile options
    #

    target_compile_options(${target}_${RASTA_VARIANT}
        PRIVATE
        ${DEFAULT_COMPILE_OPTIONS}
    )

    if(ENABLE_RASTA_OPAQUE)
        include(CheckLinkerFlag)
        target_compile_definitions(${target}_${RASTA_VARIANT} PUBLIC ENABLE_OPAQUE)
        # libopaque headers
        target_include_directories(${target}_${RASTA_VARIANT} PUBLIC ${CMAKE_BINARY_DIR}/include)
        target_link_directories(${target}_${RASTA_VARIANT} PUBLIC ${CMAKE_BINARY_DIR}/lib)

        check_linker_flag(C "-static" LINK_STATIC_SUPPORTED)
        check_linker_flag(C "-dynamic" LINK_DYNAMIC_SUPPORTED)
        if(${LINK_DYNAMIC_SUPPORTED} AND ${LINK_STATIC_SUPPORTED})
            message("Linker supports -static")
            # link only the libopaque library statically, and force all modules to be included
            target_link_options(${target}_${RASTA_VARIANT} PUBLIC "LINKER:-static")
            if(APPLE)
                target_link_options(${target}_${RASTA_VARIANT} PUBLIC "LINKER:-force-load LINKER:-lopaque")
                target_link_options(${target}_${RASTA_VARIANT} PUBLIC "LINKER:-dynamic")
            else()
                target_link_options(${target}_${RASTA_VARIANT} PUBLIC LINKER:--whole-archive LINKER:-lopaque LINKER:--no-whole-archive)
                target_link_options(${target}_${RASTA_VARIANT} PUBLIC "LINKER:-Bdynamic")
            endif()
            # consuming application also needs to link libsodium to resolve opaque's dependencies
            target_link_libraries(${target}_${RASTA_VARIANT} sodium)
        else()
            message(FATAL_ERROR "Linker does not support required linker flags!")
        endif()
    endif()

    # Installation for library
    install(TARGETS ${target}_${RASTA_VARIANT}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endforeach()

target_compile_definitions(${target}_udp PUBLIC USE_UDP)
target_compile_definitions(${target}_tcp PUBLIC USE_TCP)

if(ENABLE_RASTA_TLS)
    target_compile_definitions(${target}_dtls PUBLIC USE_UDP ENABLE_TLS)
    target_compile_definitions(${target}_tls PUBLIC USE_TCP ENABLE_TLS)

    target_link_libraries(${target}_dtls wolfssl)
    target_link_libraries(${target}_tls wolfssl)
endif(ENABLE_RASTA_TLS)
