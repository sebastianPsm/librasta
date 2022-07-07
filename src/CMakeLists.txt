if(ENABLE_RASTA_TLS)
    find_package(WolfSSL REQUIRED)
endif(ENABLE_RASTA_TLS)

# Target name
set(target rasta)

include_directories(
    rasta/headers
    sci/headers)

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
    rasta/headers/rastablake2.h
    rasta/headers/rastasiphash24.h
    rasta/headers/rastahashing.h
)

# SCI headers
set(SCI_HDRS
    sci/headers/hashmap.h
    sci/headers/sci.h
    sci/headers/sci_telegram_factory.h
    sci/headers/scils.h
    sci/headers/scils_telegram_factory.h
    sci/headers/scip.h
    sci/headers/scip_telegram_factory.h
)

# Shared object for RaSTA and SCI protocols
add_library(${target} SHARED
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
    sci/c/hashmap.c
    rasta/c/rastablake2.c
    rasta/c/rastasiphash24.c
    rasta/c/rastahashing.c
    # SCI sources
    sci/c/sci.c
    sci/c/sci_telegram_factory.c
    sci/c/scils.c
    sci/c/scils_telegram_factory.c
    sci/c/scip.c
    sci/c/scip_telegram_factory.c
        rasta/c/key_exchange.c rasta/headers/key_exchange.h)

# Link system libraries for librasta
target_link_libraries(${target} rt pthread)
if(ENABLE_RASTA_TLS)
target_link_libraries(${target} wolfssl)
endif(ENABLE_RASTA_TLS)

set_property(TARGET ${target}
    PROPERTY PUBLIC_HEADER
    ${RASTA_HDRS}
    ${SCI_HDRS})

# if USE_OPENSSL parameter is passed to cmake or if architecture is ARM -> use openssl md4 implementation
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm" OR ${USE_OPENSSL})
    message("Using OpenSSL MD4 implementation (only standard IV)")

    # define flag to use openssl in rastamd4
    target_compile_definitions(rasta PUBLIC USE_OPENSSL)
    # link libcrypto
    target_link_libraries(rasta crypto)
else()
    message("Using rasta-c MD4 implementation")
endif()

#
# Project options
#

set_target_properties(${target}
    PROPERTIES
    ${DEFAULT_PROJECT_OPTIONS}
)

#
# Include directories
#

target_include_directories(${target}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/rasta/headers
    ${CMAKE_CURRENT_SOURCE_DIR}/sci/headers
    # Opaque headers
    ${CMAKE_CURRENT_BINARY_DIR}/include

    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/rasta/headers>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sci/headers>
)

#
# Compile options
#

target_compile_options(${target}
    PRIVATE
    ${DEFAULT_COMPILE_OPTIONS}
)

if(ENABLE_RASTA_TLS)
    target_compile_definitions(rasta PRIVATE ENABLE_TLS)
endif(ENABLE_RASTA_TLS)

if(ENABLE_RASTA_OPAQUE)
    include(CheckLinkerFlag)

    target_compile_definitions(rasta PUBLIC ENABLE_OPAQUE)
    target_link_directories(rasta PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../lib)
    check_linker_flag(C "-static" LINK_STATIC_SUPPORTED)
    check_linker_flag(C "-dynamic" LINK_DYNAMIC_SUPPORTED)
    if(${LINK_DYNAMIC_SUPPORTED} AND ${LINK_STATIC_SUPPORTED})
        message("Linker supports -static")
        # link only the libopaque library statically, and force all modules to be included
        target_link_options(rasta PUBLIC "LINKER:-static")
        if(APPLE)
            target_link_options(rasta PUBLIC "LINKER:-force-load LINKER:-lopaque")
            target_link_options(rasta PUBLIC "LINKER:-dynamic")
        else()
            target_link_options(rasta PUBLIC LINKER:--whole-archive LINKER:-lopaque LINKER:--no-whole-archive)
            target_link_options(rasta PUBLIC "LINKER:-Bdynamic")
        endif()
        # consuming application also needs to link libsodium to resolve opaque's dependencies
        target_link_options(rasta PUBLIC "LINKER:-lsodium")
    else()
        message(FATAL_ERROR "Linker does not support required linker flags!")
    endif()
endif()

# Installation for library
install(TARGETS ${target}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
