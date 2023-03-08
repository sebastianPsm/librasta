FROM mcr.microsoft.com/devcontainers/cpp:0-ubuntu-22.04

# [Optional] Install CMake version different from what base image has already installed.
# CMake reinstall choices: none, 3.21.5, 3.22.2, or versions from https://cmake.org/download/
ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="none"

# Optionally install the cmake for vcpkg
COPY ./reinstall-cmake.sh /tmp/
RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    build-essential autoconf libtool \
        libcunit1 libcunit1-doc libcunit1-dev \
        libsodium-dev pkgconf \
        autogen automake

RUN cd /tmp \
 && git clone --recurse-submodules -b v5.2.0-stable --depth 1 --shallow-submodules https://github.com/wolfssl/wolfssl \
 && cd wolfssl \
 && ./autogen.sh \
 && ./configure --enable-dtls --enable-debug --enable-certgen --enable-tls13 CFLAGS="-DHAVE_SECRET_CALLBACK" --enable-opensslextra \
 && make && make install \
 && cd / && rm -rf /tmp/wolfssl

RUN cd /tmp \
 && git clone --recurse-submodules -b v1.47.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc \
 && cd grpc \
 && mkdir -p cmake/build && cd cmake/build \
 && cmake ../.. -DgRPC_INSTALL=ON \
 && make -j16 && make install \
 && cd / && rm -rf /tmp/grpc

ENV LD_LIBRARY_PATH=/usr/local/lib
