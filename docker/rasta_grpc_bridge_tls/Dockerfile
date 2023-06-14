FROM ubuntu:22.04

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends libtool autogen automake autoconf git ca-certificates build-essential cmake

RUN cd /tmp \
 && git clone --recurse-submodules -b v1.47.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc \
 && cd grpc \
 && mkdir -p cmake/build && cd cmake/build \
 && cmake ../.. -DgRPC_INSTALL=ON \
 && make -j16 && make install \
 && cd / && rm -rf /tmp/grpc

RUN cd /tmp \
 && git clone --recurse-submodules -b v5.2.0-stable --depth 1 --shallow-submodules https://github.com/wolfssl/wolfssl \
 && cd wolfssl \
 && ./autogen.sh \
 && ./configure --enable-dtls --enable-debug --enable-certgen --enable-tls13 CFLAGS="-DHAVE_SECRET_CALLBACK" --enable-opensslextra \
 && make && make install \
 && cd / && rm -rf /tmp/wolfssl

ENV LD_LIBRARY_PATH=/usr/local/lib:.

WORKDIR /app
COPY build/librasta_tls.so build/rasta_grpc_bridge_tls ./

ENTRYPOINT ["/app/rasta_grpc_bridge_tls"]
