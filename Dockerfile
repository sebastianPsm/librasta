FROM debian:11

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y install --no-install-recommends libtool autogen automake git ca-certificates build-essential

WORKDIR /tmp/wolfssl
RUN git clone https://github.com/wolfssl/wolfssl . && git checkout v4.6.0-stable \
 && ./autogen.sh \
 && ./configure --enable-dtls --enable-debug --enable-certgen --enable-tls13 CFLAGS="-DHAVE_SECRET_CALLBACK" --enable-opensslextra \
 && make && make install

ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app
COPY build .
