# docker build -f Dockerfile . -t fio-builder && docker run --user $UID -ti -v `pwd`:`pwd` fio-builder $PWD/package.sh
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential  upx  libssl-dev autoconf libtool git wget pkg-config libaio-dev
# librtmp-dev libssh-dev libpsl-dev libldap2-dev libbrotli-dev libkrb5-dev tcpdump less  libnghttp2-dev

# libnfs-dev
WORKDIR /src
RUN git clone -b taras/static-build https://github.com/tarasglek/libnfs/
RUN cd libnfs && ./bootstrap && ./configure --prefix=/usr && make -j && make install
RUN apt-get remove --purge -y libcurl*
RUN wget https://curl.haxx.se/download/curl-7.66.0.tar.gz && \
tar zxvf curl-7.66.0.tar.gz && cd curl-7.66.0 && ./configure --prefix=/usr && make -j && make install
