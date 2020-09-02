# (cd docker && docker build -f Dockerfile . -t fio-builder)
# docker run -v `pwd`:/root/fio fio-builder sh ./package.sh 
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential  upx  libssl-dev autoconf libtool git wget
# librtmp-dev libssh-dev libpsl-dev libldap2-dev libbrotli-dev libkrb5-dev tcpdump less  libnghttp2-dev

# libnfs-dev
WORKDIR /root
RUN git clone https://github.com/sahlberg/libnfs
RUN cd libnfs && ./bootstrap && ./configure --prefix=/usr && make -j && make install
RUN apt-get remove --purge -y libcurl*
RUN wget https://curl.haxx.se/download/curl-7.66.0.tar.gz && \
tar zxvf curl-7.66.0.tar.gz && cd curl-7.66.0 && ./configure --prefix=/usr && make -j && make install
RUN mkdir /root/fio
WORKDIR /root/fio