#!/bin/sh
set -x -e
cd `dirname $0` && (make clean; ./configure --build-static --disable-native && make -j )
curl -XPUT $ARTIFACTORY_URL/artifactory/ir-tools/benchmarks/fio-nfs.a5671ade55 -T fio
