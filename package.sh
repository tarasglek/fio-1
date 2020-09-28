set -x -e
make clean; ./configure --build-static --disable-native && make -j
# curl -XPUT $ARTIFACTORY_URL/artifactory/ir-tools/benchmarks/fio-nfs.1.debug -T fio
