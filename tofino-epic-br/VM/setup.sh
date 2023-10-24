# SPDX-License-Identifier: AGPL-3.0-or-later

# Development Environment Setup Script
# ------------------------------------


### Install Docker (for SCION)
# See install_docker.sh


### Install SCION development environment
#### https://scion.docs.anapaya.net/en/latest/build/setup.html
cd ~
git clone https://github.com/scionproto/scion
cd scion
./tools/install_bazel
APTARGS='-y' ./tools/install_deps
sudo apt-get install -y python-is-python3
source ~/.profile
./scion.sh bazel_remote
make
docker stop bazel-remote-cache


### Install go (for SCION Apps)
#### https://go.dev/doc/install
cd ~
curl -fsSL -O https://go.dev/dl/go1.17.7.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.17.7.linux-amd64.tar.gz
rm go1.17.7.linux-amd64.tar.gz
echo 'PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile


### Install SCION Apps
#### https://github.com/netsec-ethz/scion-apps
cd ~
git clone https://github.com/netsec-ethz/scion-apps.git
cd scion-apps

#### Dependencies
sudo apt-get install -y libpam0g-dev
curl -fsSL -O https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh
sudo sh ./install.sh -b /usr/local/go/bin v1.43.0
rm install.sh

### Build
make -j $(nproc)
sudo cp -t /usr/local/go/bin bin/scion-*


### Install boost from source
sudo apt install build-essential
cd ~
curl -fsSL -O https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.bz2
if ! echo "8681f175d4bdb26c52222665793eef08490d7758529330f98d3b29dd0735bccc boost_1_78_0.tar.bz2" | sha256sum -c -; then
    echo "Incorrect checksum"
    exit 1
fi
tar -xjf boost_1_78_0.tar.bz2
rm boost_1_78_0.tar.bz2
cd boost_1_78_0
./bootstrap.sh --prefix=/usr
./b2
sudo ./b2 install


### Install gRPC from source
#### https://grpc.io/docs/languages/cpp/quickstart/
sudo apt-get install -y cmake
cd ~
git clone --recurse-submodules -b v1.43.0 https://github.com/grpc/grpc.git
cd grpc
mkdir -p cmake/build
cd cmake/build
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF ../..
make -j $(nproc)
sudo make install


### Install nanomsg
#### https://github.com/nanomsg/nanomsg
cd ~
git clone https://github.com/nanomsg/nanomsg.git
cd nanomsg
mkdir build
cd build
cmake ..
cmake --build .
sudo cmake --build . --target install
sudo ldconfig


### Install bmv2
#### https://github.com/p4lang/behavioral-model
cd ~
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model

#### Dependencies
sudo apt-get install -y automake cmake libjudy-dev libgmp-dev libpcap-dev \
libevent-dev libtool flex bison \
pkg-config g++ libssl-dev
# Boost is installed from source
# sudo apt-get install -y libboost-dev libboost-test-dev libboost-program-options-dev \
# libboost-system-dev libboost-filesystem-dev libboost-thread-dev
sudo apt-get install -y thrift-compiler libthrift-dev libnanomsg-dev
sudo pip3 install thrift

#### Build
./autogen.sh
./configure --enable-debugger --with-nanomsg --with-thrift
make -j $(nproc)
sudo make install
sudo ldconfig


### Install PI
#### https://github.com/p4lang/PI
cd ~
git clone --recursive https://github.com/p4lang/PI.git
cd PI

#### Dependencies
sudo apt-get install -y libjudy-dev libreadline-dev
# Boost is installed from source
# sudo apt-get install -y libboost-thread-dev
# protobuf and gRPC are installed from source
# sudo apt-get install -y libprotobuf-dev libgrpc-dev libgrpc++-dev protobuf-compiler \
# protobuf-compiler-grpc

#### Fix for building with Apache Thrift 0.13.0 (see https://github.com/p4lang/PI/issues/533)
sed -i -e 's#::stdcxx::shared_ptr#std::shared_ptr#g' targets/bmv2/conn_mgr.cpp

#### Build
./autogen.sh
./configure --with-bmv2 --with-proto --with-fe-cpp --with-internal-rpc --with-cli
make -j $(nproc)
sudo make install
sudo ldconfig


### Install bmv2 simple_switch_grpc
cd ~/behavioral-model
./configure --enable-debugger --with-nanomsg --with-thrift --with-pi
make -j $(nproc)
sudo make install
sudo ldconfig
cd ~/behavioral-model/targets/simple_switch_grpc
./configure --with-thrift
make -j $(nproc)
sudo make install
sudo ldconfig


### Install P4 Compiler
#### https://github.com/p4lang/p4c
cd ~
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c

#### Dependencies
sudo apt-get install -y cmake g++ git automake libtool libgc-dev bison flex \
libfl-dev libgmp-dev llvm pkg-config tcpdump doxygen graphviz
# Boost is installed from source
sudo apt-get install -y libboost-dev libboost-iostreams-dev libboost-graph-dev

#### eBPF backend dependencies
sudo apt-get install -y clang llvm libpcap-dev libelf-dev

#### Python dependencies
sudo pip3 install scapy ply

#### Build
python3 backends/ebpf/build_libbpf
mkdir build
cd build
cmake ..
make -j 2 # very memory intensive
sudo make install


### Install asio-grpc
#### https://github.com/Tradias/asio-grpc
cd ~
git clone https://github.com/Tradias/asio-grpc.git
cd asio-grpc
mkdir build
cd build
cmake ..
sudo cmake --build . --target install


### Install cppkafka
#### https://github.com/mfontanini/cppkafka
sudo apt-get install -y librdkafka-dev
cd ~
git clone https://github.com/mfontanini/cppkafka.git
cd cppkafka
mkdir build
cd build
cmake ..
make -j $(nproc)
sudo make install
sudo ldconfig


### Install P4 examples
#### https://github.com/netsys-lab/scion-int-p4.git
cd ~
git clone https://github.com/netsys-lab/scion-int-p4.git
cd scion-int-p4

#### Dependencies
sudo apt-get install -y jq mininet doctest-dev
sudo pip3 install yq mininet

#### Build
cd simple_switch/l2_switch_grpc
make
