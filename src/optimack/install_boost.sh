sudo apt-get remove -y libboost-dev
sudo apt-get purge -y libboost-dev
cd ~
wget https://boostorg.jfrog.io/artifactory/main/release/1.79.0/source/boost_1_79_0.tar.bz2
tar --bzip2 -xf boost_1_79_0.tar.bz2	
cd boost_1_79_0
./bootstrap.sh --prefix=/usr/
sudo ./b2 install