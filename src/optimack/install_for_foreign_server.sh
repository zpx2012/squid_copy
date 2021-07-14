sudo apt-get install -y libnetfilter-queue-dev
sudo apt-get install -y autotools-dev autogen autoconf libtool
# sudo apt-get -y install wireshark tshark
sudo apt-get -y install python-pip python-setuptools python-dev screen
curl  https://bootstrap.pypa.io/get-pip.py  --output ~/get-pip.py
pip install numpy pandas
# wget http://47.116.141.4/squid_copy.tar.gz
# tar -xvzf squid_copy.tar.gz
cd squid_copy
sudo autoreconf -f -i
./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
make
sudo make install
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -p