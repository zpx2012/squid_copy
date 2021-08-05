sudo apt-get update
sudo apt-get install -y libnetfilter-queue-dev
sudo apt-get install -y autotools-dev autogen autoconf libtool
# sudo apt-get -y install wireshark tshark
sudo apt-get -y install python-pip python-setuptools python-dev screen
curl http://47.116.141.4/get-pip.py --output ~/get-pip.py
pip install numpy pandas
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark tshark
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
# wget http://47.116.141.4/squid_copy.tar.gz
# tar -xvzf squid_copy.tar.gz
cd ~/squid_copy
sudo autoreconf -f -i
./configure --prefix=/usr/local/squid --disable-optimizations --enable-linux-netfilter
make
sudo make install
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -p