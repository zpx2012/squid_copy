cd ~
wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
tar xvf openssl-1.1.1k.tar.gz
sudo apt-get remove -y openssl
cd openssl-1.1.1k
./config shared --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make
make test
sudo make install
cp ~/.bashrc  ~/.bashrc.bak
echo "export PATH=\"/usr/local/ssl/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
cd /etc/ld.so.conf.d/
sudo sh -c "echo \"/usr/local/ssl/lib\" > openssl-.conf"
sudo ldconfig -v
