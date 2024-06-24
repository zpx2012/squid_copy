#! /bin/bash

apt install -y subversion libpcre3-dev libexpat1-dev libxml2-dev libxml2 libxml2-utils
cd ~
wget https://dlcdn.apache.org//httpd/httpd-2.4.51.tar.gz
gzip -d httpd-2.4.51.tar.gz
tar xvf httpd-2.4.51.tar
wget https://dlcdn.apache.org//apr/apr-1.7.0.tar.gz
wget https://dlcdn.apache.org//apr/apr-util-1.6.1.tar.gz
tar -xf apr-1.7.0.tar.gz -C ~/httpd-2.4.51/srclib/
tar -xf apr-util-1.6.1.tar.gz -C ~/httpd-2.4.51/srclib/
mv ~/httpd-2.4.51/srclib/apr-1.7.0 ~/httpd-2.4.51/srclib/apr
mv ~/httpd-2.4.51/srclib/apr-util-1.6.1 ~/httpd-2.4.51/srclib/apr-util
cd httpd-2.4.51
./configure --with-included-apr --with-included-apr-util
make install