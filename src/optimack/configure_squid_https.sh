#!/bin/sh
set -e

prefix=$1
./configure --prefix=$prefix/squid --disable-optimizations --with-openssl=/usr/local/ssl --enable-ssl-crtd
make
make install

cd $prefix/squid/etc/
mkdir -p ssl_cert
chmod 700 ssl_cert
cd ssl_cert/
openssl req -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -extensions v3_ca -keyout myCA.pem  -out myCA.pem -subj "/C=US/ST=CA/L=RS/O=UCR"
mkdir -p $prefix/squid/var/lib
$prefix/squid/libexec/security_file_certgen -c -s $prefix/squid/var/lib/ssl_db -M 4MB

config="
# https config\nhttp_port 3129 ssl-bump cert=$prefix/squid/etc/ssl_cert/myCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB\n\n# For squid 4.x\nsslcrtd_program $prefix/squid/libexec/security_file_certgen -s $prefix/squid/var/lib/ssl_db -M 4MB\nacl step1 at_step SslBump1\nssl_bump peek step1\nssl_bump bump all\n
"
echo -e $config >> $prefix/squid/etc/squid.conf

cd $prefix/squid/
