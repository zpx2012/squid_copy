sudo apt update
sudo apt install -y apache2
rm /var/www/html/index.html
cd /var/www/html/
wget http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso
wget http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template
wget http://mirrors.mit.edu/ubuntu/indices/md5sums.gz