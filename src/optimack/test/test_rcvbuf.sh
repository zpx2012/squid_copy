# rcvbuf=212992
# rcvbufdouble=0
while true; do
    # let rcvbufdouble=2*rcvbuf
    # sudo sysctl -w net.core.rmem_max=${rcvbuf}
    sudo sysctl -p
    # sudo /usr/local/squid/sbin/squid -s
    for i in 1 2 3 4 5 6 7 8 9 10; do 
        bash test_rcvbuf_once.sh
        sleep 10
    done
    # sudo /usr/local/squid/sbin/squid -k shutdown
    # let rcvbuf+=200000
done