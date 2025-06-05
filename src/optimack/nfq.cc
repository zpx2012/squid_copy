#include "Optimack.h"
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
// #include <pthread.h>
// #include <errno.h>
#include "logging.h"


NFQ::NFQ(unsigned short nfq_queue_num, void* data, int (*func)(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data))
{
    this->nfq_queue_num = nfq_queue_num;
    setup_nfq(data, func);
}


int NFQ::setup_nfq(void* data, int (*func)(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *)){
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        // debugs(0, DBG_CRITICAL,"error during nfq_open()");
        return -1;
    }

    // debugs(0, DBG_CRITICAL,"unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_unbind_pf()");
        return -1;
    }

    // debugs(0, DBG_CRITICAL,"binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    // nfq_queue_num = id;
    // debugs(0, DBG_CRITICAL,"binding this socket to queue " << nfq_queue_num);
    g_nfq_qh = nfq_create_queue(g_nfq_h, nfq_queue_num, func, data);
    if (!g_nfq_qh) {
        // debugs(0, DBG_CRITICAL,"error during nfq_create_queue()");
        return -1;
    }
    // debugs(0, DBG_CRITICAL,"nfq queue handler: " << g_nfq_qh);

    // debugs(0, DBG_CRITICAL,"setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        // debugs(0, DBG_CRITICAL,"can't set packet_copy mode");
        return -1;
    }

    unsigned int bufsize = 0x3fffffff, rc = 0;//
    if (nfq_set_queue_maxlen(g_nfq_qh, bufsize/1024) < 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    // for (; ; bufsize-=0x1000){
    //     rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    //     print_func("Buffer size %x wanted %x\n", rc, bufsize);
    //     if (rc == bufsize*2)
    //         break;
    // }
    rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    // log_info("Buffer size %x wanted %x", rc, bufsize*2);
    if(rc != bufsize*2){
        exit(-1);
    }

    g_nfq_fd = nfq_fd(g_nfq_h);

    setup_nfqloop();
    printf("nfq %d is set up\n", nfq_queue_num);

    return 0;
}

int NFQ::teardown_nfq(){
    // log_info("unbinding from queue %d", nfq_queue_num);
    if (g_nfq_qh && nfq_destroy_queue(g_nfq_qh) != 0) {
        // log_error("error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    // debugs(0, DBG_CRITICAL,"unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    // debugs(0, DBG_CRITICAL,"closing library handle");
    if (g_nfq_h && nfq_close(g_nfq_h) != 0) {
        // debugs(0, DBG_CRITICAL,"error during nfq_close()");
        return -1;
    }

    return 0;

}

NFQ::~NFQ()
{
    nfq_stop = 1;
    teardown_nfq();
}



void NFQ::nfq_loop()
{
    int rv;
    char buf[65536];

    while (!(nfq_stop)) {
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            nfq_handle_packet(g_nfq_h, buf, rv);
        }
        else {
            usleep(100); //10000
        }
    }
    return;
}

int NFQ::setup_nfqloop()
{
    nfq_stop = cb_stop = 0;
    std::thread nfq_std_thread(&NFQ::nfq_loop, this);
    nfq_std_thread.detach();
    // if (pthread_create(&nfq_thread, NULL, nfq_loop, NULL) != 0) {
    //     return -1;
    // }
    return 0;
}
