/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CachePeer.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"
#include "fde.h"
#include "FwdState.h"
#include "neighbors.h"
#include "security/NegotiationHistory.h"
#include "SquidConfig.h"
#include "SquidTime.h"

class CachePeer;
bool
Comm::IsConnOpen(const Comm::ConnectionPointer &conn)
{
    return conn != NULL && conn->isOpen();
}

Comm::Connection::Connection() :
    peerType(HIER_NONE),
    fd(-1),
    tos(0),
    nfmark(0),
    flags(COMM_NONBLOCKING),
    peer_(nullptr),
    startTime_(squid_curtime),
    tlsHistory(nullptr)
{
    *rfc931 = 0; // quick init the head. the rest does not matter.
#ifdef USE_OPTIMACK
    optimack_server = nullptr;
#endif
}

static int64_t lost_conn = 0;
Comm::Connection::~Connection()
{
    if (fd >= 0) {
        debugs(5, 4, "BUG #3329: Orphan Comm::Connection: " << *this);
        debugs(5, 4, "NOTE: " << ++lost_conn << " Orphans since last started.");
        close();
    }

    cbdataReferenceDone(peer_);

    delete tlsHistory;

    /* Our code */
    // if(optimack_server){
        // optimack_server->cleanup();
        // delete optimack_server;
        // optimack_server = nullptr;
    // }
}

#ifdef USE_OPTIMACK
void Comm::Connection::setOptimack(){
    // optimack_server = new Optimack();
    char remote_ip[16], local_ip[16];
    remote.toStr(remote_ip, 16);
    local.toStr(local_ip, 16);
    // printf(remote_ip);
    // printf(local_ip);

    std::string ips[5] = {"52.41.132.37", "34.215.6.110", "34.160.144.191", "34.120.158.37", "34.102.187.140"};
    for(uint i = 0; i < 5; i++)
        if(ips[i].compare(remote_ip) == 0)
            return;

    optimack_server = std::make_shared<Optimack>();
    if (optimack_server){
        // NFQ nfq_opt(333, (void*)optimack_server.get(), &cb);
        optimack_server->init();
        // optimack_server->setup_nfq(local.port());
        // optimack_server->nfq_stop = 0;
        // optimack_server->setup_nfqloop();
        
        optimack_server->set_main_subconn(remote_ip, local_ip, remote.port(), local.port(), fd);
    }
}
#endif


Comm::ConnectionPointer
Comm::Connection::copyDetails() const
{
    ConnectionPointer c = new Comm::Connection;

    c->setAddrs(local, remote);
    c->peerType = peerType;
    c->tos = tos;
    c->nfmark = nfmark;
    c->flags = flags;
    c->startTime_ = startTime_;

    // ensure FD is not open in the new copy.
    c->fd = -1;

    // ensure we have a cbdata reference to peer_ not a straight ptr copy.
    c->peer_ = cbdataReference(getPeer());

    return c;
}

void
Comm::Connection::close()
{
    if (isOpen()) {
        comm_close(fd);
        noteClosure();
    }
}

void
Comm::Connection::noteClosure()
{
    if (isOpen()) {
        fd = -1;
        if (CachePeer *p=getPeer())
            peerConnClosed(p);
    }
}

CachePeer *
Comm::Connection::getPeer() const
{
    if (cbdataReferenceValid(peer_))
        return peer_;

    return NULL;
}

void
Comm::Connection::setPeer(CachePeer *p)
{
    /* set to self. nothing to do. */
    if (getPeer() == p)
        return;

    cbdataReferenceDone(peer_);
    if (p) {
        peer_ = cbdataReference(p);
    }
}

time_t
Comm::Connection::timeLeft(const time_t idleTimeout) const
{
    if (!Config.Timeout.pconnLifetime)
        return idleTimeout;

    const time_t lifeTimeLeft = lifeTime() < Config.Timeout.pconnLifetime ? Config.Timeout.pconnLifetime - lifeTime() : 1;
    return min(lifeTimeLeft, idleTimeout);
}

Security::NegotiationHistory *
Comm::Connection::tlsNegotiations()
{
    if (!tlsHistory)
        tlsHistory = new Security::NegotiationHistory;
    return tlsHistory;
}

time_t
Comm::Connection::connectTimeout(const time_t fwdStart) const
{
    // a connection opening timeout (ignoring forwarding time limits for now)
    const CachePeer *peer = getPeer();
    const time_t ctimeout = peer ? peerConnectTimeout(peer) : Config.Timeout.connect;

    // time we have left to finish the whole forwarding process
    const time_t fwdTimeLeft = FwdState::ForwardTimeout(fwdStart);

    // The caller decided to connect. If there is no time left, to protect
    // connecting code from trying to establish a connection while a zero (i.e.,
    // "immediate") timeout notification is firing, ensure a positive timeout.
    // XXX: This hack gives some timed-out forwarding sequences more time than
    // some sequences that have not quite reached the forwarding timeout yet!
    const time_t ftimeout = fwdTimeLeft ? fwdTimeLeft : 5; // seconds

    return min(ctimeout, ftimeout);
}

