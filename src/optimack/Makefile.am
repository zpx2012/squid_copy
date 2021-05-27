## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

## Our code
include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

##SUBDIRS = openssl-bio-fetch
##DIST_SUBDIRS = openssl-bio-fetch

noinst_LTLIBRARIES = liboptim.la

liboptim_la_SOURCES = \
	Optimack.h \
	Optimack.cc \
	checksum.h \
	checksum.cc \
	hping2.cc \
	hping2.h \
	sendtcp.cc \
	socket.cc \
	socket.h \
	thr_pool.cc \
	thr_pool.h \
	util.cc \
	util.h \
	logging.cc \
	logging.h \
	globals.h \
	waitpacket.cc \
	interval.h \
	interval.cc \
	get_server_key.h \
	get_server_key.c \
	ssl_local.h \
	evp.h \
	modes_local.h \
	include/openssl/aes.h \
	include/openssl/engine.h

liboptim_la_LDFLAGS = -Bstatic -lssl -lcrypto