libwsclient
===========


WebSocket client library for C

This library abstracts away WebSocket protocol framing for
client connections.  It aims to provide a *somewhat* similar
API to the implementation in your browser.  You create a new
client context and create callbacks to be triggered when
certain events occur (onopen, onmessage, onclose, onerror).

Your best bet for getting started is to look at test.c which shows
how to connect to an echo server using libwsclient calls.

Also, to install:

./autogen.sh

./configure && make && sudo make install

Then link your C program against wsclient: 'gcc -g -O2 -o test test.c -lwsclient'


