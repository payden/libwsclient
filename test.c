#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wsclient/wsclient.h>

int onopen(void) {
	fprintf(stderr, "Connection opened.\n");
	return 0;
}

int onmessage(char *msg, int64_t length) {
	fprintf(stderr, "Received message (%ull): %s\n", length, msg);
	return 0;
}

int main(int argc, char **argv) {
	wsclient *client = libwsclient_new("ws://localhost:3333/mtgox");
	if(!client) {
		fprintf(stderr, "Unable to initialize new WS client.\n");
		exit(1);
	}
	client->onopen = &onopen;
	client->onmessage = &onmessage;
	libwsclient_send(client, "Testing");
	libwsclient_run(client);
	return 0;
}

