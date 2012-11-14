#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wsclient/wsclient.h>

int onclose(wsclient *c) {
	fprintf(stderr, "Closing websocket with: %d\n", c->sockfd);
}

int onerror(wsclient *c, wsclient_error *err) {
	fprintf(stderr, "Error occured (%d): %s\n", err->code, err->str);
}

int onmessage(wsclient *c, wsclient_message *msg) {
	fprintf(stderr, "Received (%llu): %s\n", msg->payload_len, msg->payload);
	return 0;
}

int onopen(wsclient *c) {
	fprintf(stderr, "onopen called.\n");
	libwsclient_send(c, "testing::testing::demo.paydensutherland.com");
	return 0;
}

int main(int argc, char **argv) {
	wsclient *client = libwsclient_new("ws://ip6-localhost:8080");
	if(!client) {
		fprintf(stderr, "Unable to initialize new WS client.\n");
		exit(1);
	}
	libwsclient_onopen(client, &onopen);
	libwsclient_onmessage(client, &onmessage);
	libwsclient_onerror(client, &onerror);
	libwsclient_onclose(client, &onclose);
	libwsclient_run(client);
	libwsclient_finish(client);
	return 0;
}

