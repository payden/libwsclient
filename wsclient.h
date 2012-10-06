#include <stdint.h>

#ifndef WSCLIENT_H_
#define WSCLIENT_H_

#define CLIENT_IS_SSL (1 << 0)

#define REQUEST_HAS_CONNECTION (1 << 0)
#define REQUEST_HAS_UPGRADE (1 << 1)
#define REQUEST_VALID_STATUS (1 << 2)
#define REQUEST_VALID_ACCEPT (1 << 3)

typedef struct _wsclient {
	int sockfd;
	int flags;
	int (*onopen)(void);
	int (*onclose)(void);
	int (*onerror)(void);
	int (*onmessage)(char *message, int64_t length);
	void (*run)(void);
} wsclient;

//Function defs

wsclient *libwsclient_new(const char *URI);
int libwsclient_open_connection(const char *host, const char *port);
int stricmp(const char *s1, const char *s2);

#endif /* WSCLIENT_H_ */
