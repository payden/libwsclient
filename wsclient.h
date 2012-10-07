#include <stdint.h>
#include <pthread.h>

#ifndef WSCLIENT_H_
#define WSCLIENT_H_

#define FRAME_CHUNK_LENGTH 1024

#define CLIENT_IS_SSL (1 << 0)
#define CLIENT_CONNECTING (1 << 1)
#define CLIENT_SHOULD_CLOSE (1 << 2)
#define CLIENT_SENT_CLOSE_FRAME (1 << 3)


#define REQUEST_HAS_CONNECTION (1 << 0)
#define REQUEST_HAS_UPGRADE (1 << 1)
#define REQUEST_VALID_STATUS (1 << 2)
#define REQUEST_VALID_ACCEPT (1 << 3)

typedef struct _libwsclient_frame {
	unsigned int fin;
	unsigned int opcode;
	unsigned int mask_offset;
	unsigned int payload_offset;
	unsigned int rawdata_idx;
	unsigned int rawdata_sz;
	unsigned long long payload_len;
	char *rawdata;
	struct _libwsclient_frame *next_frame;
	struct _libwsclient_frame *prev_frame;
	unsigned char mask[4];
} libwsclient_frame;

typedef struct _libwsclient_message {
	unsigned int opcode;
	unsigned long long payload_len;
	char *payload;
} libwsclient_message;

typedef struct _wsclient {
	pthread_t handshake_thread;
	pthread_t run_thread;
	pthread_mutex_t lock;
	char *URI;
	int sockfd;
	int flags;
	int (*onopen)(struct _wsclient *);
	int (*onclose)(struct _wsclient *);
	int (*onerror)(struct _wsclient *);
	int (*onmessage)(struct _wsclient *, libwsclient_message *msg);
	libwsclient_frame *current_frame;

} wsclient;


//Function defs

wsclient *libwsclient_new(const char *URI);
int libwsclient_open_connection(const char *host, const char *port);
int stricmp(const char *s1, const char *s2);
int libwsclient_complete_frame(libwsclient_frame *frame);
void libwsclient_handle_control_frame(wsclient *c, libwsclient_frame *ctl_frame);
void libwsclient_run(wsclient *c);
void libwsclient_finish(wsclient *client);
void *libwsclient_run_thread(void *ptr);
void *libwsclient_handshake_thread(void *ptr);
void libwsclient_cleanup_frames(libwsclient_frame *first);
void libwsclient_in_data(wsclient *c, char in);
void libwsclient_dispatch_message(wsclient *c, libwsclient_frame *current);
void libwsclient_close(wsclient *c);
#endif /* WSCLIENT_H_ */
