#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <signal.h>



#include <pthread.h>

#include "wsclient.h"
#include "config.h"
#include "sha1.h"


void libwsclient_run(wsclient *c) {
	if(c->flags & CLIENT_CONNECTING) {
		pthread_join(c->handshake_thread, NULL);
		pthread_mutex_lock(&c->lock);
		c->flags &= ~CLIENT_CONNECTING;
		free(c->URI);
		c->URI = NULL;
		pthread_mutex_unlock(&c->lock);
	}
	if(c->sockfd) {
		pthread_create(&c->run_thread, NULL, libwsclient_run_thread, (void *)c);
	}
}

void *libwsclient_run_thread(void *ptr) {
	wsclient *c = (wsclient *)ptr;
	wsclient_error *err = NULL;
	int sockfd;
	char buf[1024];
	int n, i;
	do {
		memset(buf, 0, 1024);
		n = _libwsclient_read(c, buf, 1023);
		for(i = 0; i < n; i++)
			libwsclient_in_data(c, buf[i]);

	} while(n > 0);

	if(n < 0) {
		if(c->onerror) {
			err = libwsclient_new_error(WS_RUN_THREAD_RECV_ERR);
			err->extra_code = n;
			c->onerror(c, err);
			free(err);
			err = NULL;
		}

	}

	if(c->onclose) {
		c->onclose(c);
	}
	close(c->sockfd);
	free(c);
	return NULL;
}

void libwsclient_finish(wsclient *client) {
	//TODO: handle UNIX socket helper thread shutdown better than killing it...  :P
	if(client->helper_thread) {
		pthread_kill(client->helper_thread, SIGINT);
	}
	if(client->run_thread) {
		pthread_join(client->run_thread, NULL);
	}

}

void libwsclient_onclose(wsclient *client, int (*cb)(wsclient *c)) {
	pthread_mutex_lock(&client->lock);
	client->onclose = cb;
	pthread_mutex_unlock(&client->lock);
}

void libwsclient_onopen(wsclient *client, int (*cb)(wsclient *c)) {
	pthread_mutex_lock(&client->lock);
	client->onopen = cb;
	pthread_mutex_unlock(&client->lock);
}

void libwsclient_onmessage(wsclient *client, int (*cb)(wsclient *c, wsclient_message *msg)) {
	pthread_mutex_lock(&client->lock);
	client->onmessage = cb;
	pthread_mutex_unlock(&client->lock);
}

void libwsclient_onerror(wsclient *client, int (*cb)(wsclient *c, wsclient_error *err)) {
	pthread_mutex_lock(&client->lock);
	client->onerror = cb;
	pthread_mutex_unlock(&client->lock);
}

void libwsclient_close(wsclient *client) {
	wsclient_error *err = NULL;
	char data[6];
	int i = 0, n, mask_int;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec * tv.tv_usec);
	mask_int = rand();
	memcpy(data+2, &mask_int, 4);
	data[0] = 0x88;
	data[1] = 0x80;
	pthread_mutex_lock(&client->send_lock);
	do {
		n = _libwsclient_write(client, data, 6);
		i += n;
	} while(i < 6 && n > 0);
	pthread_mutex_unlock(&client->send_lock);
	if(n < 0) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_DO_CLOSE_SEND_ERR);
			err->extra_code = n;
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return;
	}
	pthread_mutex_lock(&client->lock);
	client->flags |= CLIENT_SENT_CLOSE_FRAME;
	pthread_mutex_unlock(&client->lock);
}

void libwsclient_handle_control_frame(wsclient *c, wsclient_frame *ctl_frame) {
	wsclient_error *err = NULL;
	wsclient_frame *ptr = NULL;
	int i, n = 0;
	char mask[4];
	int mask_int;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec * tv.tv_usec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	pthread_mutex_lock(&c->lock);
	switch(ctl_frame->opcode) {
		case 0x8:
			//close frame
			if((c->flags & CLIENT_SENT_CLOSE_FRAME) == 0) {
				//server request close.  Send close frame as acknowledgement.
				for(i=0;i<ctl_frame->payload_len;i++)
					*(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (mask[i % 4] & 0xff); //mask payload
				*(ctl_frame->rawdata + 1) |= 0x80; //turn mask bit on
				i = 0;
				pthread_mutex_lock(&c->send_lock);
				while(i < ctl_frame->payload_offset + ctl_frame->payload_len && n >= 0) {
					n = _libwsclient_write(c, ctl_frame->rawdata + i, ctl_frame->payload_offset + ctl_frame->payload_len - i);
					i += n;
				}
				pthread_mutex_unlock(&c->send_lock);
				if(n < 0) {
					if(c->onerror) {
						err = libwsclient_new_error(WS_HANDLE_CTL_FRAME_SEND_ERR);
						err->extra_code = n;
						c->onerror(c, err);
						free(err);
						err = NULL;
					}
				}
			}
			c->flags |= CLIENT_SHOULD_CLOSE;
			break;
		default:
			fprintf(stderr, "Unhandled control frame received.  Opcode: %d\n", ctl_frame->opcode);
			break;
	}

	ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
	free(ctl_frame->rawdata);
	memset(ctl_frame, 0, sizeof(wsclient_frame));
	ctl_frame->prev_frame = ptr;
	ctl_frame->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
	memset(ctl_frame->rawdata, 0, FRAME_CHUNK_LENGTH);
	pthread_mutex_unlock(&c->lock);
}

inline void libwsclient_in_data(wsclient *c, char in) {
	wsclient_frame *current = NULL, *new = NULL;
	unsigned char payload_len_short;
	pthread_mutex_lock(&c->lock);
	if(c->current_frame == NULL) {
		c->current_frame = (wsclient_frame *)malloc(sizeof(wsclient_frame));
		memset(c->current_frame, 0, sizeof(wsclient_frame));
		c->current_frame->payload_len = -1;
		c->current_frame->rawdata_sz = FRAME_CHUNK_LENGTH;
		c->current_frame->rawdata = (char *)malloc(c->current_frame->rawdata_sz);
		memset(c->current_frame->rawdata, 0, c->current_frame->rawdata_sz);
	}
	current = c->current_frame;
	if(current->rawdata_idx >= current->rawdata_sz) {
		current->rawdata_sz += FRAME_CHUNK_LENGTH;
		current->rawdata = (char *)realloc(current->rawdata, current->rawdata_sz);
		memset(current->rawdata + current->rawdata_idx, 0, current->rawdata_sz - current->rawdata_idx);
	}
	*(current->rawdata + current->rawdata_idx++) = in;
	pthread_mutex_unlock(&c->lock);
	if(libwsclient_complete_frame(c, current) == 1) {
		if(current->fin == 1) {
			//is control frame
			if((current->opcode & 0x08) == 0x08) {
				libwsclient_handle_control_frame(c, current);
			} else {
				libwsclient_dispatch_message(c, current);
				c->current_frame = NULL;
			}
		} else {
			new = (wsclient_frame *)malloc(sizeof(wsclient_frame));
			memset(new, 0, sizeof(wsclient_frame));
			new->payload_len = -1;
			new->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
			memset(new->rawdata, 0, FRAME_CHUNK_LENGTH);
			new->prev_frame = current;
			current->next_frame = new;
			c->current_frame = new;
		}
	}
}

void libwsclient_dispatch_message(wsclient *c, wsclient_frame *current) {
	unsigned long long message_payload_len, message_offset;
	int message_opcode, i;
	char *message_payload;
	wsclient_frame *first = NULL;
	wsclient_message *msg = NULL;
	wsclient_error *err = NULL;
	if(current == NULL) {
		if(c->onerror) {
			err = libwsclient_new_error(WS_DISPATCH_MESSAGE_NULL_PTR_ERR);
			c->onerror(c, err);
			free(err);
			err = NULL;
		}
		return;
	}
	message_offset = 0;
	message_payload_len = current->payload_len;
	for(;current->prev_frame != NULL;current = current->prev_frame) {
		message_payload_len += current->payload_len;
	}
	first = current;
	message_opcode = current->opcode;
	message_payload = (char *)malloc(message_payload_len + 1);
	memset(message_payload, 0, message_payload_len + 1);
	for(;current != NULL; current = current->next_frame) {
		memcpy(message_payload + message_offset, current->rawdata + current->payload_offset, current->payload_len);
		message_offset += current->payload_len;
	}


	libwsclient_cleanup_frames(first);
	msg = (wsclient_message *)malloc(sizeof(wsclient_message));
	memset(msg, 0, sizeof(wsclient_message));
	msg->opcode = message_opcode;
	msg->payload_len = message_offset;
	msg->payload = message_payload;
	if(c->onmessage != NULL) {
		c->onmessage(c, msg);
	} else {
		fprintf(stderr, "No onmessage call back registered with libwsclient.\n");
	}
	free(msg->payload);
	free(msg);
}
void libwsclient_cleanup_frames(wsclient_frame *first) {
	wsclient_frame *this = NULL;
	wsclient_frame *next = first;
	while(next != NULL) {
		this = next;
		next = this->next_frame;
		if(this->rawdata != NULL) {
			free(this->rawdata);
		}
		free(this);
	}
}

int libwsclient_complete_frame(wsclient *c, wsclient_frame *frame) {
	wsclient_error *err = NULL;
	int payload_len_short, i;
	unsigned long long payload_len = 0;
	if(frame->rawdata_idx < 2) {
		return 0;
	}
	frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
	frame->opcode = *(frame->rawdata) & 0x0f;
	frame->payload_offset = 2;
	if((*(frame->rawdata+1) & 0x80) != 0x0) {
		if(c->onerror) {
			err = libwsclient_new_error(WS_COMPLETE_FRAME_MASKED_ERR);
			c->onerror(c, err);
			free(err);
			err = NULL;
		}
		pthread_mutex_lock(&c->lock);
		c->flags |= CLIENT_SHOULD_CLOSE;
		pthread_mutex_unlock(&c->lock);
		return 0;
	}
	payload_len_short = *(frame->rawdata+1) & 0x7f;
	switch(payload_len_short) {
	case 126:
		if(frame->rawdata_idx < 4) {
			return 0;
		}
		for(i = 0; i < 2; i++) {
			memcpy((void *)&payload_len+i, frame->rawdata+3-i, 1);
		}
		frame->payload_offset += 2;
		frame->payload_len = payload_len;
		break;
	case 127:
		if(frame->rawdata_idx < 10) {
			return 0;
		}
		for(i = 0; i < 8; i++) {
			memcpy((void *)&payload_len+i, frame->rawdata+9-i, 1);
		}
		frame->payload_offset += 8;
		frame->payload_len = payload_len;
		break;
	default:
		frame->payload_len = payload_len_short;
		break;

	}
	if(frame->rawdata_idx < frame->payload_offset + frame->payload_len) {
		return 0;
	}
	return 1;
}

int libwsclient_open_connection(const char *host, const char *port) {
	struct addrinfo hints, *servinfo, *p;
	int rv, sockfd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
		return WS_OPEN_CONNECTION_ADDRINFO_ERR;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}
		if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);
	if(p == NULL) {
		return WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR;
	}
	return sockfd;
}

int libwsclient_helper_socket(wsclient *c, const char *path) {
	socklen_t len;
	int sockfd;
	if(c->helper_sa.sun_family) {
		fprintf(stderr, "Can only bind one UNIX socket for helper program communications.\n");
		return WS_HELPER_ALREADY_BOUND_ERR;
	}
	c->helper_sa.sun_family = AF_UNIX;
	strncpy(c->helper_sa.sun_path, path, sizeof(c->helper_sa.sun_path) - 1);
	unlink(c->helper_sa.sun_path);
	len = strlen(c->helper_sa.sun_path) + sizeof(c->helper_sa.sun_family);
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sockfd == -1) {
		fprintf(stderr, "Error creating UNIX socket.\n");
		return WS_HELPER_CREATE_SOCK_ERR;
	}


	if(bind(sockfd, (struct sockaddr *)&c->helper_sa, len) == -1) {
		fprintf(stderr, "Error binding UNIX socket.\n");
		perror("bind");
		close(sockfd);
		memset(&c->helper_sa, 0, sizeof(struct sockaddr_un));
		return WS_HELPER_BIND_ERR;
	}

	if(listen(sockfd, 5) == -1) {
		fprintf(stderr, "Error listening on UNIX socket.\n");
		close(sockfd);
		memset(&c->helper_sa, 0, sizeof(struct sockaddr_un));
		return WS_HELPER_LISTEN_ERR;
	}

	c->helper_sock = sockfd;
	pthread_create(&c->helper_thread, NULL, libwsclient_helper_socket_thread, (void *)c);
}

void *libwsclient_helper_socket_thread(void *ptr) {
	wsclient *c = ptr;
	struct sockaddr_un remote;
	socklen_t len;
	int remote_sock, n, n2, flags;
	char recv_buf[HELPER_RECV_BUF_SIZE];
	char secondary_buf[HELPER_RECV_BUF_SIZE];



	for(;;) { //TODO: some way to cleanly break this loop
		len = sizeof(remote);

		if((remote_sock = accept(c->helper_sock, (struct sockaddr *)&remote, &len)) == -1) {
			continue;
		}

		pthread_mutex_lock(&c->send_lock);

		n2 = 0;
		n = 1;
		flags = WS_FRAGMENT_START;
		while(1) {
			memset(recv_buf, 0, HELPER_RECV_BUF_SIZE);
			n = recv(remote_sock, recv_buf, HELPER_RECV_BUF_SIZE - 1, 0);
			if(n == 0 && n2 != 0) {
				libwsclient_send_fragment(c, secondary_buf, n2, flags | WS_FRAGMENT_FIN);
				break;
			}
			if(n == 0 && n2 == 0) {
				fprintf(stderr, "Never received any data from UNIX socket, not sending anything.\n");
				break;
			}
			if(n != 0 && n2 != 0) {
				libwsclient_send_fragment(c, secondary_buf, n2, flags);
				flags &= ~WS_FRAGMENT_START;
			}
			if(n > 0) {
				memset(secondary_buf, 0, HELPER_RECV_BUF_SIZE);
				memcpy(secondary_buf, recv_buf, n);
				n2 = n;
			}
			if(n < 0) {
				fprintf(stderr, "Error occured\n");
				perror("recv");
				break;
			}

		}
		pthread_mutex_unlock(&c->send_lock);
		close(remote_sock);
	}
	return NULL;
}

wsclient *libwsclient_new(const char *URI) {
	wsclient *client = NULL;

	client = (wsclient *)malloc(sizeof(wsclient));
	if(!client) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(WS_EXIT_MALLOC);
	}
	memset(client, 0, sizeof(wsclient));
	if(pthread_mutex_init(&client->lock, NULL) != 0) {
		fprintf(stderr, "Unable to init mutex in libwsclient_new.\n");
		exit(WS_EXIT_PTHREAD_MUTEX_INIT);
	}
	if(pthread_mutex_init(&client->send_lock, NULL) != 0) {
		fprintf(stderr, "Unable to init send lock in libwsclient_new.\n");
		exit(WS_EXIT_PTHREAD_MUTEX_INIT);
	}
	pthread_mutex_lock(&client->lock);
	client->URI = (char *)malloc(strlen(URI)+1);
	if(!client->URI) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(WS_EXIT_MALLOC);
	}
	memset(client->URI, 0, strlen(URI)+1);
	strncpy(client->URI, URI, strlen(URI));
	client->flags |= CLIENT_CONNECTING;
	pthread_mutex_unlock(&client->lock);

	if(pthread_create(&client->handshake_thread, NULL, libwsclient_handshake_thread, (void *)client)) {
		fprintf(stderr, "Unable to create handshake thread.\n");
		exit(WS_EXIT_PTHREAD_CREATE);
	}
	return client;
}
void *libwsclient_handshake_thread(void *ptr) {
	wsclient *client = (wsclient *)ptr;
	wsclient_error *err = NULL;
	const char *URI = client->URI;
	SHA1Context shactx;
	const char *UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	char pre_encode[256];
	char sha1bytes[20];
	char expected_base64[512];
	char request_headers[1024];
	char websocket_key[256];
	char key_nonce[16];
	char scheme[10];
	char host[255];
	char request_host[255];
	char port[10];
	char path[255];
	char recv_buf[1024];
	char *URI_copy = NULL, *p = NULL, *rcv = NULL, *tok = NULL;
	int i, z, sockfd, n, flags = 0, headers_space = 1024;
	URI_copy = (char *)malloc(strlen(URI)+1);
	if(!URI_copy) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(WS_EXIT_MALLOC);
	}
	memset(URI_copy, 0, strlen(URI)+1);
	strncpy(URI_copy, URI, strlen(URI));
	p = strstr(URI_copy, "://");
	if(p == NULL) {
		fprintf(stderr, "Malformed or missing scheme for URI.\n");
		exit(WS_EXIT_BAD_SCHEME);
	}
	strncpy(scheme, URI_copy, p-URI_copy);
	scheme[p-URI_copy] = '\0';
	if(strcmp(scheme, "ws") != 0 && strcmp(scheme, "wss") != 0) {
		fprintf(stderr, "Invalid scheme for URI: %s\n", scheme);
		exit(WS_EXIT_BAD_SCHEME);
	}
	if(strcmp(scheme, "ws") == 0) {
		strncpy(port, "80", 9);
	} else {
		strncpy(port, "443", 9);
		pthread_mutex_lock(&client->lock);
		client->flags |= CLIENT_IS_SSL;
		pthread_mutex_unlock(&client->lock);
	}
	for(i=p-URI_copy+3,z=0;*(URI_copy+i) != '/' && *(URI_copy+i) != ':' && *(URI_copy+i) != '\0';i++,z++) {
		host[z] = *(URI_copy+i);
	}
	host[z] = '\0';
	if(*(URI_copy+i) == ':') {
		i++;
		p = strchr(URI_copy+i, '/');
		if(!p)
			p = strchr(URI_copy+i, '\0');
		strncpy(port, URI_copy+i, (p - (URI_copy+i)));
		port[p-(URI_copy+i)] = '\0';
		i += p-(URI_copy+i);
	}
	if(*(URI_copy+i) == '\0') {
		//end of URI request path will be /
		strncpy(path, "/", 1);
	} else {
		strncpy(path, URI_copy+i, 254);
	}
	free(URI_copy);
	sockfd = libwsclient_open_connection(host, port);


	if(sockfd < 0) {
		if(client->onerror) {
			err = libwsclient_new_error(sockfd);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}

#ifdef HAVE_LIBSSL
	if(client->flags & CLIENT_IS_SSL) {
		if((libwsclient_flags & WS_FLAGS_SSL_INIT) == 0) {
			SSL_library_init();
			SSL_load_error_strings();
			libwsclient_flags |= WS_FLAGS_SSL_INIT;
		}
		client->ssl_ctx = SSL_CTX_new(SSLv23_method());
		client->ssl = SSL_new(client->ssl_ctx);
		SSL_set_fd(client->ssl, sockfd);
		SSL_connect(client->ssl);
	}
#endif

	pthread_mutex_lock(&client->lock);
	client->sockfd = sockfd;
	pthread_mutex_unlock(&client->lock);
	//perform handshake
	//generate nonce
	srand(time(NULL));
	for(z=0;z<16;z++) {
		key_nonce[z] = rand() & 0xff;
	}
	base64_encode(key_nonce, 16, websocket_key, 256);
	memset(request_headers, 0, 1024);

	if(strcmp(port, "80") != 0) {
		snprintf(request_host, 255, "%s:%s", host, port);
	} else {
		snprintf(request_host, 255, "%s", host);
	}
	snprintf(request_headers, 1024, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: %s\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, request_host, websocket_key);
	n = _libwsclient_write(client, request_headers, strlen(request_headers));
	z = 0;
	memset(recv_buf, 0, 1024);
	//TODO: actually handle data after \r\n\r\n in case server
	// sends post-handshake data that gets coalesced in this recv
	do {
		n = _libwsclient_read(client, recv_buf + z, 1023 - z);
		z += n;
	} while((z < 4 || strstr(recv_buf, "\r\n\r\n") == NULL) && n > 0);

	if(n == 0) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_HANDSHAKE_REMOTE_CLOSED_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}
	if(n < 0) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_HANDSHAKE_RECV_ERR);
			err->extra_code = n;
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}
	//parse recv_buf for response headers and assure Accept matches expected value
	rcv = (char *)malloc(strlen(recv_buf)+1);
	if(!rcv) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(WS_EXIT_MALLOC);
	}
	memset(rcv, 0, strlen(recv_buf)+1);
	strncpy(rcv, recv_buf, strlen(recv_buf));
	memset(pre_encode, 0, 256);
	snprintf(pre_encode, 256, "%s%s", websocket_key, UUID);
	SHA1Reset(&shactx);
	SHA1Input(&shactx, pre_encode, strlen(pre_encode));
	SHA1Result(&shactx);
	memset(pre_encode, 0, 256);
	snprintf(pre_encode, 256, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2], shactx.Message_Digest[3], shactx.Message_Digest[4]);
	for(z = 0; z < (strlen(pre_encode)/2);z++)
		sscanf(pre_encode+(z*2), "%02hhx", sha1bytes+z);
	memset(expected_base64, 0, 512);
	base64_encode(sha1bytes, 20, expected_base64, 512);
	for(tok = strtok(rcv, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
		if(*tok == 'H' && *(tok+1) == 'T' && *(tok+2) == 'T' && *(tok+3) == 'P') {
			p = strchr(tok, ' ');
			p = strchr(p+1, ' ');
			*p = '\0';
			if(strcmp(tok, "HTTP/1.1 101") != 0 && strcmp(tok, "HTTP/1.0 101") != 0) {
				if(client->onerror) {
					err = libwsclient_new_error(WS_HANDSHAKE_BAD_STATUS_ERR);
					client->onerror(client, err);
					free(err);
					err = NULL;
				}
				return NULL;
			}
			flags |= REQUEST_VALID_STATUS;
		} else {
			p = strchr(tok, ' ');
			*p = '\0';
			if(strcmp(tok, "Upgrade:") == 0) {
				if(stricmp(p+1, "websocket") == 0) {
					flags |= REQUEST_HAS_UPGRADE;
				}
			}
			if(strcmp(tok, "Connection:") == 0) {
				if(stricmp(p+1, "upgrade") == 0) {
					flags |= REQUEST_HAS_CONNECTION;
				}
			}
			if(strcmp(tok, "Sec-WebSocket-Accept:") == 0) {
				if(strcmp(p+1, expected_base64) == 0) {
					flags |= REQUEST_VALID_ACCEPT;
				}
			}
		}
	}
	if(!flags & REQUEST_HAS_UPGRADE) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_HANDSHAKE_NO_UPGRADE_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}
	if(!flags & REQUEST_HAS_CONNECTION) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_HANDSHAKE_NO_CONNECTION_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}
	if(!flags & REQUEST_VALID_ACCEPT) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_HANDSHAKE_BAD_ACCEPT_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return NULL;
	}


	pthread_mutex_lock(&client->lock);
	client->flags &= ~CLIENT_CONNECTING;
	pthread_mutex_unlock(&client->lock);
	if(client->onopen != NULL) {
		client->onopen(client);
	}
	return NULL;
}

//somewhat hackish stricmp
int stricmp(const char *s1, const char *s2) {
        register unsigned char c1, c2;
        register unsigned char flipbit = ~(1 << 5);
        do {
                c1 = (unsigned char)*s1++ & flipbit;
                c2 = (unsigned char)*s2++ & flipbit;
                if(c1 == '\0')
                        return c1 - c2;
        } while(c1 == c2);
        return c1 - c2;
}

wsclient_error *libwsclient_new_error(int errcode) {
	wsclient_error *err = NULL;
	err = (wsclient_error *)malloc(sizeof(wsclient_error));
	if(!err) {
		//one of the few places we will fail and exit
		fprintf(stderr, "Unable to allocate memory in libwsclient_new_error.\n");
		exit(errcode);
	}
	memset(err, 0, sizeof(wsclient_error));
	err->code = errcode;
	switch(err->code) {
		case WS_OPEN_CONNECTION_ADDRINFO_ERR:
			err->str = *(errors + 1);
			break;
		case WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR:
			err->str = *(errors + 2);
			break;
		case WS_RUN_THREAD_RECV_ERR:
			err->str = *(errors + 3);
			break;
		case WS_DO_CLOSE_SEND_ERR:
			err->str = *(errors + 4);
			break;
		case WS_HANDLE_CTL_FRAME_SEND_ERR:
			err->str = *(errors + 5);
			break;
		case WS_COMPLETE_FRAME_MASKED_ERR:
			err->str = *(errors + 6);
			break;
		case WS_DISPATCH_MESSAGE_NULL_PTR_ERR:
			err->str = *(errors + 7);
			break;
		case WS_SEND_AFTER_CLOSE_FRAME_ERR:
			err->str = *(errors + 8);
			break;
		case WS_SEND_DURING_CONNECT_ERR:
			err->str = *(errors + 9);
			break;
		case WS_SEND_NULL_DATA_ERR:
			err->str = *(errors + 10);
			break;
		case WS_SEND_DATA_TOO_LARGE_ERR:
			err->str = *(errors + 11);
			break;
		case WS_SEND_SEND_ERR:
			err->str = *(errors + 12);
			break;
		case WS_HANDSHAKE_REMOTE_CLOSED_ERR:
			err->str = *(errors + 13);
			break;
		case WS_HANDSHAKE_RECV_ERR:
			err->str = *(errors + 14);
			break;
		case WS_HANDSHAKE_BAD_STATUS_ERR:
			err->str = *(errors + 15);
			break;
		case WS_HANDSHAKE_NO_UPGRADE_ERR:
			err->str = *(errors + 16);
			break;
		case WS_HANDSHAKE_NO_CONNECTION_ERR:
			err->str = *(errors + 17);
			break;
		case WS_HANDSHAKE_BAD_ACCEPT_ERR:
			err->str = *(errors + 18);
			break;
		default:
			err->str = *errors;
			break;
	}

	return err;
}

int libwsclient_send_fragment(wsclient *client, char *strdata, int len, int flags) {
	wsclient_error *err = NULL;
	struct timeval tv;
	unsigned char mask[4];
	unsigned int mask_int;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 6;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i, sockfd;
	unsigned int frame_size;
	char *data = NULL;


	sockfd = client->sockfd;


	if(client->flags & CLIENT_SENT_CLOSE_FRAME) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_AFTER_CLOSE_FRAME_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}
	if(client->flags & CLIENT_CONNECTING) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_DURING_CONNECT_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}

	if(strdata == NULL) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_NULL_DATA_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}

	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	payload_len = len;
	if(payload_len <= 125) {
		frame_size = 6 + payload_len;
		payload_len_small = payload_len;

	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 8 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 14 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_DATA_TOO_LARGE_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}
	data = (char *)malloc(frame_size);

	memset(data, 0, frame_size);
	*data = flags & 0xff;
	*(data+1) = payload_len_small | 0x80; //payload length with mask bit on
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	for(i=0;i<4;i++)
		*(data+(payload_offset-4)+i) = mask[i] & 0xff;

	memcpy(data+payload_offset, strdata, len);
	for(i=0;i<len;i++)
		*(data+payload_offset+i) ^= mask[i % 4] & 0xff;
	sent = 0;
	i = 1;

	//we don't need the send lock here.  It *should* have already been acquired before sending fragmented message
	//and will be released after last fragment sent.
	while(sent < frame_size && i > 0) {
		i = _libwsclient_write(client, data+sent, frame_size - sent);
		sent += i;
	}


	if(i < 0) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_SEND_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
	}

	free(data);
	return sent;
}

int libwsclient_send(wsclient *client, char *strdata)  {
	wsclient_error *err = NULL;
	struct timeval tv;
	unsigned char mask[4];
	unsigned int mask_int;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 6;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i, sockfd;
	unsigned int frame_size;
	char *data;

	sockfd = client->sockfd;

	if(client->flags & CLIENT_SENT_CLOSE_FRAME) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_AFTER_CLOSE_FRAME_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}
	if(client->flags & CLIENT_CONNECTING) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_DURING_CONNECT_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}
	if(strdata == NULL) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_NULL_DATA_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return 0;
	}

	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	payload_len = strlen(strdata);
	finNopcode = 0x81; //FIN and text opcode.
	if(payload_len <= 125) {
		frame_size = 6 + payload_len;
		payload_len_small = payload_len;

	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 8 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 14 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_DATA_TOO_LARGE_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
		return -1;
	}
	data = (char *)malloc(frame_size);
	memset(data, 0, frame_size);
	*data = finNopcode;
	*(data+1) = payload_len_small | 0x80; //payload length with mask bit on
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	for(i=0;i<4;i++)
		*(data+(payload_offset-4)+i) = mask[i];

	memcpy(data+payload_offset, strdata, strlen(strdata));
	for(i=0;i<strlen(strdata);i++)
		*(data+payload_offset+i) ^= mask[i % 4] & 0xff;
	sent = 0;
	i = 0;

	pthread_mutex_lock(&client->send_lock);
	while(sent < frame_size && i >= 0) {
		i = _libwsclient_write(client, data+sent, frame_size - sent);
		sent += i;
	}
	pthread_mutex_unlock(&client->send_lock);

	if(i < 0) {
		if(client->onerror) {
			err = libwsclient_new_error(WS_SEND_SEND_ERR);
			client->onerror(client, err);
			free(err);
			err = NULL;
		}
	}

	free(data);
	return sent;
}

ssize_t _libwsclient_read(wsclient *c, void *buf, size_t length) {
#ifdef HAVE_LIBSSL
	if(c->flags & CLIENT_IS_SSL) {
		return (ssize_t)SSL_read(c->ssl, buf, length);
	} else {
#endif
		return recv(c->sockfd, buf, length, 0);
#ifdef HAVE_LIBSSL
	}
#endif
}

ssize_t _libwsclient_write(wsclient *c, const void *buf, size_t length) {
#ifdef HAVE_LIBSSL
	if(c->flags & CLIENT_IS_SSL) {
		return (ssize_t)SSL_write(c->ssl, buf, length);
	} else {
#endif
		return send(c->sockfd, buf, length, 0);
#ifdef HAVE_LIBSSL
	}
#endif
}


