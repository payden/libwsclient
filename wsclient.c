#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "wsclient.h"
#include "sha1.h"

int libwsclient_run(wsclient *c) {

}



int libwsclient_open_connection(const char *host, const char *port) {
	struct addrinfo hints, *servinfo, *p;
	int rv, sockfd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("connect");
			continue;
		}
		break;
	}
	if(p == NULL) {
		fprintf(stderr, "Failed to connect.\n");
		freeaddrinfo(servinfo);
		return -1;
	}
	return sockfd;
}

wsclient *libwsclient_new(const char *URI) {
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
	wsclient *client = (wsclient *)malloc(sizeof(wsclient));
	if(!client) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(1);
	}
	memset(client, 0, sizeof(wsclient));
	URI_copy = (char *)malloc(strlen(URI)+1);
	if(!URI_copy) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(2);
	}
	memset(URI_copy, 0, strlen(URI)+1);
	strncpy(URI_copy, URI, strlen(URI));
	p = strstr(URI_copy, "://");
	if(p == NULL) {
		fprintf(stderr, "Malformed or missing scheme for URI.\n");
		exit(3);
	}
	strncpy(scheme, URI_copy, p-URI_copy);
	scheme[p-URI_copy] = '\0';
	if(strcmp(scheme, "ws") != 0 && strcmp(scheme, "wss") != 0) {
		fprintf(stderr, "Invalid scheme for URI: %s\n", scheme);
		exit(4);
	}
	for(i=p-URI_copy+3,z=0;*(URI_copy+i) != '/' && *(URI_copy+i) != ':' && *(URI_copy+i) != '\0';i++,z++) {
		host[z] = *(URI_copy+i);
	}
	host[z] = '\0';
	if(*(URI_copy+i) == '\0') {
		//end of URI request path will be /
		strncpy(path, "/", 1);
	} else {
		if(*(URI_copy+i) != ':') {
			if(strcmp(scheme, "ws") == 0) {
				strncpy(port, "80", 9);
			} else {
				strncpy(port, "443", 9);
				client->flags |= CLIENT_IS_SSL;
			}
		} else {
			i++;
			p = strchr(URI_copy+i, '/');
			strncpy(port, URI_copy+i, (p - (URI_copy+i)));
			port[p-(URI_copy+i)] = '\0';
			i += p-(URI_copy+i);
		}
	}
	strncpy(path, URI_copy+i, 254);
	free(URI_copy);
	sockfd = libwsclient_open_connection(host, port);
	if(sockfd == -1) {
		fprintf(stderr, "Error opening socket.\n");
		exit(5);
	}
	client->sockfd = sockfd;

	//perform handshake
	//generate nonce
	srand(time(NULL));
	for(z=0;z<16;z++) {
		key_nonce[z] = rand() & 0xff;
	}
	base64_encode(key_nonce, 16, websocket_key, 256);
	memset(request_headers, 0, 1024);

	if(strcmp(port, "80") != 0) {
		snprintf(request_host, 256, "%s:%s", host, port);
	} else {
		snprintf(request_host, 256, "%s", host);
	}
	snprintf(request_headers, 1024, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: %s\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, request_host, websocket_key);
	n = send(client->sockfd, request_headers, strlen(request_headers), 0);
	z = 0;
	memset(recv_buf, 0, 1024);
	do {
		n = recv(client->sockfd, recv_buf + z, 1023 - z, 0);
		z += n;
	} while((z < 4 || strcmp(recv_buf + z - 4, "\r\n\r\n") != 0) && n > 0);
	//parse recv_buf for response headers and assure Accept matches expected value
	rcv = (char *)malloc(strlen(recv_buf)+1);
	if(!rcv) {
		fprintf(stderr, "Unable to allocate memory in libwsclient_new.\n");
		exit(6);
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
				fprintf(stderr, "Invalid HTTP version or invalid HTTP status from server: %s\n", tok);
				exit(7);
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
		fprintf(stderr, "Response from server did not include Upgrade header, failing.\n");
		exit(8);
	}
	if(!flags & REQUEST_HAS_CONNECTION) {
		fprintf(stderr,  "Response from server did not include Connection header, failing.\n");
		exit(9);
	}
	if(!flags & REQUEST_VALID_ACCEPT) {
		fprintf(stderr, "Server did not send valid Sec-WebSocket-Accept header, failing.\n");
		exit(10);
	}
	return client;
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

int libwsclient_send(wsclient *client, char *strdata)  {
	if(strdata == NULL) {
		fprintf(stderr, "Will not send empty message.\n");
		return -1;
	}
	int sockfd = client->sockfd;
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
	int i;
	unsigned int frame_size;
	char *data;
	gettimeofday(&tv);
	srand(tv.tv_usec * tv.tv_sec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	payload_len = strlen(strdata);
	finNopcode = 0x81; //FIN and text opcode.
	if(payload_len <= 125) {
		frame_size = 6 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = payload_len;

	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 8 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 14 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		fprintf(stderr, "Whoa man.  What are you trying to send?\n");
		return -1;
	}
	memset(data, 0, frame_size);
	payload_len_small |= 0x80;
	memcpy(data, &finNopcode, 1);
	memcpy(data+1, &payload_len_small, 1); //mask bit om, 7 bit payload len
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	for(i=0;i<4;i++)
		*(data+(payload_offset-4)+i) = mask[i];

	memcpy(data+payload_offset, strdata, strlen(strdata));
	for(i=0;i<strlen(strdata);i++)
		*(data+payload_offset+i) ^= mask[i % 4] & 0xff;
	sent = 0;

	while(sent < frame_size) {
		sent += send(sockfd, data+sent, frame_size - sent, 0);
	}
	free(data);
	return sent;
}


