/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#ifdef  __MINGW64__
#else
#ifdef  __MINGW32__
#else
#include <netdb.h>
#endif
#endif
#include <stdarg.h>

#include <sys/stat.h>

#ifdef WIN32
#define compatible_close(fd) closesocket(fd);
#ifdef  __MINGW64__                                                             
#else                                                                           
#ifdef  __MINGW32__                                                             
#else
#include <time.h >
#endif
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#ifndef LWS_NO_FORK
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <poll.h>
#include <sys/mman.h>
#include <sys/time.h>

#define compatible_close(fd) close(fd);
#endif

#ifdef LWS_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

#include "libwebsockets.h"

extern void _lws_log(int filter, const char *format, ...);

/* warn and log are always compiled in */
#define lwsl_warn(...) _lws_log(LLL_WARN, __VA_ARGS__)
#define lwsl_err(...) _lws_log(LLL_ERR, __VA_ARGS__)

/*
 *  weaker logging can be deselected at configure time using disable_debug
 *  that gets rid of the overhead of checking while keeping _warn and _err
 *  active
 */
#ifdef _DEBUG
#define lwsl_info(...) _lws_log(LLL_INFO, __VA_ARGS__)
#define lwsl_debug(...) _lws_log(LLL_DEBUG, __VA_ARGS__)
#define lwsl_parser(...) _lws_log(LLL_PARSER, __VA_ARGS__)
#define lwsl_header(...)  _lws_log(LLL_HEADER, __VA_ARGS__)
#define lwsl_ext(...)  _lws_log(LLL_HEADER, __VA_ARGS__)
#define lwsl_client(...) _lws_log(LLL_CLIENT, __VA_ARGS__)
extern void lwsl_hexdump(void *buf, size_t len);
#else /* no debug */
#define lwsl_info(...)
#define lwsl_debug(...)
#define lwsl_parser(...)
#define lwsl_header(...)
#define lwsl_ext(...)
#define lwsl_client(...)
#define lwsl_hexdump(a, b)
#endif

/*
 * Mac OSX as well as iOS do not define the MSG_NOSIGNAL flag,
 * but happily have something equivalent in the SO_NOSIGPIPE flag.
 */
#ifdef __APPLE__
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#ifndef LWS_MAX_HEADER_NAME_LENGTH
#define LWS_MAX_HEADER_NAME_LENGTH 64
#endif
#ifndef LWS_MAX_HEADER_LEN
#define LWS_MAX_HEADER_LEN 4096
#endif
#ifndef LWS_INITIAL_HDR_ALLOC
#define LWS_INITIAL_HDR_ALLOC 256
#endif
#ifndef LWS_ADDITIONAL_HDR_ALLOC
#define LWS_ADDITIONAL_HDR_ALLOC 64
#endif
#ifndef MAX_USER_RX_BUFFER
#define MAX_USER_RX_BUFFER 4096
#endif
#ifndef MAX_BROADCAST_PAYLOAD
#define MAX_BROADCAST_PAYLOAD 4096
#endif
#ifndef LWS_MAX_PROTOCOLS
#define LWS_MAX_PROTOCOLS 10
#endif
#ifndef LWS_MAX_EXTENSIONS_ACTIVE
#define LWS_MAX_EXTENSIONS_ACTIVE 10
#endif
#ifndef SPEC_LATEST_SUPPORTED
#define SPEC_LATEST_SUPPORTED 13
#endif
#ifndef AWAITING_TIMEOUT
#define AWAITING_TIMEOUT 5
#endif
#ifndef CIPHERS_LIST_STRING
#define CIPHERS_LIST_STRING "DEFAULT"
#endif
#ifndef LWS_SOMAXCONN
#define LWS_SOMAXCONN SOMAXCONN
#endif

#define MAX_WEBSOCKET_04_KEY_LEN 128

#ifndef SYSTEM_RANDOM_FILEPATH
#define SYSTEM_RANDOM_FILEPATH "/dev/urandom"
#endif
#ifndef LWS_MAX_ZLIB_CONN_BUFFER
#define LWS_MAX_ZLIB_CONN_BUFFER (64 * 1024)
#endif

/*
 * if not in a connection storm, check for incoming
 * connections this many normal connection services
 */
#define LWS_LISTEN_SERVICE_MODULO 10

enum lws_websocket_opcodes_04 {
	LWS_WS_OPCODE_04__CONTINUATION = 0,
	LWS_WS_OPCODE_04__CLOSE = 1,
	LWS_WS_OPCODE_04__PING = 2,
	LWS_WS_OPCODE_04__PONG = 3,
	LWS_WS_OPCODE_04__TEXT_FRAME = 4,
	LWS_WS_OPCODE_04__BINARY_FRAME = 5,

	LWS_WS_OPCODE_04__RESERVED_6 = 6,
	LWS_WS_OPCODE_04__RESERVED_7 = 7,
	LWS_WS_OPCODE_04__RESERVED_8 = 8,
	LWS_WS_OPCODE_04__RESERVED_9 = 9,
	LWS_WS_OPCODE_04__RESERVED_A = 0xa,
	LWS_WS_OPCODE_04__RESERVED_B = 0xb,
	LWS_WS_OPCODE_04__RESERVED_C = 0xc,
	LWS_WS_OPCODE_04__RESERVED_D = 0xd,
	LWS_WS_OPCODE_04__RESERVED_E = 0xe,
	LWS_WS_OPCODE_04__RESERVED_F = 0xf,
};

enum lws_websocket_opcodes_07 {
	LWS_WS_OPCODE_07__CONTINUATION = 0,
	LWS_WS_OPCODE_07__TEXT_FRAME = 1,
	LWS_WS_OPCODE_07__BINARY_FRAME = 2,

	LWS_WS_OPCODE_07__NOSPEC__MUX = 7,

	/* control extensions 8+ */

	LWS_WS_OPCODE_07__CLOSE = 8,
	LWS_WS_OPCODE_07__PING = 9,
	LWS_WS_OPCODE_07__PONG = 0xa,
};


enum lws_connection_states {
	WSI_STATE_HTTP,
	WSI_STATE_HTTP_ISSUING_FILE,
	WSI_STATE_HTTP_HEADERS,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED,
	WSI_STATE_CLIENT_UNCONNECTED,
	WSI_STATE_RETURNED_CLOSE_ALREADY,
	WSI_STATE_AWAITING_CLOSE_ACK,
};

enum lws_rx_parse_state {
	LWS_RXPS_NEW,

	LWS_RXPS_SEEN_76_FF,
	LWS_RXPS_PULLING_76_LENGTH,
	LWS_RXPS_EAT_UNTIL_76_FF,

	LWS_RXPS_04_MASK_NONCE_1,
	LWS_RXPS_04_MASK_NONCE_2,
	LWS_RXPS_04_MASK_NONCE_3,

	LWS_RXPS_04_FRAME_HDR_1,
	LWS_RXPS_04_FRAME_HDR_LEN,
	LWS_RXPS_04_FRAME_HDR_LEN16_2,
	LWS_RXPS_04_FRAME_HDR_LEN16_1,
	LWS_RXPS_04_FRAME_HDR_LEN64_8,
	LWS_RXPS_04_FRAME_HDR_LEN64_7,
	LWS_RXPS_04_FRAME_HDR_LEN64_6,
	LWS_RXPS_04_FRAME_HDR_LEN64_5,
	LWS_RXPS_04_FRAME_HDR_LEN64_4,
	LWS_RXPS_04_FRAME_HDR_LEN64_3,
	LWS_RXPS_04_FRAME_HDR_LEN64_2,
	LWS_RXPS_04_FRAME_HDR_LEN64_1,

	LWS_RXPS_07_COLLECT_FRAME_KEY_1,
	LWS_RXPS_07_COLLECT_FRAME_KEY_2,
	LWS_RXPS_07_COLLECT_FRAME_KEY_3,
	LWS_RXPS_07_COLLECT_FRAME_KEY_4,

	LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED
};


enum connection_mode {
	LWS_CONNMODE_HTTP_SERVING,

	LWS_CONNMODE_WS_SERVING,
	LWS_CONNMODE_WS_CLIENT,

	/* transient modes */
	LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY,
	LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE,
	LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY,
	LWS_CONNMODE_WS_CLIENT_WAITING_EXTENSION_CONNECT,
	LWS_CONNMODE_WS_CLIENT_PENDING_CANDIDATE_CHILD,

	/* special internal types */
	LWS_CONNMODE_SERVER_LISTENER,
	LWS_CONNMODE_BROADCAST_PROXY_LISTENER,
	LWS_CONNMODE_BROADCAST_PROXY
};

struct libwebsocket_protocols;
struct libwebsocket;

struct libwebsocket_context {
	struct pollfd *fds;
	struct libwebsocket **lws_lookup; /* fd to wsi */
	int fds_count;
	int max_fds;
	int listen_port;
	char http_proxy_address[256];
	char canonical_hostname[1024];
	unsigned int http_proxy_port;
	unsigned int options;
	unsigned long last_timeout_check_s;

	int fd_random;
	int listen_service_modulo;
	int listen_service_count;
	int listen_service_fd;
	int listen_service_extraseen;

#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_client_ctx;
#endif
	struct libwebsocket_protocols *protocols;
	int count_protocols;
	struct libwebsocket_extension *extensions;

    void *user_space;
};


enum pending_timeout {
	NO_PENDING_TIMEOUT = 0,
	PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
	PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
	PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
	PENDING_TIMEOUT_AWAITING_PING,
	PENDING_TIMEOUT_CLOSE_ACK,
	PENDING_TIMEOUT_AWAITING_EXTENSION_CONNECT_RESPONSE,
	PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
};


/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration; the user can use the pointer with
 * other APIs to get information out of it.
 */

struct libwebsocket {
	const struct libwebsocket_protocols *protocol;
	struct libwebsocket_extension *
				   active_extensions[LWS_MAX_EXTENSIONS_ACTIVE];
	void *active_extensions_user[LWS_MAX_EXTENSIONS_ACTIVE];
	int count_active_extensions;

	enum lws_connection_states state;

	char name_buffer[LWS_MAX_HEADER_NAME_LENGTH];
	int name_buffer_pos;
	int current_alloc_len;
	enum lws_token_indexes parser_state;
	struct lws_tokens utf8_token[WSI_TOKEN_COUNT];
	int ietf_spec_revision;
	char rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING + MAX_USER_RX_BUFFER +
						  LWS_SEND_BUFFER_POST_PADDING];
	int rx_user_buffer_head;
	enum libwebsocket_write_protocol rx_frame_type;
	int protocol_index_for_broadcast_proxy;
	enum pending_timeout pending_timeout;
	unsigned long pending_timeout_limit;

	int sock;
	int position_in_fds_table;
	unsigned char *rxflow_buffer;
	int rxflow_len;
	int rxflow_pos;
	int rxflow_change_to;

	enum lws_rx_parse_state lws_rx_parse_state;
	char extension_data_pending;
	struct libwebsocket *candidate_children_list;
	struct libwebsocket *extension_handles;

	/* 04 protocol specific */

	char key_b64[150];
	unsigned char masking_key_04[20];
	unsigned char frame_masking_nonce_04[4];
	unsigned char frame_mask_04[20];
	unsigned char frame_mask_index;
	size_t rx_packet_length;
	unsigned char opcode;
	unsigned char final;
	unsigned char rsv;

	int pings_vs_pongs;
	unsigned char (*xor_mask)(struct libwebsocket *, unsigned char);
	char all_zero_nonce;

	enum lws_close_status close_reason;

	/* 07 specific */
	char this_frame_masked;

	/* client support */
	char initial_handshake_hash_base64[30];
	enum connection_mode mode;
	char *c_path;
	char *c_host;
	char *c_origin;
	char *c_protocol;
	callback_function *c_callback;

	char *c_address;
	int c_port;


#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
	BIO *client_bio;
	int use_ssl;
#endif

	/* http send file */
	char filepath[PATH_MAX];
	unsigned long filepos;
	unsigned long filelen;

	void *user_space;
};

extern int
libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_parse(struct libwebsocket *wsi, unsigned char c);

extern int
libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);

extern int
libwebsocket_read(struct libwebsocket_context *context,
				struct libwebsocket *wsi,
					       unsigned char *buf, size_t len);

extern int
lws_b64_selftest(void);

extern unsigned char
xor_no_mask(struct libwebsocket *wsi, unsigned char c);

extern unsigned char
xor_mask_04(struct libwebsocket *wsi, unsigned char c);

extern unsigned char
xor_mask_05(struct libwebsocket *wsi, unsigned char c);

extern struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *context, int fd);

extern int
insert_wsi_socket_into_fds(struct libwebsocket_context *context, struct libwebsocket *wsi);

extern void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					 enum pending_timeout reason, int secs);

extern int
lws_issue_raw(struct libwebsocket *wsi, unsigned char *buf, size_t len);


extern void
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				    struct libwebsocket *wsi, unsigned int sec);

extern struct libwebsocket *
__libwebsocket_client_connect_2(struct libwebsocket_context *context,
	struct libwebsocket *wsi);

extern struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context);

extern char *
libwebsockets_generate_client_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi, char *pkt);

extern int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
			      struct libwebsocket *wsi, struct pollfd *pollfd);

extern int
lws_any_extension_handled(struct libwebsocket_context *context,
			  struct libwebsocket *wsi,
			  enum libwebsocket_extension_callback_reasons r,
			  void *v, size_t len);

extern void *
lws_get_extension_user_matching_ext(struct libwebsocket *wsi,
			  struct libwebsocket_extension *ext);

extern int
lws_client_interpret_server_handshake(struct libwebsocket_context *context,
		struct libwebsocket *wsi);

extern int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c);

extern int
lws_issue_raw_ext_access(struct libwebsocket *wsi,
						unsigned char *buf, size_t len);

extern int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi);

extern int
user_callback_handle_rxflow(callback_function, struct libwebsocket_context * context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);

#ifndef LWS_OPENSSL_SUPPORT

unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md);

void
MD5(const unsigned char *input, int ilen, unsigned char *output);

#endif
