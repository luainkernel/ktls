#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include "map.h"
#include "../uapi/tls.h"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <gnutls/gnutls.h>

#define KTLS /* comment this for not using kTLS */
// #define USERLUA /* comment this for not using user lua */

#define HTTP_404                                                               \
	"HTTP/1.1 404 Not Found\r\n"                                           \
	"Connection: close"
#define HTTP_200                                                               \
	"HTTP/1.1 200 OK\r\n"                                                  \
	"Content-Length: %d\r\n"                                               \
	"Content-Type: text/plain\r\n"                                         \
	"Connection: close\r\n"                                                \
	"\r\n"

#define PRIORITY                                                               \
	"NONE:"                                                                \
	"+SECURE256:+SHA256:"                                                  \
	"+ECDHE-ECDSA:+AES-256-GCM:"                                           \
	"+VERS-TLS1.2:+COMP-NULL:+SIGN-ALL"
#define CHECK(x) assert((x) >= 0)

int main_server(int port, char *www_path, int cork);
void cache_replies(map_str_t *cache, char *path);
void set_luafile(int client, char *path, lua_State *L);
int tls_send(gnutls_session_t session, int client, void *buf, size_t size);
int tls_recv(gnutls_session_t session, int client, void *buf, size_t size);
int handle_request(gnutls_session_t session, int client, map_str_t *cache,
		   char *filepath);
char *read_file(char *path);

int main(int argc, char *argv[])
{
	int opt;
	int port;
	int cork;
	char *path;

	cork = 0;
	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c':
			cork = 1;
			break;
		default:
			printf("usage: ./test [-c] port path\n");
			return 0;
		}
	}
	port = atoi(argv[optind]);
	path = argv[optind + 1];
	printf("Serving port %i\n", port);

	CHECK(gnutls_global_init());

	main_server(port, path, cork);

	gnutls_global_deinit();
	return 0;
}

void cache_replies(map_str_t *cache, char *path)
{
	DIR *dir;
	struct dirent *dentry;
	struct stat st;
	char *buf_path, *buf_data;
	if (dir = opendir(path)) {
		while ((dentry = readdir(dir)) != NULL &&
		       dentry->d_type == DT_REG) {
			if (asprintf(&buf_path, "%s/%s", path, dentry->d_name) <
			    0) {
				perror("cache asprintf path");
				exit(-1);
			}
			stat(buf_path, &st);
			if (asprintf(&buf_data, HTTP_200, (int)st.st_size) <
			    0) {
				perror("cache asprintf data");
				exit(-1);
			}
			map_set(cache, buf_path, buf_data);
		}
		closedir(dir);
	}
}

void set_luafile(int client, char *path, lua_State *L)
{
	DIR *dir;
	struct dirent *dentry;
	char *script;
	if (dir = opendir(path)) {
		while ((dentry = readdir(dir)) != NULL &&
		       dentry->d_type == DT_REG) {
			if (asprintf(&script, "files['%s'] = true",
				     dentry->d_name) < 0) {
				perror("script asprintf");
				exit(-1);
			}
			if (!L) {
				if (setsockopt(client, SOL_TLS,
					       TLS_LUA_LOADSCRIPT, script,
					       strlen(script) + 1) == -1) {
					perror("setsockopt[lua]");
					exit(-1);
				}
			} else {
				luaL_dostring(L, script);
			}
		}
		closedir(dir);
	}
}

char *read_file(char *path)
{
	FILE *fp;
	char *ret;
	long len;
	fp = fopen(path, "r");
	if (!fp) {
		perror("read file");
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	ret = (char *)malloc((len + 1) * sizeof(char));
	rewind(fp);
	len = fread(ret, 1, len, fp);
	ret[len] = '\0';
	fclose(fp);
	return ret;
}

int tls_send(gnutls_session_t session, int client, void *buf, size_t size)
{
#ifdef KTLS
	return send(client, buf, size, 0);
#else
	return gnutls_record_send(session, buf, size);
#endif
}

int tls_recv(gnutls_session_t session, int client, void *buf, size_t size)
{
#ifdef KTLS
	return recv(client, buf, size, 0);
#else
	return gnutls_record_recv(session, buf, size);
#endif
}

int handle_request(gnutls_session_t session, int client, map_str_t *cache,
		   char *file_path)
{
	char *http_data;
	char *http_header;
	int fd;
	struct stat file_stat;
	int err;

	fd = open(file_path, O_RDONLY);
	if (fd == -1) {
		if (tls_send(session, client, HTTP_404, strlen(HTTP_404)) ==
		    -1) {
			perror("404 send");
			close(fd);
			return -1;
		};
	} else {
		if (fstat(fd, &file_stat)) {
			perror("fstat");
			close(fd);
			return -1;
		}
		char **header = map_get(cache, file_path);
		if (header) {
			if (tls_send(session, client, *header,
				     strlen(*header)) == -1) {
				perror("send");
				close(fd);
				return -1;
			}
		} else {
			if (asprintf(&http_header, HTTP_200,
				     (int)file_stat.st_size) < 0) {
				perror("http_header asprintf");
				close(fd);
				return -1;
			}
			if (tls_send(session, client, http_header,
				     strlen(http_header)) == -1) {
				perror("send");
				close(fd);
				return -1;
			}
			map_set(cache, file_path, http_header);
			// http_header shouldn't free
		}

#ifdef KTLS
		if (sendfile(client, fd, NULL, file_stat.st_size) == -1) {
			perror("sendfile");
			close(fd);
			return -1;
		}
#else
		http_data = (char *)malloc(1024 * 8);
		while ((err = read(fd, http_data, 1024 * 8)) > 0) {
			if (gnutls_record_send(session, http_data, err) == -1) {
				perror("sendfile");
				free(http_data);
				close(fd);
				return -1;
			}
		}
		free(http_data);
#endif
		close(fd);
	}
	return 0;
}

int init_sock(int port)
{
	int sock;
	int one = 1;
	int err;
	struct sockaddr_in sa;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		perror("setsockopt[reuseaddr]");
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port);
	err = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (err || !sock) {
		perror("server bind");
		return -1;
	}
	err = listen(sock, 10);
	if (err || !sock) {
		perror("server listen");
		return -1;
	}
	return sock;
}

int main_server(int port, char *www_path, int cork)
{
	int err;
	int sock;
	int client;
	int one = 1;
	struct sockaddr_in addr;
	unsigned int addrlen;

	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_cred;

	char *buf;
	int offset;
	int http_code;
	unsigned int intlen;
	char *http_file;
	char path[4096];
	char method[4096];
	int maxpath;

	char *lua_hook;
	lua_State *L;
	map_str_t cache;
	int pagesize;

	/* cache reply */
	map_init(&cache);
	cache_replies(&cache, www_path);

	addrlen = sizeof(addr);
	intlen = sizeof(int);
	pagesize = getpagesize();
	maxpath = 4096;

	lua_hook = read_file("hook.lua");
#ifdef USERLUA
	L = luaL_newstate();
	if (!L) {
		perror("no memory");
		exit(-1);
	}
	luaL_openlibs(L);
	if (luaL_dostring(L, lua_hook)) {
		perror(lua_tostring(L, -1));
		exit(-1);
	}
	set_luafile(0, www_path, L);
#endif

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_key_file(
		x509_cred, "../test_certs/cert.pem", "../test_certs/key.pem",
		GNUTLS_X509_FMT_PEM));

	sock = init_sock(port);
	if (sock == -1)
		exit(-1);

	while (1) {
		offset = 0;
		gnutls_init(&session, GNUTLS_SERVER);
		gnutls_priority_set_direct(session, PRIORITY, NULL);
		CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
					     x509_cred));
		gnutls_certificate_server_set_request(session,
						      GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(session,
					     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		client = accept(sock, (struct sockaddr *)&addr, &addrlen);
		gnutls_transport_set_int(session, client);

#ifdef KTLS
		if (setsockopt(client, SOL_TCP, TCP_ULP, "tls",
			       sizeof("tls"))) {
			perror("setsockopt[tls]");
			exit(-1);
		}
#endif
		if (cork)
			if (setsockopt(client, SOL_TCP, TCP_CORK, &one,
				       sizeof(one))) {
				perror("setsockopt[cork]");
				exit(-1);
			}

		do {
			err = gnutls_handshake(session);
		} while (err < 0 && gnutls_error_is_fatal(err) == 0);
		if (err) {
			gnutls_perror(err);
			exit(-1);
		}

#ifdef KTLS
		gnutls_datum_t mac_key;
		gnutls_datum_t iv;
		gnutls_datum_t cipher_key;
		unsigned char seq_number[8];
		err = gnutls_record_get_state(session, 1, &mac_key, &iv,
					      &cipher_key, seq_number);
		if (err) {
			gnutls_perror(err);
			exit(-1);
		}

		struct tls12_crypto_info_aes_gcm_256 crypto_info;
		crypto_info.info.version = TLS_1_2_VERSION;
		crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(crypto_info.iv, iv.data + 4,
		       TLS_CIPHER_AES_GCM_256_IV_SIZE);
		memcpy(crypto_info.rec_seq, seq_number,
		       TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
		memcpy(crypto_info.key, cipher_key.data,
		       TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		memcpy(crypto_info.salt, iv.data,
		       TLS_CIPHER_AES_GCM_256_SALT_SIZE);
		if (setsockopt(client, SOL_TLS, TLS_RX, &crypto_info,
			       sizeof(crypto_info))) {
			perror("setsockopt[tls]");
			exit(-1);
		}

		err = gnutls_record_get_state(session, 0, &mac_key, &iv,
					      &cipher_key, seq_number);
		if (err) {
			gnutls_perror(err);
			exit(-1);
		}

		memcpy(crypto_info.iv, iv.data + 4,
		       TLS_CIPHER_AES_GCM_256_IV_SIZE);
		memcpy(crypto_info.rec_seq, seq_number,
		       TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
		memcpy(crypto_info.key, cipher_key.data,
		       TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		memcpy(crypto_info.salt, iv.data,
		       TLS_CIPHER_AES_GCM_256_SALT_SIZE);
		if (setsockopt(client, SOL_TLS, TLS_TX, &crypto_info,
			       sizeof(crypto_info))) {
			perror("setsockopt[tls]");
			exit(-1);
		}

#ifndef USERLUA
		if (setsockopt(client, SOL_TLS, TLS_LUA_LOADSCRIPT, lua_hook,
			       strlen(lua_hook) + 1) == -1) {
			perror("setsockopt[lua]");
			exit(-1);
		}
		if (setsockopt(client, SOL_TLS, TLS_LUA_RECVENTRY, "recv",
			       strlen("recv") + 1) == -1) {
			perror("setsockopt[lua]");
			exit(-1);
		}
		set_luafile(client, www_path, NULL);
#endif
#endif

		buf = (char *)malloc(pagesize);
		while ((err = tls_recv(session, client, buf + offset,
				       pagesize - (offset % pagesize))) != 0) {
#ifdef KTLS
			if (err == -1 && errno == EAGAIN) {
				getsockopt(client, SOL_TLS, TLS_LUA_ERRNO, &err,
					   &intlen);
				if (err == TLS_LUA_RECVERR) {
					printf("recv lua err\n");
					goto end;
				}
#ifndef USERLUA
				else {
					http_file = (char *)malloc(maxpath);
					getsockopt(client, SOL_TLS,
						   TLS_LUA_CODE, &http_code,
						   &intlen);
					getsockopt(client, SOL_TLS,
						   TLS_LUA_FILE, http_file,
						   &maxpath);
					if (handle_request(session, client,
							   &cache,
							   http_file) != 0)
						goto end;
					break;
				}
#endif
			} else if (err == -1) {
				perror("recv");
				goto end;
			}
#else
			if (err == -1) {
				perror("gnutls_record_recv");
				goto end;
			}
#endif
			else {
				offset += err;
				if (buf[offset - 4] == '\r' &&
				    buf[offset - 3] == '\n' &&
				    buf[offset - 2] == '\r' &&
				    buf[offset - 1] == '\n')
					break;
				if (offset % pagesize == 0)
					buf = (char *)realloc(
						buf, offset + pagesize);
			}
		}

#ifdef USERLUA
		lua_getglobal(L, "recv");
		lua_pushstring(L, www_path);
		lua_pushlstring(L, buf, offset);
		if (lua_pcall(L, 2, 2, 0)) {
			perror(lua_tostring(L, -1));
			goto end;
		} else {
			if (!lua_isinteger(L, -2) || !lua_isstring(L, -1)) {
				perror("recv hook should return 1 int and 1 string");
				goto end;
			} else {
				http_code = lua_tointeger(L, -2);
				http_file = lua_tostring(L, -1);
				lua_pop(L, 2);
				if (http_code == 0) {
					perror("unknown");
					goto end;
				}
			}
		}
		handle_request(session, client, &cache, http_file);
#else
#ifndef KTLS
		sscanf(buf, "%s %s", method, path);
		if (asprintf(&http_file, "%s%s", www_path, path) < 0) {
			perror("real path asprintf");
			goto end;
		}
		handle_request(session, client, &cache, http_file);
#endif
#endif

	end:
#ifndef USERLUA
		free(http_file);
#endif
		close(client);
		gnutls_deinit(session);
		free(buf);
	}
	gnutls_certificate_free_credentials(x509_cred);
	shutdown(sock, SHUT_RDWR);
	close(sock);
	free(lua_hook);
	map_deinit(&cache);
	return 0;
}
