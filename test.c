#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/tcp.h>
#include "uapi/tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/modes.h>
#include <openssl/aes.h>

int port;

/* OpenSSL define */
/* Opaque OpenSSL structures to fetch keys */
#define u64 uint64_t
#define u32 uint32_t
#define u8 uint8_t

typedef struct {
	u64 hi, lo;
} u128;

typedef struct {
	/* Following 6 names follow names in GCM specification */
	union {
		u64 u[2];
		u32 d[4];
		u8 c[16];
		size_t t[16 / sizeof(size_t)];
	} Yi, EKi, EK0, len, Xi, H;
	/*
   * Relative position of Xi, H and pre-computed Htable is used in some
   * assembler modules, i.e. don't change the order!
   */
#if TABLE_BITS == 8
	u128 Htable[256];
#else
	u128 Htable[16];
	void (*gmult)(u64 Xi[2], const u128 Htable[16]);
	void (*ghash)(u64 Xi[2], const u128 Htable[16], const u8 *inp,
		      size_t len);
#endif
	unsigned int mres, ares;
	block128_f block;
	void *key;
} gcm128_context_alias;

typedef struct {
	union {
		double align;
		AES_KEY ks;
	} ks; /* AES key schedule to use */
	int key_set; /* Set if key initialised */
	int iv_set; /* Set if an iv is set */
	gcm128_context_alias gcm;
	unsigned char *iv; /* Temporary IV store */
	int ivlen; /* IV length */
	int taglen;
	int iv_gen; /* It is OK to generate IVs */
	int tls_aad_len; /* TLS AAD length */
	ctr128_f ctr;
} EVP_AES_GCM_CTX;
/* End OpenSSL define */

pthread_t server_thread;

void *main_server(void *);
int main_tls_client(void);

int main(int argv, char *argc[])
{
	if (argv != 2) {
		printf("usage: ./test port\n");
		exit(-1);
	}
	port = atoi(argc[1]);
	printf("Serving port %i\n", port);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings(); /* load all error messages */

	int rc = pthread_create(&server_thread, NULL, main_server, NULL);
	if (rc) {
		printf("Error creating server %i\n", rc);
		exit(-1);
	}
	sleep(1);

	main_tls_client();
	return 0;
}

int create_socket()
{
	int sockfd;
	struct sockaddr_in addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&(addr), 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *)&addr,
		    sizeof(struct sockaddr_in)) == -1) {
		perror("Connect");
		exit(-1);
	}

	char *init_script = "print('hello world')";
	char *recv_script = "print('hello world in recv')";
	if (setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		perror("setsockopt[ulp]");
		exit(-1);
	}
	struct tls_lua_info lua_info;
	lua_info.init = init_script;
	lua_info.init_len = strlen(init_script) + 1;
	lua_info.recv = recv_script;
	lua_info.recv_len = strlen(recv_script) + 1;
	if (setsockopt(sockfd, SOL_TLS, TLS_LUA, &lua_info, sizeof(lua_info)) ==
	    -1) {
		perror("setsockopt[lua]");
		exit(EXIT_FAILURE);
	}
	return sockfd;
}

int main_tls_client()
{
	SSL_CTX *ctx;
	SSL *ssl;
	int server = 0;

	if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		printf("Unable to create a new SSL context structure.\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

	ssl = SSL_new(ctx);
	server = create_socket();
	SSL_set_fd(ssl, server);
	if (SSL_connect(ssl) != 1) {
		printf("Error: Could not build a SSL session\n");
		exit(-1);
	}

	// EVP_CIPHER_CTX *writeCtx = ssl->enc_write_ctx;
	EVP_CIPHER_CTX *readCtx = ssl->enc_read_ctx;

	// EVP_AES_GCM_CTX *gcmWrite = (EVP_AES_GCM_CTX *)(writeCtx->cipher_data);
	EVP_AES_GCM_CTX *gcmRead = (EVP_AES_GCM_CTX *)(readCtx->cipher_data);

	// unsigned char *writeSeqNum = ssl->s3->write_sequence;
	unsigned char *readSeqNum = ssl->s3->read_sequence;

	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	crypto_info.info.version = TLS_1_2_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memcpy(crypto_info.iv, gcmRead->iv + EVP_GCM_TLS_FIXED_IV_LEN,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(crypto_info.rec_seq, readSeqNum,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(crypto_info.key, gcmRead->gcm.key,
	       TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(crypto_info.salt, gcmRead->iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	if (setsockopt(server, SOL_TLS, TLS_RX, &crypto_info,
		       sizeof(crypto_info))) {
		perror("setsockopt[tls]");
		exit(-1);
	}

	char buf[256];
	// int ret=SSL_read(ssl,buf,256);
	int ret = recv(SSL_get_fd(ssl), buf, 256, 0);
	printf("recv: %d %s\n", ret, buf);

	SSL_free(ssl);
	close(server);
	SSL_CTX_free(ctx);
	return 0;
}

int OpenListener(int port)
{
	int sockfd;
	struct sockaddr_in addr;

	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("can't bind port");
		abort();
	}
	if (listen(sockfd, 10) != 0) {
		perror("Can't configure listening port");
		abort();
	}
	return sockfd;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <=
	    0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,
			"Private key does not match the public certificate\n");
		abort();
	}
}

void *main_server(void *unused)
{
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	int client;
	char buf[255] = "test_msg";

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	LoadCertificates(ctx, "./test_certs/ca.crt", "./test_certs/ca.pem");
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

	/* create server socket */
	server = OpenListener(port);

	struct sockaddr_in addr;
	unsigned int len = sizeof(addr);
	while (1) {
		client = accept(server, (struct sockaddr *)&addr, &len);
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) == -1) {
			ERR_print_errors_fp(stderr);
		} else {
			sleep(1); // openssl bug, data race
			SSL_write(ssl, buf, strlen(buf) + 1);
		}

		SSL_free(ssl);
		close(client);
	}
	close(server);
	SSL_CTX_free(ctx);

	return NULL;
}
