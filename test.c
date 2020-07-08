#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/tcp.h>
#include "uapi/tls.h"

#include <gnutls/gnutls.h>

#define PRIORITY                                                               \
	"NONE:+SECURE256:+SHA256:+ECDHE-ECDSA:+AES-256-GCM:+VERS-TLS1.2:+COMP-NULL:+SIGN-ALL"
#define CHECK(x) assert((x) >= 0)

int port;
pthread_t server_thread;

void *main_server(void *);
int main_client(void);

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: ./test port\n");
		exit(-1);
	}
	port = atoi(argv[1]);
	printf("Serving port %i\n", port);

	CHECK(gnutls_global_init());

	int rc = pthread_create(&server_thread, NULL, main_server, NULL);
	if (rc) {
		printf("Error creating server %i\n", rc);
		exit(-1);
	}
	sleep(1); /* wait for server start */

	main_client();

	gnutls_global_deinit();
	return 0;
}

int main_client()
{
	int err;
	int sock;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	struct sockaddr_in sa;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, "localhost", &sa.sin_addr);

	err = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (err || !sock) {
		perror("client socket");
		exit(-1);
	}

	if (setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		perror("setsockopt[tls]");
		exit(-1);
	}

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_certificate_allocate_credentials(&x509_cred);
	CHECK(gnutls_certificate_set_x509_system_trust(x509_cred));
	gnutls_priority_set_direct(session, PRIORITY, NULL);
	CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				     x509_cred));
	gnutls_transport_set_int(session, sock);
	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		err = gnutls_handshake(session);
	} while (err < 0 && gnutls_error_is_fatal(err) == 0);
	if (err) {
		gnutls_perror(err);
		goto end;
	}

	gnutls_datum_t mac_key;
	gnutls_datum_t iv_read;
	gnutls_datum_t cipher_key_read;
	unsigned char seq_number_read[8];
	err = gnutls_record_get_state(session, 1, &mac_key, &iv_read,
				      &cipher_key_read, seq_number_read);
	if (err) {
		gnutls_perror(err);
		goto end;
	}

	struct tls12_crypto_info_aes_gcm_256 crypto_info;
	crypto_info.info.version = TLS_1_2_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
	memcpy(crypto_info.iv, iv_read.data + 4,
	       TLS_CIPHER_AES_GCM_256_IV_SIZE);
	memcpy(crypto_info.rec_seq, seq_number_read,
	       TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
	memcpy(crypto_info.key, cipher_key_read.data,
	       TLS_CIPHER_AES_GCM_256_KEY_SIZE);
	memcpy(crypto_info.salt, iv_read.data,
	       TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	if (setsockopt(sock, SOL_TLS, TLS_RX, &crypto_info,
		       sizeof(crypto_info))) {
		perror("setsockopt[tls]");
		exit(-1);
	}

	char *init_script = "print('hello world')";
	char *recv_script = "print('hello world in recv')";
	struct tls_lua_info lua_info;
	lua_info.init = init_script;
	lua_info.init_len = strlen(init_script) + 1;
	lua_info.recv = recv_script;
	lua_info.recv_len = strlen(recv_script) + 1;
	if (setsockopt(sock, SOL_TLS, TLS_LUA, &lua_info, sizeof(lua_info))) {
		perror("setsockopt[lua]");
		exit(-1);
	}

	char buf[256];
	int ret = recv(sock, buf, sizeof(buf), 0);
	// int ret = gnutls_record_recv(session, buf, sizeof(buf));
	printf("recv: %d %s\n", ret, buf);

	gnutls_bye(session, GNUTLS_SHUT_WR);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
end:
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return 0;
}

void *main_server(void *unused)
{
	int err;
	int sock;
	int client;
	char buf[] = "test_msg";
	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_cred;
	struct sockaddr_in sa;

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_key_file(
		x509_cred, "./test_certs/cert.pem",
		"./test_certs/key.pem", GNUTLS_X509_FMT_PEM));

	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port);
	err = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (err || !sock) {
		perror("server socket");
		exit(-1);
	}
	err = listen(sock, 10);
	if (err || !sock) {
		perror("server listen");
		exit(-1);
	}

	struct sockaddr_in addr;
	unsigned int len = sizeof(addr);
	while (1) {
		gnutls_init(&session, GNUTLS_SERVER);
		gnutls_priority_set_direct(session, PRIORITY, NULL);
		CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
					     x509_cred));
		gnutls_certificate_server_set_request(session,
						      GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(session,
					     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		client = accept(sock, (struct sockaddr *)&addr, &len);
		gnutls_transport_set_int(session, client);

		do {
			err = gnutls_handshake(session);
		} while (err < 0 && gnutls_error_is_fatal(err) == 0);
		if (err) {
			gnutls_perror(err);
			exit(-1);
		}

		gnutls_record_send(session, buf, sizeof(buf));

		gnutls_bye(session, GNUTLS_SHUT_WR);
		close(client);
		gnutls_deinit(session);
	}
	gnutls_certificate_free_credentials(x509_cred);
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return NULL;
}
