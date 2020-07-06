#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <netinet/tcp.h>
#include <errno.h>
#include "../uapi/tls.h"

#include <gnutls/gnutls.h>

#define KTLS // comment this for not using kTLS

#define PRIORITY                                                               \
	"NONE:+SECURE256:+SHA256:+ECDHE-ECDSA:+AES-256-GCM:+VERS-TLS1.2:+COMP-NULL:+SIGN-ALL"
#define CHECK(x) assert((x) >= 0)

int port;

int main_server(void);

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: ./test port\n");
		exit(-1);
	}
	port = atoi(argv[1]);
	printf("Serving port %i\n", port);

	CHECK(gnutls_global_init());

	main_server();

	gnutls_global_deinit();
	return 0;
}

int main_server(void)
{
	int err;
	int sock;
	int client;
	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_cred;
	struct sockaddr_in sa;
	struct sockaddr_in addr;
	char buf[256];
	unsigned int len;
	FILE *fp;
	char *fdata;
	long flen;
	int intlen;

	len = sizeof(addr);
	intlen = sizeof(int);

	fp = fopen("hook.lua", "r");
	if (!fp) {
		perror("lua file");
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	flen = ftell(fp);
	fdata = (char *)malloc((flen + 1) * sizeof(char));
	rewind(fp);
	flen = fread(fdata, 1, flen, fp);
	fdata[flen] = '\0';
	fclose(fp);

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_key_file(
		x509_cred, "../test_certs/cert.pem", "../test_certs/key.pem",
		GNUTLS_X509_FMT_PEM));

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

#ifdef KTLS
		if (setsockopt(client, SOL_TCP, TCP_ULP, "tls",
			       sizeof("tls"))) {
			perror("setsockopt[tls]");
			exit(-1);
		}
#endif

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

		if (setsockopt(client, SOL_TLS, TLS_LUA_LOADSCRIPT, fdata,
			       strlen(fdata) + 1) == -1) {
			perror("setsockopt[lua]");
			exit(-1);
		}
		if (setsockopt(client, SOL_TLS, TLS_LUA_RECVENTRY, "recv",
			       strlen("recv") + 1) == -1) {
			perror("setsockopt[lua]");
			exit(-1);
		}
#endif

#ifdef KTLS
		err = recv(client, buf, sizeof(buf), 0);
		if (err == -1 && errno == EAGAIN) {
			int err;
			getsockopt(client, SOL_TLS, TLS_LUA_ERRNO, &err,
				   &intlen);
			if (err == TLS_LUA_RECVERR) {
				printf("recv lua err\n");
			}
		}
#else
		gnutls_record_recv(session, buf, sizeof(buf));
#endif
		gnutls_record_send(session, buf, strlen(buf) + 1);

		gnutls_bye(session, GNUTLS_SHUT_WR);
		close(client);
		gnutls_deinit(session);
	}
	gnutls_certificate_free_credentials(x509_cred);
	shutdown(sock, SHUT_RDWR);
	close(sock);
	free(fdata);
	return 0;
}
