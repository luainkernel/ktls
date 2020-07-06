#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <netinet/tcp.h>
#include "../uapi/tls.h"

#include <gnutls/gnutls.h>

#define MESSAGE "Hello world."

#define PRIORITY                                                               \
	"NONE:+SECURE256:+SHA256:+ECDHE-ECDSA:+AES-256-GCM:+VERS-TLS1.2:+COMP-NULL:+SIGN-ALL"
#define CHECK(x) assert((x) >= 0)

char *ip;
int port;

int main_client(void);

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("usage: ./test ip port\n");
		exit(-1);
	}
	ip = argv[1];
	port = atoi(argv[2]);
	printf("Connect to %s:%i\n", ip, port);

	CHECK(gnutls_global_init());

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
	char buf[256];
	int ret;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, ip, &sa.sin_addr);

	err = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (err || !sock) {
		perror("client socket");
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
		exit(-1);
	}

	gnutls_record_send(session, MESSAGE, strlen(MESSAGE) + 1);
	ret = gnutls_record_recv(session, buf, sizeof(buf));

	printf("recv bytes: %d, %s\n", ret, buf);

	if (strcmp(buf, MESSAGE) == 0)
		printf("OK\n");
	else
		printf("ERROR\n");

	close(sock);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	return 0;
}
