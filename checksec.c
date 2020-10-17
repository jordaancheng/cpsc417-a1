#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h> /* Basic Input/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>

#include <pthread.h>

#define BUFFER_SIZE 1024
#define DATE_LEN 128

//https://stackoverflow.com/questions/1352749/multiple-arguments-to-function-called-by-pthread-create
struct arg_struct {
  SSL *ssl;
  SSL_CTX *ctx;
  int server;
};

void print_master_key(SSL* ssl, BIO* outbio) {

  SSL_SESSION * ssl_session = SSL_get_session(ssl);
  unsigned char *dest = malloc(100);
  int sizeof_master = SSL_SESSION_get_master_key(ssl_session, dest, 100);
  BIO_printf(outbio, "Master key:\n  ");
  for (int i=0; i<sizeof_master; i++) {
    BIO_printf(outbio, "%02x", dest[i]);
  }
  free(dest);
  BIO_printf(outbio, "\n\n");
}

void print_supported_ciphers(SSL *ssl, BIO* outbio) {

  STACK_OF(SSL_CIPHER) * supported_ciphers = SSL_get1_supported_ciphers(ssl);
  int num = sk_SSL_CIPHER_num(supported_ciphers);

  BIO_printf(outbio, "Supported cipher suites:\n");
  for (int i = 0; i < num ;i++) {
    const SSL_CIPHER *c = sk_SSL_CIPHER_value(supported_ciphers, i);
    const char * p = SSL_CIPHER_get_name(c);
    BIO_printf(outbio, "  %s\n", p);
  }
  BIO_printf(outbio,"Using cipher suite: %s\n", SSL_get_cipher(ssl));
  BIO_printf(outbio, "\n");
}

void print_server_certificate(SSL* ssl, SSL_CTX* ctx, BIO* outbio) {

  /* Get server's certficiate into X509 structure */
  X509 *cert = SSL_get_peer_certificate(ssl);

  /* Check if server provided a cert
     if not, cert version = NONE & don't print public key */
  if (cert == NULL) {
    BIO_printf(outbio, "Certificate version     : NONE\n");
  }
  else {
    /* Get cert version */
    BIO_printf(outbio, "Certificate version     : %ld\n", X509_get_version(cert)+1);

    /* Verify cert */
    /* Jonatan said you can get verification results from the SSL object itself */
    int result = (int) SSL_get_verify_result(ssl);
    BIO_printf(outbio, "Certificate verification: %s\n", X509_verify_cert_error_string(result));

    /* Get date/time range when cert is valid */
    ASN1_TIME *not_before_time = X509_getm_notBefore(cert);
    ASN1_TIME *not_after_time = X509_getm_notAfter(cert);

    BIO_printf(outbio, "Certificate start time  : ");
    ASN1_TIME_print(outbio, not_before_time);
    BIO_printf(outbio, "\nCertificate end time    : ");
    ASN1_TIME_print(outbio, not_after_time);
    BIO_printf(outbio, "\n\n");

    /* Get cert subject all key-value entries */
    BIO_printf(outbio, "Certificate Subject:\n");
    X509_NAME *cert_subject = X509_NAME_new();
    cert_subject = X509_get_subject_name(cert);
    X509_NAME_print_ex(outbio, cert_subject, 6, XN_FLAG_MULTILINE);
    BIO_printf(outbio, "\n\n");

    /* Get cert issuer all key-value entries */
    BIO_printf(outbio, "Certificate Issuer:\n");
    X509_NAME *cert_issuer = X509_NAME_new();
    cert_issuer = X509_get_issuer_name(cert);
    X509_NAME_print_ex(outbio, cert_issuer, 6, XN_FLAG_MULTILINE);
    BIO_printf(outbio, "\n\n");

    /* Get server public key */
    BIO_printf(outbio, "Server public key:\n");
    EVP_PKEY *public_key = X509_get_pubkey(cert);
    PEM_write_bio_PUBKEY(outbio, public_key);
    BIO_printf(outbio, "\n");

    EVP_PKEY_free(public_key);
  }

  X509_free(cert);
}

void report_and_exit(const char* msg) {
  perror(msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void init_ssl() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

void *read_user_input(void *arg) {
  struct arg_struct *args = arg;
  SSL *ssl = args->ssl;
  SSL_CTX * ctx = args->ctx;
  int server = args->server;
  char buf[BUFFER_SIZE];
  size_t n;
  int res;
  fprintf(stderr, "Type your message: \n");
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    n = strlen(buf);
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    res = SSL_write(ssl, buf, strlen(buf));
    if (res <  0){
      fprintf(stderr, "ERROR: could not Send msg \n"); 
    }
    /* TODO Send message */
  }

  /* TODO EOF in stdin, shutdown the connection */

  fprintf(stderr, "Finished TLS connection with server. Shutting down.\n");
  SSL_CTX_free(ctx);
  SSL_free(ssl);
  close(server);
  exit(0);
  return 0;
}

void *read_ssl_response(void *arg) {
  char buf[1024];
  SSL *ssl = arg;
  while(1) {
    int bytes = SSL_read(ssl, buf, sizeof(buf));
	  if ( bytes > 0 ) {
      buf[bytes] = 0;
      fprintf(stderr,"Received: %s\n", buf);
    }
  }
}

SSL_CTX* initialize_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
    report_and_exit("Error: Unable to create a new SSL context structure.\n");
  }
  return ctx;
}

int establish_socket(const char* hostname, const char* port, BIO* outbio) {

  int sock_fd, error;
  struct addrinfo *result, *res;

  error = getaddrinfo(hostname, port, NULL, &result);
  if (error != 0) {
    BIO_printf(outbio, "Error: getaddrinfo: %s.\n", gai_strerror(error));
    exit(-1);
  }

  for (res = result; res != NULL; res = res->ai_next) {
    /* Create the socket */
    sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd == 1) continue;

    /* If connected, break out of loop */
    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) != -1) break;

    close(sock_fd);
  }

  if (res == NULL) {
    BIO_printf(outbio, "Error: could not connect to host %s on port %s", hostname, port);
  } 

  return sock_fd;
}

void secure_connect(const char* hostname, const char *port) {
  SSL *ssl = NULL;
  SSL_CTX *ctx;
  int server = 0;
  BIO *outbio = NULL;
  outbio = BIO_new_fp(stderr, BIO_NOCLOSE);

  /* TODO Establish SSL context and connection */
  ctx = initialize_context();
  ssl = SSL_new(ctx);

  /* Set default verify paths on the context before connection is established */
  if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
    BIO_printf(outbio, "Error: failed to specify default paths.\n");
  }

  /* Create & establish TCP socket connection */
  server = establish_socket(hostname, port, outbio);

  if (SSL_set_fd(ssl, server) != 1) {
    report_and_exit("Error: failed to set the file descriptor as the input/output facility for the TLS connection.\n");
  }
  if (SSL_connect(ssl) != 1) {
    report_and_exit("Error: Could not initiate a SSL handshake session.\n");
  }

  /* TODO Print stats about connection */
  print_master_key(ssl, outbio);
  print_supported_ciphers(ssl, outbio);
  print_server_certificate(ssl, ctx, outbio);

  /* TODO Receive messages and print them to stdout */
  /* Create thread that will read data from stdin */
  struct arg_struct *args = malloc(sizeof(struct arg_struct));
  args->ssl = ssl;
  args->ctx = ctx;
  pthread_t thread;
  pthread_t thread2;
  pthread_create(&thread, NULL, read_user_input, (void *)args);
  pthread_create(&thread2, NULL, read_ssl_response, ssl);
  pthread_join( thread, NULL);
  pthread_join( thread2, NULL);
  pthread_detach(thread);
  pthread_detach(thread2);

}

int main(int argc, char *argv[]) {
  init_ssl();
  
  const char* hostname;
  const char* port = "443";

  if (argc < 2) {
    fprintf(stderr, "Usage: %s hostname [port]\n", argv[0]);
    return 1;
  }

  hostname = argv[1];
  if (argc > 2)
    port = argv[2];
  
  fprintf(stderr, "Host: %s\nPort: %s\n\n", hostname, port);
  secure_connect(hostname, port);
  
  return 0;
}
