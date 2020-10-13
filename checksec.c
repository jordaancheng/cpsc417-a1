#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bio.h> /* Basic Input/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#include <pthread.h>

#define BUFFER_SIZE 1024
#define DATE_LEN 128


void report_and_exit(const char* msg) {
  perror(msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void init_ssl() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  // ERR_load_BIO_strings();
  // ERR_load_crypto_strings();
}

void *read_user_input(void *arg) {
  // SSL *ssl = arg;
  char buf[BUFFER_SIZE];
  size_t n;
  fprintf(stderr, "\nType your message:");
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    fprintf(stderr, "\nType your message:");
    n = strlen(buf);
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    
    /* TODO Send message */
  }

  /* TODO EOF in stdin, shutdown the connection */
  
  return 0;
}

SSL_CTX* initialize_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
    // ERR_print_errors_fp(stderr);
    fprintf(stderr, "Error with context\n");
    abort();
  }
  return ctx;
}

void secure_connect(const char* hostname, const char *port) {
  // char buf[BUFFER_SIZE];

  SSL *ssl = NULL;
  SSL_CTX *ctx;

  /* Commented out code will be used later */

  // int server = 0;
  // BIO *inbio = NULL;
  // BIO *outbio = NULL;
  // X509 *cert = NULL;
  // X509_NAME *certname = NULL;

  // inbio = BIO_new(BIO_s_file());
  // outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* TODO Establish SSL context and connection */
  ctx = initialize_context();
  ssl = SSL_new(ctx);

  // server = create_socket(hostname, outbio);
  // if (server != 0) {
  //   BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", hostname);
  // }

  // SSL_set_fd(ssl, server);

  // if (SSL_connect(ssl) != 1) {
  //   BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", hostname);
  // } else {
  //   BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", hostname);
  // }

  /* TODO Print stats about connection */
  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, ssl);
  pthread_join( thread, NULL);
  //pthread_detach(thread);
  
  fprintf(stderr, "\nType your message:\n\n");

  /* TODO Receive messages and print them to stdout */
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
