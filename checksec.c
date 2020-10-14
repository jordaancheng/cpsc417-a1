#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

void print_master_key(SSL* ssl, BIO* outbio) {

  SSL_SESSION * ssl_session = SSL_get_session(ssl);
  unsigned char *dest = malloc(100);
  int sizeof_master = SSL_SESSION_get_master_key(ssl_session, dest, 100);
  // fprintf(stderr,"size of master key: %d \n", sizeof_master);
  BIO_printf(outbio, "Master key:\n");

  BIO_printf(outbio, "  ");
  for (int i=0; i<sizeof_master; i++) {
    BIO_printf(outbio, "%02x", dest[i]);
  }
  BIO_printf(outbio, "\n\n");
  
  free(dest);
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
}

void print_server_certificate(SSL* ssl, BIO* outbio) {

  X509 *cert = NULL;
  // get server's certficiate into X509 structure
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    fprintf(stderr, "Error: Could not get a certificate.\n");
  }
  else {
    fprintf(stderr, "Retrieved the server's certificate.\n");
  }

  // TODO: check if server provided a cert
  //       if not: cert version = NONE, don't print public key
  // TODO: get cert version
  // TODO: verify vertf
  // TODO: get date/time range when cert is valid
  // TODO: get cert subject all key-value entries
  // TODO: get cert issuer all key-value entries

  EVP_PKEY *public_key = NULL;
  if ((public_key = X509_get_pubkey(cert)) == NULL) {
    fprintf(stderr, "Error getting public key from certificate.\n");
  }
  if(!PEM_write_bio_PUBKEY(outbio, public_key)) {
    fprintf(stderr, "Error writing public key data in PEM format.\n");
  }
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
  // ERR_load_BIO_strings();
  // ERR_load_crypto_strings();
}

void *read_user_input(void *arg) {
  // SSL *ssl = arg;
  char buf[BUFFER_SIZE];
  size_t n;
  fprintf(stderr, "\nType your message: ");
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    fprintf(stderr, "\nType your message: ");
    n = strlen(buf);
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    
    /* TODO Send message */
  }

  /* TODO EOF in stdin, shutdown the connection */
  
  return 0;
}

/*  Helper function: use this if you want to extract 
    IPv4 or IPv6 address from a sockaddr struct
    Source: https://stackoverflow.com/questions/1276294/getting-ipv4-address-from-a-sockaddr-structure */
char* get_address_from_sockaddr_struct(struct addrinfo *res) {
  char *s = NULL;
  switch(res->ai_addr->sa_family) {
    case AF_INET: {
      struct sockaddr_in *addr_in = (struct sockaddr_in *) res->ai_addr;
      s = malloc(INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) res->ai_addr;
      s = malloc(INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(addr_in6->sin6_addr), s, INET_ADDRSTRLEN);
      break;
    }
    default:
      break;
  }
  return s;
}

SSL_CTX* initialize_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
    fprintf(stderr, "Error: Unable to create a new SSL context structure.\n");
    abort();
  }
  return ctx;
}

int establish_socket(const char* hostname, const char* port) {
  int sock_fd, error;
  struct addrinfo *result, *res;

  error = getaddrinfo(hostname, port, NULL, &result);
  if (error != 0) {
    fprintf(stderr, "Error: Hostname %s in getaddrinfo: %s.\n", hostname, gai_strerror(error));
    abort();
  }

  for (res = result; res != NULL; res = res->ai_next) {

    char* ip_address = get_address_from_sockaddr_struct(res);
    printf("ip_addres = %s\n", ip_address);

    // printf("res->ai_family = %d\n", res->ai_family);
    // printf("res->ai_socktype = %d\n", res->ai_socktype);
    // printf("res->ai_protocol = %d\n", res->ai_protocol);

    // Create the socket
    sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    // printf("sock_fd = %d\n\n", sock_fd);
    if (sock_fd == 1) continue;

    // If connected, break out of loop
    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) != -1) break;
    close(sock_fd);
  }

  // Success
  if (res == NULL) {
    fprintf(stderr, "Error: could not connect to host %s on port %s", hostname, port);
  } 

  return sock_fd;
}

void secure_connect(const char* hostname, const char *port) {
  // char buf[BUFFER_SIZE];

  SSL *ssl = NULL;
  SSL_CTX *ctx;

  /* Commented out code will be used later */

  int server = 0;
  // BIO *inbio = NULL;
  BIO *outbio = NULL;
  // X509_NAME *certname = NULL;

  // inbio = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stderr, BIO_NOCLOSE);

  /* TODO Establish SSL context and connection */
  
  // create & initialize a new SSL context
  ctx = initialize_context();
  // create new SSL connection state object
  ssl = SSL_new(ctx);

  // create & establish TCP socket connection
  server = establish_socket(hostname, port);
  if (server != 0) {
    fprintf(stderr, "Successfully made TCP connection to %s on %s.\n", hostname, port);
  }

  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) != 1) {
    fprintf(stderr, "Error: Could not initiate a SSL handshake session.\n");
    exit(1);
  } else {
    fprintf(stderr, "Initiaited a SSL handshake session.\n");
  }

  /* TODO Print stats about connection */
  print_master_key(ssl, outbio);
  print_supported_ciphers(ssl, outbio);
  print_server_certificate(ssl, outbio);

  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, ssl);
  pthread_join( thread, NULL);
  //pthread_detach(thread);
  
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
