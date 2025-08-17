#ifndef IOSTREAM_SSL_TEST_H
#define IOSTREAM_SSL_TEST_H

struct ssl_iostream_settings;

void ssl_iostream_test_settings_server(struct ssl_iostream_settings *test_set);
void ssl_iostream_test_settings_client(struct ssl_iostream_settings *test_set);

void iostream_ssl_test_cert_callback(struct ssl_iostream *ssl_io,
				     void *context);
#endif
