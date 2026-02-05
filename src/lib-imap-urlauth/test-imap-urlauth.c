/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-master.h"
#include "mail-storage.h"
#include "imap-url.h"
#include "mail-user.h"
#include "imap-urlauth-private.h"
#include "imap-urlauth-fetch.h"
#include "imap-urlauth-backend.h"
#include "imap-urlauth-connection.h"
#include "imap-msgpart-url.h"
#include "test-common.h"
#include <time.h>

/* Mocks */
int imap_msgpart_url_create(struct mail_user *user ATTR_UNUSED,
			    const struct imap_url *url ATTR_UNUSED,
			    struct imap_msgpart_url **mpurl_r,
			    const char **error_r ATTR_UNUSED)
{
	*mpurl_r = (struct imap_msgpart_url *)"mock-mpurl";
	return 0;
}
void imap_msgpart_url_free(struct imap_msgpart_url **mpurl ATTR_UNUSED)
{
}
int imap_msgpart_url_verify(struct imap_msgpart_url *mpurl ATTR_UNUSED,
			    const char **error_r ATTR_UNUSED)
{
	return 1;
}
struct mailbox *imap_msgpart_url_get_mailbox(struct imap_msgpart_url *mpurl ATTR_UNUSED)
{
	return (struct mailbox *)"mock-mailbox";
}
int imap_msgpart_url_open_mailbox(struct imap_msgpart_url *mpurl ATTR_UNUSED,
				  struct mailbox **box_r,
				  enum mail_error *error_code_r ATTR_UNUSED,
				  const char **error_r ATTR_UNUSED)
{
	*box_r = (struct mailbox *)"mock-mailbox";
	return 1;
}
int imap_urlauth_backend_get_mailbox_key(struct mailbox *box ATTR_UNUSED,
					 bool create ATTR_UNUSED,
					 unsigned char key_r[IMAP_URLAUTH_KEY_LEN],
					 const char **client_error_r ATTR_UNUSED,
					 enum mail_error *error_code_r ATTR_UNUSED)
{
	memset(key_r, 0, IMAP_URLAUTH_KEY_LEN);
	return 1;
}
int imap_urlauth_backend_reset_mailbox_key(struct mailbox *box ATTR_UNUSED)
{
	return 0;
}
int imap_urlauth_backend_reset_all_keys(struct mail_user *user ATTR_UNUSED)
{
	return 0;
}
int auth_master_user_lookup(struct auth_master_connection *conn ATTR_UNUSED,
			    const char *user ATTR_UNUSED,
			    const struct auth_user_info *info ATTR_UNUSED,
			    pool_t pool ATTR_UNUSED,
			    const char **username_r ATTR_UNUSED,
			    const char *const **fields_r ATTR_UNUSED)
{
	return 0;
}
struct auth_master_connection *mail_user_auth_master_conn = NULL;

struct imap_urlauth_connection *
imap_urlauth_connection_init(const char *path ATTR_UNUSED,
			     const char *service ATTR_UNUSED,
			     struct mail_user *user ATTR_UNUSED,
			     const char *session_id ATTR_UNUSED,
			     unsigned int idle_timeout_msecs ATTR_UNUSED)
{
	return (struct imap_urlauth_connection *)"mock-conn";
}
void imap_urlauth_connection_deinit(struct imap_urlauth_connection **conn)
{
	*conn = NULL;
}

static void test_imap_urlauth_init_deinit(void)
{
	struct imap_urlauth_config config = {
		.url_host = "localhost",
		.url_port = 143,
		.access_user = "user",
		.access_service = "imap",
		.access_anonymous = FALSE
	};
	struct imap_urlauth_context *uctx;

	test_begin("imap_urlauth_init() and deinit()");

	uctx = imap_urlauth_init(NULL, &config);
	test_out("imap_urlauth_init(basic)", uctx != NULL);
	if (uctx != NULL) {
		test_out("uctx->url_host", strcmp(uctx->url_host, "localhost") == 0);
		test_out("uctx->url_port", uctx->url_port == 143);
		test_out("uctx->access_user", strcmp(uctx->access_user, "user") == 0);
		test_out("uctx->access_service", strcmp(uctx->access_service, "imap") == 0);
		test_out("uctx->access_anonymous", uctx->access_anonymous == FALSE);
		imap_urlauth_deinit(&uctx);
		test_out("imap_urlauth_deinit sets pointer to NULL", uctx == NULL);
	}

	config.access_anonymous = TRUE;
	uctx = imap_urlauth_init(NULL, &config);
	test_out("imap_urlauth_init(anonymous)", uctx != NULL);
	if (uctx != NULL) {
		test_out("uctx->access_user is anonymous", strcmp(uctx->access_user, "anonymous") == 0);
		test_out("uctx->access_anonymous is TRUE", uctx->access_anonymous == TRUE);
		imap_urlauth_deinit(&uctx);
	}

	const char *apps[] = { "app1", "app2+", NULL };
	config.access_applications = apps;
	config.access_anonymous = FALSE;
	uctx = imap_urlauth_init(NULL, &config);
	test_out("imap_urlauth_init(with applications)", uctx != NULL);
	if (uctx != NULL) {
		test_out("uctx->access_applications set", uctx->access_applications != NULL);
		test_out("uctx->access_applications[0]", strcmp(uctx->access_applications[0], "app1") == 0);
		test_out("uctx->access_applications[1]", strcmp(uctx->access_applications[1], "app2+") == 0);
		imap_urlauth_deinit(&uctx);
	}

	test_end();
}

static void test_imap_urlauth_check_basic(void)
{
	struct imap_urlauth_context uctx = {
		.url_host = "localhost",
		.url_port = 143,
		.access_service = "imap",
		.access_user = "user",
	};
	struct imap_url url = {
		.mailbox = "INBOX",
		.uid = 1,
		.uauth_rumpurl = "imap://user@localhost/INBOX/;UID=1;URLAUTH=anonymous",
		.uauth_mechanism = "INTERNAL",
		.userid = "user",
		.uauth_access_application = "anonymous",
		.host = { .name = "localhost" },
		.uauth_expire = (time_t)-1,
	};
	const char *error;
	bool result;
	time_t now = time(NULL);

	test_begin("imap_urlauth_check()");

	/* 1. Success case */
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(valid)", result);

	/* 2. Invalid URL fields */
	url.mailbox = NULL;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(missing mailbox)", !result);
	url.mailbox = "INBOX";

	url.uid = 0;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(missing uid)", !result);
	url.uid = 1;

	url.search_program = "ALL";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(search program not allowed)", !result);
	url.search_program = NULL;

	url.uauth_rumpurl = NULL;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(missing rumpurl)", !result);
	url.uauth_rumpurl = "imap://user@localhost/INBOX/;UID=1;URLAUTH=anonymous";

	url.uauth_mechanism = NULL;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(missing mechanism)", !result);
	url.uauth_mechanism = "INTERNAL";

	/* 3. Missing userid */
	url.userid = NULL;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(missing userid)", !result);
	url.userid = "user";

	/* 4. Unsupported mechanism */
	url.uauth_mechanism = "UNKNOWN";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(unsupported mechanism)", !result);
	url.uauth_mechanism = "INTERNAL";

	/* 5. Expired */
	url.uauth_expire = now - 1;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(expired)", !result);
	url.uauth_expire = now + 3600;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(not expired)", result);
	url.uauth_expire = (time_t)-1;

	/* 6. Host/port check */
	url.host.name = "otherhost";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(invalid host)", !result);
	url.host.name = "localhost";

	uctx.url_host = "*";
	url.host.name = "anyhost";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(any host allowed)", result);
	uctx.url_host = "localhost";
	url.host.name = "localhost";

	url.port = 993;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(invalid port)", !result);
	url.port = 0; /* Default 143 */
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(default port 143)", result);

	/* 7. Access checks - IMAP */
	uctx.access_service = "imap";

	/* application=user */
	url.uauth_access_application = "user";
	url.uauth_access_user = "user";
	uctx.access_user = "user";
	uctx.access_anonymous = FALSE;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap user access - match)", result);

	uctx.access_user = "other";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap user access - mismatch)", !result);

	uctx.access_anonymous = TRUE;
	uctx.access_user = "anonymous";
	url.uauth_access_user = "anonymous";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap user access - anonymous match)", result);

	/* application=authuser */
	url.uauth_access_application = "authuser";
	url.uauth_access_user = NULL;
	uctx.access_anonymous = FALSE;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap authuser access)", result);
	uctx.access_anonymous = TRUE;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap authuser access - anonymous not allowed)", !result);

	/* application=anonymous */
	url.uauth_access_application = "anonymous";
	uctx.access_anonymous = TRUE;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap anonymous access)", result);

	/* custom applications */
	const char *apps[] = { "app1", "app2+", NULL };
	uctx.access_applications = apps;
	uctx.access_anonymous = FALSE;
	uctx.access_user = "user";
	url.uauth_access_application = "app1";
	url.uauth_access_user = NULL;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap custom app1 access)", result);

	url.uauth_access_application = "app2";
	url.uauth_access_user = "someuser";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap custom app2+ access)", result);

	url.uauth_access_application = "app3";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(imap unknown app access)", !result);
	result = imap_urlauth_check(&uctx, &url, TRUE, &error);
	test_out("imap_urlauth_check(imap unknown app access - ignore_unknown)", result);

	/* 8. Access checks - Submission */
	uctx.access_service = "submission";
	url.uauth_access_application = "submit";
	url.uauth_access_user = "user";
	uctx.access_user = "user";
	uctx.access_anonymous = FALSE;
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(submission submit access)", result);

	url.uauth_access_application = "user";
	result = imap_urlauth_check(&uctx, &url, FALSE, &error);
	test_out("imap_urlauth_check(submission user access - not allowed)", !result);

	test_end();
}

static void test_imap_urlauth_generate_basic(void)
{
	struct mail_user user;
	struct imap_urlauth_context uctx = {
		.user = &user,
		.url_host = "localhost",
		.url_port = 143,
		.access_service = "imap",
		.access_user = "user",
	};
	const char *urlauth, *error;
	int ret;

	test_begin("imap_urlauth_generate()");

	i_zero(&user);
	user.username = "user";

	/* 1. Unsupported mechanism */
	ret = imap_urlauth_generate(&uctx, "UNKNOWN", "imap://user@localhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(unsupported mechanism)", ret == 0 && error != NULL);

	/* 2. Invalid URL */
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "invalid-url", &urlauth, &error);
	test_out("imap_urlauth_generate(invalid url)", ret == 0 && error != NULL);

	/* 3. Not a rump URL (has search program) */
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://user@localhost/INBOX?ALL", &urlauth, &error);
	test_out("imap_urlauth_generate(not a rump url - search)", ret == 0 && error != NULL);

	/* 4. Missing userid */
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://localhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(missing userid)", ret == 0 && error != NULL);

	/* 5. Anonymous user not permitted */
	user.anonymous = TRUE;
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://user@localhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(anonymous not permitted)", ret == 0 && error != NULL);
	user.anonymous = FALSE;

	/* 6. User mismatch */
	user.username = "other";
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://user@localhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(user mismatch)", ret == 0 && error != NULL);
	user.username = "user";

	/* 7. Host mismatch */
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://user@otherhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(host mismatch)", ret == 0 && error != NULL);

	/* 8. Success path (with mocks) */
	ret = imap_urlauth_generate(&uctx, "INTERNAL", "imap://user@localhost/INBOX/;UID=1;URLAUTH=user+user", &urlauth, &error);
	test_out("imap_urlauth_generate(success)", ret == 1 && urlauth != NULL);

	test_end();
}

static void test_imap_urlauth_fetch_basic(void)
{
	struct mail_user user;
	struct imap_urlauth_context uctx = {
		.user = &user,
		.url_host = "localhost",
		.url_port = 143,
		.access_service = "imap",
		.access_user = "user",
	};
	struct imap_url url;
	struct imap_msgpart_url *mpurl;
	enum mail_error error_code;
	const char *error;
	int ret;

	test_begin("imap_urlauth_fetch()");

	i_zero(&user);
	user.username = "user";

	i_zero(&url);
	url.mailbox = "INBOX";
	url.uid = 1;
	url.uauth_rumpurl = "imap://user@localhost/INBOX/;UID=1;URLAUTH=anonymous";
	url.uauth_mechanism = "INTERNAL";
	url.userid = "user";
	url.uauth_access_application = "anonymous";
	url.host.name = "localhost";
	url.uauth_expire = (time_t)-1;
	url.uauth_token = (const unsigned char *)"12345678901234567890";
	url.uauth_token_size = 20;

	/* 1. imap_urlauth_fetch_parsed failure */
	url.host.name = "otherhost";
	ret = imap_urlauth_fetch_parsed(&uctx, &url, &mpurl, &error_code, &error);
	test_out("imap_urlauth_fetch_parsed(check failure)", ret == 0 && error_code == MAIL_ERROR_PARAMS);
	url.host.name = "localhost";

	/* 2. imap_urlauth_fetch failure (invalid string) */
	ret = imap_urlauth_fetch(&uctx, "invalid-url", &mpurl, &error_code, &error);
	test_out("imap_urlauth_fetch(invalid url)", ret == 0 && error_code == MAIL_ERROR_PARAMS);

	/* 3. imap_urlauth_fetch success path (calls parsed) */
	ret = imap_urlauth_fetch(&uctx, "imap://user@localhost/INBOX/;UID=1;URLAUTH=anonymous:INTERNAL:4142434445464748494A4B4C4D4E4F5051525354", &mpurl, &error_code, &error);
	/* Verification failure is expected because our mock key is all zeros but the token is not a SHA1-HMAC of rumpurl with zero key */
	test_out("imap_urlauth_fetch(verification failure)", ret == 0 && error_code == MAIL_ERROR_PERM);

	test_end();
}

static void test_imap_urlauth_reset_keys(void)
{
	struct imap_urlauth_context uctx = {
		.user = NULL
	};

	test_begin("imap_urlauth_reset_keys()");
	test_out("imap_urlauth_reset_mailbox_key", imap_urlauth_reset_mailbox_key(&uctx, NULL) == 0);
	test_out("imap_urlauth_reset_all_keys", imap_urlauth_reset_all_keys(&uctx) == 0);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_urlauth_init_deinit,
		test_imap_urlauth_check_basic,
		test_imap_urlauth_generate_basic,
		test_imap_urlauth_fetch_basic,
		test_imap_urlauth_reset_keys,
		NULL
	};
	return test_run(test_functions);
}
