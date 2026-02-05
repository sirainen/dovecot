/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-url.h"
#include "imap-urlauth-private.h"
#include "test-common.h"
#include <time.h>

static void test_imap_urlauth_check(void)
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_urlauth_check,
		NULL
	};
	return test_run(test_functions);
}
