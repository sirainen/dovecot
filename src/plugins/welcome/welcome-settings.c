/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "service-settings.h"

struct service_settings welcome_service_settings = {
	.name = "welcome",
	.protocol = "",
	.type = "",
	.executable = "",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};

const struct setting_keyvalue welcome_service_settings_defaults[] = {
	{ "unix_listener", "welcome" },

	{ "unix_listener/welcome/user", "vmail" },

	{ NULL, NULL }
};
