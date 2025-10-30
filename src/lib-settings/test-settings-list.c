/* Copyright (c) 2021-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "test-common.h"

struct test_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) strlist;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct test_settings)

static struct setting_define test_setting_defines[] = {
	DEF(STRLIST, strlist),
	SETTING_DEFINE_LIST_END
};

static struct test_settings test_default_settings = {
	.strlist = ARRAY_INIT,
};

static const struct setting_parser_info test_setting_parser_info = {
	.name = "test",

	.defines = test_setting_defines,
	.defaults = &test_default_settings,

	.struct_size = sizeof(struct test_settings),
	.pool_offset1 = 1 + offsetof(struct test_settings, pool),
};

static void
test_settings_list_run(const char *const settings[],
		       const char *const expected_results[])
{
	struct event *event;
	struct settings_root *set_root;
	struct test_settings *set;
	const char *error;
	int ret;

	set_root = settings_root_init();
	for (unsigned int i = 0; settings[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(settings[i], &key, &value);
		settings_root_override(set_root, key, value,
				       SETTINGS_OVERRIDE_TYPE_CODE);
	}
	event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	ret = settings_get(event, &test_setting_parser_info, 0,
			   &set, &error);
	test_assert(ret == 0);
	test_assert(error == NULL);
	if (ret < 0)
		i_error("settings_get() failed: %s", error);

	test_assert(array_count(&set->strlist) == str_array_length(expected_results));
	for (unsigned int i = 0; i < str_array_length(expected_results); i++) {
		const char *const *value = array_idx(&set->strlist, i*2+1);
		test_assert_strcmp_idx(*value, expected_results[i], i);
	}

	settings_free(set);
	settings_root_deinit(&set_root);
	event_unref(&event);
}

static void test_settings_list(void)
{
	test_begin("settings list");

	const char *const settings1[] = {
		"strlist/key1=value1",
		"strlist/key2=value2",
		NULL
	};
	const char *const results1[] = {
		"value1", "value2"
	};
	test_settings_list_run(settings1, results1);

	const char *const settings2[] = {
		"strlist/key1=value1",
		"strlist/key2=value2",
		"strlist/key1-=value1",
		NULL
	};
	const char *const results2[] = {
		"value2"
	};
	test_settings_list_run(settings2, results2);

	const char *const settings3[] = {
		"strlist/key1=value1",
		"strlist/key2=value2",
		"strlist/key2-=value2",
		NULL
	};
	const char *const results3[] = {
		"value1"
	};
	test_settings_list_run(settings3, results3);

	const char *const settings4[] = {
		"strlist/key1=value1",
		"strlist/key2=value2",
		"strlist/key1-=value1",
		"strlist/key2-=value2",
		NULL
	};
	const char *const results4[] = { NULL };
	test_settings_list_run(settings4, results4);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_list,
		NULL
	};
	return test_run(test_functions);
}
