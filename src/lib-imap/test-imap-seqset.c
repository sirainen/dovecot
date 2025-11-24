/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imap-seqset.h"
#include "seq-range-array.h"
#include "test-common.h"

static void test_imap_seq_set_parse(void)
{
	static const struct {
		const char *input;
		const char *output;
		int ret;
	} tests[] = {
		{ "1", "1", 0 },
		{ "2:4", "2:4", 0 },
		{ "5:*", "5:*", 0 },
		{ "1,3,5", "1,3,5", 0 },
		{ "1,3:5,7:*", "1,3:5,7:*", 0 },
		{ "1,2,3,4,5", "1:5", 0 },
		{ "1,2,4,5", "1:2,4:5", 0 },
		{ "1,3,2,5,4", "1:5", 0 },
		{ "", "", -1 },
		{ "1,", "", -1 },
		{ ",", "", -1 },
		{ "1,,5", "", -1 },
		{ "1:2,3,,5", "", -1 },
		{ "a", "", -1 },
		{ "1:a", "", -1 },
		{ "1:2a", "", -1 },
	};
	ARRAY_TYPE(seq_range) ranges;

	test_begin("imap_seq_set_parse()");
	t_array_init(&ranges, 4);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		array_clear(&ranges);
		int ret = imap_seq_set_parse(tests[i].input, &ranges);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			string_t *str = t_str_new(128);
			seq_range_array_to_string(str, &ranges);
			test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
		}
	}
	test_end();
}

static void test_imap_seq_set_nostar_parse(void)
{
	static const struct {
		const char *input;
		const char *output;
		int ret;
	} tests[] = {
		{ "1", "1", 0 },
		{ "2:4", "2:4", 0 },
		{ "1,3,5", "1,3,5", 0 },
		{ "1,3:5", "1,3:5", 0 },
		{ "1,2,3,4,5", "1:5", 0 },
		{ "1,2,4,5", "1:2,4:5", 0 },
		{ "1,3,2,5,4", "1:5", 0 },
		{ "5:*", "", -1 },
		{ "1,3:5,7:*", "", -1 },
		{ "*", "", -1 },
	};
	ARRAY_TYPE(seq_range) ranges;

	test_begin("imap_seq_set_nostar_parse()");
	t_array_init(&ranges, 4);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		array_clear(&ranges);
		int ret = imap_seq_set_nostar_parse(tests[i].input, &ranges);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			string_t *str = t_str_new(128);
			seq_range_array_to_string(str, &ranges);
			test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
		}
	}
	test_end();
}

static void test_imap_seq_range_parse(void)
{
	static const struct {
		const char *input;
		uint32_t seq1, seq2;
		int ret;
	} tests[] = {
		{ "1", 1, 1, 0 },
		{ "2:4", 2, 4, 0 },
		{ "5:*", 5, (uint32_t)-1, 0 },
		{ "*", (uint32_t)-1, (uint32_t)-1, 0 },
		{ "0", 0, 0, -1 },
		{ "1:0", 0, 0, -1 },
		{ "", 0, 0, -1 },
		{ ":", 0, 0, -1 },
		{ "1:", 0, 0, -1 },
		{ ":5", 0, 0, -1 },
		{ "a", 0, 0, -1 },
		{ "1a", 0, 0, -1 },
		{ "1:a", 0, 0, -1 },
	};
	uint32_t seq1, seq2;

	test_begin("imap_seq_range_parse()");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		int ret = imap_seq_range_parse(tests[i].input, &seq1, &seq2);
		test_assert_idx(ret == tests[i].ret, i);
		if (ret == 0) {
			test_assert_idx(seq1 == tests[i].seq1 &&
					seq2 == tests[i].seq2, i);
		}
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_seq_set_parse,
		test_imap_seq_set_nostar_parse,
		test_imap_seq_range_parse,
		NULL
	};
	return test_run(test_functions);
}
