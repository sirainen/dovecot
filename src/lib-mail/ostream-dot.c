/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream-private.h"
#include "ostream-dot.h"

enum dot_ostream_state {
	STREAM_STATE_INIT = 0,
	STREAM_STATE_NONE,
	STREAM_STATE_CR,
	STREAM_STATE_CRLF,
	STREAM_STATE_DONE
};

struct dot_ostream {
	struct ostream_private ostream;

	enum dot_ostream_state state;
	bool force_extra_crlf;
};

static int o_stream_dot_finish(struct ostream_private *stream)
{
	struct dot_ostream *dstream = (struct dot_ostream *)stream;
	int ret;

	if (dstream->state == STREAM_STATE_DONE)
		return 1;

	if (o_stream_get_buffer_avail_size(stream->parent) < 5) {
		/* make space for the dot line */
		if ((ret = o_stream_flush(stream->parent)) <= 0) {
			if (ret < 0)
				o_stream_copy_error_from_parent(stream);
			return ret;
		}
	}

	if (dstream->state == STREAM_STATE_CRLF &&
	    !dstream->force_extra_crlf) {
		ret = o_stream_send(stream->parent, ".\r\n", 3);
		i_assert(ret == 3);
	} else {
		ret = o_stream_send(stream->parent, "\r\n.\r\n", 5);
		i_assert(ret == 5);
	}
	dstream->state = STREAM_STATE_DONE;
	return 1;
}

static int
o_stream_dot_flush(struct ostream_private *stream)
{
	int ret;

	if (stream->finished) {
		if ((ret = o_stream_dot_finish(stream)) <= 0)
			return ret;
	}

	return o_stream_flush_parent(stream);
}

static void
o_stream_dot_close(struct iostream_private *stream, bool close_parent)
{
	struct dot_ostream *dstream = (struct dot_ostream *)stream;

	if (close_parent)
		o_stream_close(dstream->ostream.parent);
}

static ssize_t
o_stream_dot_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct dot_ostream *dstream = (struct dot_ostream *)stream;
	ARRAY(struct const_iovec) iov_arr;
	const struct const_iovec *iov_new;
	size_t max_bytes, sent, added;
	unsigned int count, i;
	ssize_t ret;

	i_assert(dstream->state != STREAM_STATE_DONE);

	if ((ret=o_stream_flush(stream->parent)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		if (ret < 0)
			o_stream_copy_error_from_parent(stream);
		return ret;
	}

	/* check for dots */
	t_array_init(&iov_arr, iov_count + 32);
	max_bytes = o_stream_get_buffer_avail_size(stream->parent);
	i_assert(max_bytes > 0); /* FIXME: not supported currently */

	sent = added = 0;
	for (i = 0; i < iov_count && max_bytes > 0; i++) {
		size_t size = iov[i].iov_len, chunk;
		const char *data = iov[i].iov_base, *p, *pend;
		struct const_iovec iovn;

		p = data;
		pend = CONST_PTR_OFFSET(data, size);
		while (p < pend && max_bytes > 1) {
			size_t avail_in_buf = pend - p;
			size_t len;

			switch (dstream->state) {
			case STREAM_STATE_INIT:
			case STREAM_STATE_CRLF:
				len = i_memcspn(p, avail_in_buf, "\r\n.", 3);
				break;
			case STREAM_STATE_CR:
				len = i_memcspn(p, avail_in_buf, "\r\n", 2);
				break;
			case STREAM_STATE_NONE:
				len = i_memcspn(p, avail_in_buf, "\r\n", 2);
				break;
			case STREAM_STATE_DONE:
			default:
				i_unreached();
			}

			if (len > 0) {
				size_t copy_len = I_MIN(len, max_bytes-1);
				iovn.iov_base = p;
				iovn.iov_len = copy_len;
				array_push_back(&iov_arr, &iovn);
				max_bytes -= copy_len;
				sent += copy_len;
				p += copy_len;
				if (len > copy_len)
					continue;
			}
			if (p == pend)
				break;

			char add = 0;
			switch (dstream->state) {
			case STREAM_STATE_NONE:
				if (*p == '\n') {
					dstream->state = STREAM_STATE_CRLF;
					add = '\r';
				} else {
					i_assert(*p == '\r');
					dstream->state = STREAM_STATE_CR;
				}
				break;
			case STREAM_STATE_CR:
				if (*p == '\n')
					dstream->state = STREAM_STATE_CRLF;
				else {
					i_assert(*p == '\r');
					dstream->state = STREAM_STATE_NONE;
				}
				break;
			case STREAM_STATE_INIT:
			case STREAM_STATE_CRLF:
				if (*p == '.') {
					add = '.';
					dstream->state = STREAM_STATE_NONE;
				} else if (*p == '\n') {
					dstream->state = STREAM_STATE_CRLF;
					add = '\r';
				} else {
					i_assert(*p == '\r');
					dstream->state = STREAM_STATE_CR;
				}
				break;
			case STREAM_STATE_DONE:
				i_unreached();
			}

			if (add != 0) {
				iovn.iov_base = (add == '\r' ? "\r\n" : "..");
				iovn.iov_len = 2;
				array_push_back(&iov_arr, &iovn);
				i_assert(max_bytes >= 2);
				max_bytes -= 2;
				added++;
				sent++;
			} else {
				iovn.iov_base = p;
				iovn.iov_len = 1;
				array_push_back(&iov_arr, &iovn);
				max_bytes--;
				sent++;
			}
			p++;
		}
		chunk = pend - p;
		if (chunk > 0) {
			iovn.iov_base = data;
			iovn.iov_len = chunk;
			array_push_back(&iov_arr, &iovn);
			i_assert(max_bytes >= chunk);
			max_bytes -= chunk;
			sent += chunk;
		}
	}

	/* send */
	iov_new = array_get(&iov_arr, &count);
	if (count == 0) {
		ret = 0;
	} else if ((ret=o_stream_sendv(stream->parent, iov_new, count)) <= 0) {
		i_assert(ret < 0);
		o_stream_copy_error_from_parent(stream);
		return -1;
	}

	/* all must be sent */
	i_assert((size_t)ret == sent + added);

	stream->ostream.offset += sent;
	return sent;
}

struct ostream *
o_stream_create_dot(struct ostream *output, bool force_extra_crlf)
{
	struct dot_ostream *dstream;

	dstream = i_new(struct dot_ostream, 1);
	dstream->ostream.sendv = o_stream_dot_sendv;
	dstream->ostream.iostream.close = o_stream_dot_close;
	dstream->ostream.flush = o_stream_dot_flush;
	dstream->ostream.max_buffer_size = output->real_stream->max_buffer_size;
	dstream->force_extra_crlf = force_extra_crlf;
	(void)o_stream_create(&dstream->ostream, output, o_stream_get_fd(output));
	/* ostream-dot is always used inside another ostream that shouldn't
	   get finished when the "." line is written. Disable it here so all
	   of the callers don't have to set this. */
	o_stream_set_finish_also_parent(&dstream->ostream.ostream, FALSE);
	return &dstream->ostream.ostream;
}
