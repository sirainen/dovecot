/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

extern "C" {
#include "stats-common.h"
#include "event-exporter.h"
#include "stats-metrics.h"
}

#include <map>
#include <string>
#include <vector>
#include <memory>
#include <chrono>

#ifdef HAVE_OTEL
#include <opentelemetry/exporters/otlp/otlp_http_log_record_exporter_factory.h>
#include <opentelemetry/sdk/logs/logger_provider_factory.h>
#include <opentelemetry/sdk/logs/simple_log_record_processor_factory.h>
#include <opentelemetry/logs/provider.h>
#include <opentelemetry/sdk/resource/resource.h>

namespace logs_sdk = opentelemetry::sdk::logs;
namespace logs = opentelemetry::logs;
namespace otlp = opentelemetry::exporter::otlp;
namespace resource = opentelemetry::sdk::resource;
namespace common = opentelemetry::common;

static std::shared_ptr<logs::Logger> otel_logger;

static void otel_init_sdk(const char *endpoint) {
    if (otel_logger) return;

    otlp::OtlpHttpLogRecordExporterOptions options;
    if (endpoint != nullptr && *endpoint != '\0') {
        options.url = endpoint;
    }

    auto exporter = otlp::OtlpHttpLogRecordExporterFactory::Create(options);
    auto processor = logs_sdk::SimpleLogRecordProcessorFactory::Create(std::move(exporter));

    resource::ResourceAttributes resource_attributes = {
        {"service.name", "dovecot"}
    };
    auto resource = resource::Resource::Create(resource_attributes);

    auto provider = logs_sdk::LoggerProviderFactory::Create(std::move(processor), resource);
    logs::Provider::SetLoggerProvider(provider);
    otel_logger = provider->GetLogger("dovecot-events");
}

extern "C" {

static int event_exporter_otel_init(pool_t pool, struct event *event ATTR_UNUSED,
				   struct event_exporter **exporter_r,
				   const char **error_r ATTR_UNUSED)
{
	struct event_exporter *exporter = p_new(pool, struct event_exporter, 1);
	*exporter_r = exporter;
	return 0;
}

static void
event_exporter_otel_send_event(struct event_exporter *exporter,
			       const struct metric *metric, struct event *event)
{
    if (!otel_logger) {
        otel_init_sdk(exporter->otel_endpoint);
    }
    if (!otel_logger) return;

    auto record = otel_logger->CreateLogRecord();

    record->SetBody(metric->name);

    if (metric->sub_name != nullptr) {
        record->SetAttribute("dovecot.metric.sub_name", metric->sub_name);
    }

    struct timeval tv;
    if (event_get_last_send_time(event, &tv)) {
        record->SetTimestamp(opentelemetry::common::SystemTimestamp(
            std::chrono::system_clock::time_point(
                std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec))));
    }

    uintmax_t duration;
    event_get_last_duration(event, &duration);
    record->SetAttribute("dovecot.event.duration_us", (int64_t)duration);

    // Categories
    unsigned int cat_count;
    struct event_category *const *categories = event_get_categories(event, &cat_count);
    if (cat_count > 0) {
        std::string cats;
        for (unsigned int i = 0; i < cat_count; i++) {
            if (!cats.empty()) cats += ",";
            cats += categories[i]->name;
        }
        record->SetAttribute("dovecot.event.categories", cats);
    }

    // Fields
    unsigned int field_count;
    const struct event_field *fields = event_get_fields(event, &field_count);
    for (unsigned int i = 0; i < field_count; i++) {
        const char *key = fields[i].key;
        switch (fields[i].value_type) {
        case EVENT_FIELD_VALUE_TYPE_STR:
            record->SetAttribute(key, fields[i].value.str);
            break;
        case EVENT_FIELD_VALUE_TYPE_INTMAX:
            record->SetAttribute(key, (int64_t)fields[i].value.intmax);
            break;
        case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
            record->SetAttribute(key, (int64_t)(fields[i].value.timeval.tv_sec * 1000000LL + fields[i].value.timeval.tv_usec));
            break;
        case EVENT_FIELD_VALUE_TYPE_IP:
            record->SetAttribute(key, net_ip2addr(&fields[i].value.ip));
            break;
        case EVENT_FIELD_VALUE_TYPE_STRLIST:
            // Join strlist
            std::string val;
            const char *const *str_ptr;
            array_foreach(&fields[i].value.strlist, str_ptr) {
                if (!val.empty()) val += ",";
                val += *str_ptr;
            }
            record->SetAttribute(key, val);
            break;
        }
    }

    otel_logger->EmitLogRecord(std::move(record));
}

const struct event_exporter_transport event_exporter_transport_otel = {
	"otel",
	event_exporter_otel_init,
	nullptr, // deinit
	nullptr, // send
	nullptr, // reopen
	event_exporter_otel_send_event
};

}
#endif
