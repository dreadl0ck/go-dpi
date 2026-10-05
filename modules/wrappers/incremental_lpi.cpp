#include "incremental.h"
#include "wrappers_config.h"
#ifndef DISABLE_LPI
#include <libprotoident.h>
#include <new>
#include <cstring>

struct dpi_lpi_flow {
    lpi_data_t data;
    lpi_module_t *last;
};

void *dpi_lpi_create(void) { return trace_create_packet(); }
void dpi_lpi_destroy(void *engine) { if (engine) trace_destroy_packet(static_cast<libtrace_packet_t *>(engine)); }

void dpi_lpi_free(void *ptr) {
    dpi_lpi_flow *flow = static_cast<dpi_lpi_flow *>(ptr);
    if (!flow) return;
    delete flow;
}

dpi_step dpi_lpi_step(void *engine, void *ptr, const uint8_t *packet, uint16_t len, int direction, int final, int terminal) {
    dpi_step result = {ptr, 0, 0, 0};
    if (!engine) { result.error = -1; return result; }
    dpi_lpi_flow *flow = static_cast<dpi_lpi_flow *>(ptr);
    if (!flow) {
        flow = new (std::nothrow) dpi_lpi_flow;
        if (!flow) { result.error = -2; return result; }
        std::memset(&flow->data, 0, sizeof(flow->data));
        lpi_init_data(&flow->data);
        flow->last = NULL;
        result.flow = flow;
    }
    libtrace_packet_t *scratch = static_cast<libtrace_packet_t *>(engine);
    trace_construct_packet(scratch, TRACE_TYPE_ETH, packet, len);
    lpi_data_t before = flow->data;
    int status = lpi_update_data(scratch, &flow->data, direction);
    if (status < 0) result.error = status;
    lpi_data_t after = flow->data;
    // Classifiers use observed[] only to distinguish zero from non-zero payload.
    for (int i = 0; i < 2; i++) {
        before.observed[i] = before.observed[i] != 0;
        after.observed[i] = after.observed[i] != 0;
    }
    if (!flow->last || std::memcmp(&before, &after, sizeof(before)) != 0)
        flow->last = lpi_guess_protocol(&flow->data);
    lpi_module_t *module = flow->last;
    if (module) { result.protocol = module->protocol; result.category = module->category; }
    // Unknown and no-payload results must keep inspecting until the budget is exhausted.
    if (final || (terminal && module && module->protocol != LPI_PROTO_UNKNOWN && module->protocol != LPI_PROTO_UDP && module->protocol != LPI_PROTO_NO_PAYLOAD)) {
        dpi_lpi_free(flow); result.flow = NULL;
    }
    return result;
}
#else
void *dpi_lpi_create(void) { return NULL; }
void dpi_lpi_destroy(void *engine) {}
void dpi_lpi_free(void *flow) {}
dpi_step dpi_lpi_step(void *engine, void *flow, const uint8_t *packet, uint16_t len, int direction, int final, int terminal) {
    dpi_step result = {NULL, 0, 0, -1}; return result;
}
#endif
