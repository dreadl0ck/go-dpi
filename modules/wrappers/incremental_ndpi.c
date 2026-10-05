#include "incremental.h"
#include "wrappers_config.h"
#include <stdlib.h>
#include <string.h>
#ifndef DISABLE_NDPI
#include <ndpi/ndpi_api.h>

typedef struct {
    struct ndpi_global_context *global;
    struct ndpi_detection_module_struct *module;
} dpi_engine;

void *dpi_ndpi_create(void) {
    dpi_engine *engine = calloc(1, sizeof(*engine));
    if (!engine) return NULL;
    engine->global = ndpi_global_init();
    if (!engine->global) { free(engine); return NULL; }
    engine->module = ndpi_init_detection_module(engine->global);
    if (!engine->module) { ndpi_global_deinit(engine->global); free(engine); return NULL; }
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(engine->module, &all);
    if (ndpi_finalize_initialization(engine->module) != 0) {
        dpi_ndpi_destroy(engine);
        return NULL;
    }
    return engine;
}

void dpi_ndpi_destroy(void *ptr) {
    dpi_engine *engine = ptr;
    if (!engine) return;
    ndpi_exit_detection_module(engine->module);
    ndpi_global_deinit(engine->global);
    free(engine);
}

void dpi_ndpi_free(void *flow) {
    if (flow) ndpi_free_flow(flow);
}

dpi_step dpi_ndpi_step(void *ptr, void *state, const uint8_t *ip, uint16_t len, uint64_t time, int final) {
    dpi_step result = {state, 0, 0, 0};
    dpi_engine *engine = ptr;
    if (!engine || !ip || len < 20) { result.error = -1; return result; }
    // Validate captured lengths before nDPI reads transport headers.
    unsigned version = ip[0] >> 4;
    unsigned header = version == 4 ? (ip[0] & 15) * 4 : 40;
    unsigned total = version == 4 ? ((unsigned)ip[2] << 8) | ip[3] : 40 + (((unsigned)ip[4] << 8) | ip[5]);
    if ((version != 4 && version != 6) || header < 20 || len < header || total < header || total > len ||
        (version == 4 && ((ip[6] & 0x3f) || ip[7]))) {
        result.error = -1; return result;
    }
    if (!state) {
        state = calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
        if (!state) { result.error = -2; return result; }
        result.flow = state;
    }
    struct ndpi_flow_input_info info;
    memset(&info, 0, sizeof(info));
    ndpi_protocol detected = ndpi_detection_process_packet(engine->module, state, ip, len, time, &info);
    result.protocol = detected.proto.master_protocol ? detected.proto.master_protocol : detected.proto.app_protocol;
    if (result.protocol || final) { dpi_ndpi_free(state); result.flow = NULL; }
    return result;
}
#else
void *dpi_ndpi_create(void) { return NULL; }
void dpi_ndpi_destroy(void *engine) {}
void dpi_ndpi_free(void *flow) {}
dpi_step dpi_ndpi_step(void *engine, void *flow, const uint8_t *ip, uint16_t len, uint64_t time, int final) {
    dpi_step result = {NULL, 0, 0, -1}; return result;
}
#endif

dpi_step dpi_ndpi_resume(void *engine, const uint8_t *first, uint16_t first_len, uint64_t first_time,
                         const uint8_t *ip, uint16_t len, uint64_t time, int final) {
    dpi_step initial = dpi_ndpi_step(engine, NULL, first, first_len, first_time, 0);
    if (initial.error || initial.protocol) return initial;
    return dpi_ndpi_step(engine, initial.flow, ip, len, time, final);
}
