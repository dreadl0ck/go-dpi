#ifndef GODPI_INCREMENTAL_H
#define GODPI_INCREMENTAL_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    void *flow;
    uint32_t protocol;
    uint32_t category;
    int error;
} dpi_step;
void *dpi_ndpi_create(void);
void dpi_ndpi_destroy(void *engine);
dpi_step dpi_ndpi_step(void *engine, void *flow, const uint8_t *ip, uint16_t len, uint64_t time, int final);
dpi_step dpi_ndpi_resume(void *engine, const uint8_t *first, uint16_t first_len, uint64_t first_time,
                         const uint8_t *ip, uint16_t len, uint64_t time, int final);
void dpi_ndpi_free(void *flow);
void *dpi_lpi_create(void);
void dpi_lpi_destroy(void *engine);
dpi_step dpi_lpi_step(void *engine, void *flow, const uint8_t *packet, uint16_t len, int direction, int final, int terminal);
void dpi_lpi_free(void *flow);
#ifdef __cplusplus
}
#endif
#endif
