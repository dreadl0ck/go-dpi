#ifndef LPI_WRAPPER_ONCE
#define LPI_WRAPPER_ONCE

#include "wrappers_config.h"
#ifndef DISABLE_LPI

#include <iostream>
#include <libprotoident.h>
#include <libprotoident.h>
#include <libtrace.h>

using namespace std;

struct lpiResult {
	u_int32_t proto;
	u_int32_t category;
};

struct lpiProtocolInfo {
	u_int32_t proto;
	u_int32_t category;
	char name[256];
};

extern "C"
int lpiInitLibrary() {
    // Initialize the library
    return lpi_init_library();
}

extern "C"
lpi_data_t *lpiCreateFlow() {
    // Create a new flow
    lpi_data_t *data = new lpi_data_t;
    lpi_init_data(data);
    return data;
}

extern "C"
void lpiFreeFlow(lpi_data_t *data) {
    // Free a flow
    delete data;
}

extern "C"
int lpiAddPacketToFlow(lpi_data_t *data, const void *pktData, unsigned short pktLen, int dir) {
    // Add the data of a packet to a flow
    int retVal;
    auto packet = trace_create_packet();

    trace_construct_packet(packet, TRACE_TYPE_ETH, pktData, pktLen);
    retVal = lpi_update_data(packet, data, dir);
    trace_destroy_packet(packet);

    return retVal;
}

extern "C"
lpiResult *lpiGuessProtocol(lpi_data_t *data) {
    // Try to classify a flow
    struct lpiResult* res = new lpiResult;
    lpi_module_t *mod = lpi_guess_protocol(data);
    res->proto = mod->protocol;
    res->category = mod->category;
    return res;
}

extern "C"
void lpiDestroyLibrary() {
    // Free the library
    lpi_free_library();
}

extern "C"
int lpiGetProtocolCount() {
    // libprotoident protocols are an enum from 0 to ~540
    // We return a safe upper bound
    return 600;
}

extern "C"
lpiProtocolInfo *lpiGetProtocolInfo(int index) {
    // Cast index to protocol enum type
    lpi_protocol_t proto = static_cast<lpi_protocol_t>(index);
    
    // Use lpi_print to get the protocol name
    const char *name = lpi_print(proto);
    if (name == NULL || strcmp(name, "Unknown") == 0) {
        // Skip unknown protocols
        return NULL;
    }
    
    lpiProtocolInfo *info = new lpiProtocolInfo;
    info->proto = static_cast<uint32_t>(proto);
    
    // Get the category for this protocol
    info->category = static_cast<uint32_t>(lpi_get_category_by_protocol(proto));
    
    // Copy the protocol name
    strncpy(info->name, name, 255);
    info->name[255] = '\0';
    
    return info;
}

extern "C"
void lpiFreeProtocolInfo(lpiProtocolInfo *info) {
    delete info;
}

#else
// LPI is disabled, so initialization fails

typedef void lpi_data_t;

extern "C" int lpiInitLibrary() {
    return ERROR_LIBRARY_DISABLED;
}

extern "C" lpi_data_t *lpiCreateFlow() {
    return nullptr;
}

extern "C" void lpiFreeFlow(lpi_data_t*) {
}

extern "C" int lpiAddPacketToFlow(lpi_data_t*, const void*, unsigned short) {
    return -1;
}

extern "C" int lpiGuessProtocol(lpi_data_t*) {
    return -1;
}

extern "C" void lpiDestroyLibrary() {
}

#endif
#endif
