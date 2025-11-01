#ifndef NDPI_WRAPPER_ONCE
#define NDPI_WRAPPER_ONCE

#include <pcap.h>

#include "wrappers_config.h"
#ifndef DISABLE_NDPI

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <search.h>
#include <signal.h>

#include "nDPI_wrapper_impl.h"

#define ETH_P_IP 0x0800

#define ERR_IPV6_NOT_SUPPORTED 10
#define ERR_FRAGMENTED_PACKET 11
#define ERR_NO_FLOW 12
#define ERR_UNSPECIFIED 0


static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_global_context *ndpi_global_ctx = NULL;
static u_int32_t detection_tick_resolution = 1000;

static u_int32_t size_flow_struct = 0;

// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int32_t first_packet_time_sec;
  u_int32_t first_packet_time_usec;
  u_int8_t detection_completed, protocol;
  struct ndpi_flow_struct *ndpi_flow;

  u_int16_t packets, bytes;
  // result only, not used for flow identification
  u_int16_t detected_protocol;
} ndpi_flow_t;

extern int ndpiInitialize() {
  u_int32_t i;
  NDPI_PROTOCOL_BITMASK all;

  //printf\("\[NDPI DEBUG\] ===== ndpiInitialize START =====\n");

  // init global detection structure

  set_ndpi_malloc(malloc);
  set_ndpi_free(free);
  
  // Initialize global context first
  //printf("[NDPI DEBUG] Calling ndpi_global_init()...\n");
  ndpi_global_ctx = ndpi_global_init();
  if (ndpi_global_ctx == NULL) {
      //fprintf(stderr, "[NDPI ERROR] ndpi_global_init() failed!\n");
      return -1;
  }
  //printf("[NDPI DEBUG] ndpi_global_ctx = %p\n", (void*)ndpi_global_ctx);
  
  //printf("[NDPI DEBUG] Calling ndpi_init_detection_module()...\n");
  ndpi_struct = ndpi_init_detection_module(ndpi_global_ctx);

  if (ndpi_struct == NULL) {
    //  fprintf(stderr, "[NDPI ERROR] ndpi_init_detection_module() failed!\n");
      ndpi_global_deinit(ndpi_global_ctx);
      return -1;
  }
  //printf("[NDPI DEBUG] ndpi_struct = %p\n", (void*)ndpi_struct);
  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  // allocate memory for flow tracking
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
  //printf("[NDPI DEBUG] size_flow_struct = %u\n", size_flow_struct);
  
  if (size_flow_struct == 0) {
    //fprintf(stderr, "[NDPI ERROR] ndpi_flow_struct size is 0!\n");
    ndpi_exit_detection_module(ndpi_struct);
    ndpi_global_deinit(ndpi_global_ctx);
    return -1;
  }

  //printf\("\[NDPI DEBUG\] Calling ndpi_finalize_initialization()...\n");
  ndpi_finalize_initialization(ndpi_struct);

  //printf("[NDPI DEBUG] ===== ndpiInitialize SUCCESS =====\n");
  return 0;
}

static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
}

static void ndpi_flow_freer(void *node) {
  struct ndpi_flow *flow = (struct ndpi_flow*)node;
  free_ndpi_flow(flow);
  ndpi_free(flow);
}

extern void ndpiDestroy(void)
{
  //printf("[NDPI DEBUG] ===== ndpiDestroy START =====\n");
  //printf("[NDPI DEBUG] ndpi_struct = %p\n", (void*)ndpi_struct);
  ndpi_exit_detection_module(ndpi_struct);
  if (ndpi_global_ctx != NULL) {
    //printf("[NDPI DEBUG] Calling ndpi_global_deinit on %p\n", (void*)ndpi_global_ctx);
    ndpi_global_deinit(ndpi_global_ctx);
    ndpi_global_ctx = NULL;
  }
  //printf("[NDPI DEBUG] ===== ndpiDestroy DONE =====\n");
}

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  if(fa->lower_ip < fb->lower_ip) return(-1); else { if(fa->lower_ip > fb->lower_ip) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip < fb->upper_ip) return(-1); else { if(fa->upper_ip > fb->upper_ip) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol < fb->protocol) return(-1); else { if(fa->protocol > fb->protocol) return(1); }

  return(0);
}

static struct ndpi_flow *get_ndpi_flow(const struct pcap_pkthdr *header, 
                          const struct ndpi_iphdr *iph, u_int16_t ipsize)
{
  u_int32_t i;
  u_int16_t l4_packet_len;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;
  struct ndpi_flow *newflow;

  if (ipsize < 20)
    return NULL;

  if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
      || (iph->frag_off & htons(0x1FFF)) != 0)
    return NULL;

  l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

  if (iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  if (iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
    if (iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
    }
  } else if (iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
    if (iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

  if(newflow == NULL) {
    printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
    return NULL;
  }

  memset(newflow, 0, sizeof(struct ndpi_flow));
  newflow->protocol = iph->protocol;
  newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
  newflow->lower_port = lower_port, newflow->upper_port = upper_port;
  newflow->first_packet_time_sec = header->ts.tv_sec;
  newflow->first_packet_time_usec = header->ts.tv_usec;

  //printf\("\[NDPI DEBUG\] Allocating ndpi_flow with size %u\n", size_flow_struct);
  newflow->ndpi_flow = calloc(1, size_flow_struct);
  
  if (newflow->ndpi_flow == NULL) {
    fprintf(stderr, "[NDPI ERROR] %s(2): failed to allocate ndpi_flow_struct (size=%u)\n", __FUNCTION__, size_flow_struct);
    free(newflow);
    return NULL;
  }
  
  //printf\("\[NDPI DEBUG\] Successfully allocated ndpi_flow at %p\n", (void*)newflow->ndpi_flow);

  return newflow;
}


static int packet_processing(const u_int64_t time, const struct pcap_pkthdr *header,
              const struct ndpi_iphdr *iph, u_int16_t ipsize, u_int16_t rawsize, struct ndpi_flow *flow)
{
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int16_t protocol = 0;
  u_int16_t frag_off = ntohs(iph->frag_off);

  //printf\("\[NDPI DEBUG\] packet_processing: flow=%p\n", (void*)flow);
  
  if (flow != NULL) {
    //printf\("\[NDPI DEBUG\] packet_processing: flow->ndpi_flow=%p\n", (void*)flow->ndpi_flow);
    ndpi_flow = flow->ndpi_flow;
    
    if (ndpi_flow == NULL) {
      fprintf(stderr, "[NDPI ERROR] packet_processing: flow->ndpi_flow is NULL!\n");
      return -ERR_NO_FLOW;
    }
    
    flow->packets++, flow->bytes += rawsize;
  } else {
    fprintf(stderr, "[NDPI ERROR] packet_processing: flow is NULL!\n");
    return -ERR_NO_FLOW;
  }

  if(flow->detection_completed) return flow->detected_protocol;

  // only handle unfragmented packets
  if ((frag_off & 0x3FFF) == 0) {
    // here the actual detection is performed
    struct ndpi_flow_input_info input_info;
    memset(&input_info, 0, sizeof(input_info));
    
    ndpi_protocol detected = ndpi_detection_process_packet(ndpi_struct, ndpi_flow, (uint8_t *) iph, ipsize, time, &input_info);
    protocol = detected.proto.master_protocol;
    if (protocol == 0) {
        protocol = detected.proto.app_protocol;
    }
  } else {
    static u_int8_t frag_warning_used = 0;

    return -ERR_FRAGMENTED_PACKET;
  }
  flow->detected_protocol = protocol;

  if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (iph->protocol == IPPROTO_UDP)
     || ((iph->protocol == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

    free_ndpi_flow(flow);
  }
  return flow->detected_protocol;
}


// process a new packet
extern int ndpiPacketProcess(const struct pcap_pkthdr *header, const u_char *packet, void *flow)
{
  const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
  u_int64_t time;
  u_int16_t type, ip_offset;
  struct ndpi_iphdr *iph;
  
  //printf\("\[NDPI DEBUG\] ndpiPacketProcess: header=%p, packet=%p, flow=%p\n", 
  //       (void*)header, (void*)packet, flow);
  
  // Minimum required: Ethernet header + minimum IP header (20 bytes)
  u_int16_t min_packet_size = sizeof(struct ndpi_ethhdr) + 20;

  // Validate packet has minimum required data
  if (header->caplen < min_packet_size) {
    fprintf(stderr, "[NDPI ERROR] Packet too small: caplen=%u, min=%u\n", 
            header->caplen, min_packet_size);
    return -ERR_UNSPECIFIED;
  }
  
  //printf\("\[NDPI DEBUG\] Packet caplen=%u, len=%u\n", header->caplen, header->len);

  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);

  type = ethernet->h_proto;

  // just work on Ethernet packets that contain IP
  if (type == htons(ETH_P_IP)) {
    ip_offset = sizeof(struct ndpi_ethhdr);
    
    // NOW it's safe to access IP header
    iph = (struct ndpi_iphdr *) &packet[ip_offset];
    
    u_int16_t frag_off = ntohs(iph->frag_off);

    if (iph->version != 4) {
      return -ERR_IPV6_NOT_SUPPORTED;
    }

    // Verify we have enough data for the complete IP header
    u_int16_t ip_header_len = iph->ihl * 4;
    if (header->caplen < ip_offset + ip_header_len) {
      return -ERR_UNSPECIFIED;
    }

    // Prevent underflow
    if (header->len < ip_offset) {
      return -ERR_UNSPECIFIED;
    }

    // process the packet
    return packet_processing(time, header, iph, header->len - ip_offset, header->len, (struct ndpi_flow*)flow);
  }
  return -ERR_UNSPECIFIED;
}

extern void *ndpiGetFlow(const struct pcap_pkthdr *header, const u_char *packet) {
  const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
  struct ndpi_iphdr *iph;
  u_int16_t type, ip_offset;
  void *result;
  
  //printf\("\[NDPI DEBUG\] ndpiGetFlow: header=%p, packet=%p\n", (void*)header, (void*)packet);
  
  // Minimum required: Ethernet header + minimum IP header (20 bytes)
  u_int16_t min_packet_size = sizeof(struct ndpi_ethhdr) + 20;

  // Validate packet has minimum required data
  if (header->caplen < min_packet_size) {
    fprintf(stderr, "[NDPI ERROR] ndpiGetFlow: packet too small\n");
    return NULL;
  }

  type = ethernet->h_proto;

  // just work on Ethernet packets that contain IP
  if (type == htons(ETH_P_IP)) {
    ip_offset = sizeof(struct ndpi_ethhdr);
    
    // NOW it's safe to access IP header
    iph = (struct ndpi_iphdr *) &packet[ip_offset];
    
    if (iph->version == 4) {
      // Prevent underflow
      if (header->len >= ip_offset) {
        result = get_ndpi_flow(header, iph, header->len - ip_offset);
        //printf\("\[NDPI DEBUG\] ndpiGetFlow returning: %p\n", result);
        return result;
      }
    }
  }
  //printf\("\[NDPI DEBUG\] ndpiGetFlow returning: NULL\n");
  return NULL;
}

extern void ndpiFreeFlow(void *flow) {
    //printf\("\[NDPI DEBUG\] ndpiFreeFlow: freeing flow %p\n", flow);
    if (flow != NULL) {
        free(flow);
    } else {
        fprintf(stderr, "[NDPI ERROR] ndpiFreeFlow: attempt to free NULL flow!\n");
    }
}

#else
// nDPI is disabled, so initialization fails

extern int ndpiInitialize() {
    return ERROR_LIBRARY_DISABLED;
}

extern void ndpiDestroy(void) {
}

extern int ndpiPacketProcess(const struct pcap_pkthdr *header, const u_char *packet) {
    return -1;
}

extern void *ndpiGetFlow(const struct pcap_pkthdr *header, const u_char *packet) {
    return NULL;
}

extern void ndpiFreeFlow(void *flow) {
}

#endif
#endif
