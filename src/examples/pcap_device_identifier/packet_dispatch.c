/*
  This file is a part of Qosmos Device Identification library

  Copyright Qosmos Tech 2000-2018 - All rights reserved

  This computer program and all its components are protected by
  authors' rights and copyright law and by international treaties.
  Any representation, reproduction, distribution or modification
  of this program or any portion of it is forbidden without
  Qosmos explicit and written agreement and may result in severe
  civil and criminal penalties, and will be prosecuted
  to the maximum extent possible under the law.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <pcap.h>

/* Qosmos ixEngine header */
#include "qmdpi.h"
#include "qmdpi_bundle_api.h"
#include "qmdevice.h"

/* Include Qosmos packets structures. */
#include "packet_helper.h"

#include "pdi_common.h"
#include "pdi_utils.h"
#include "pdi_device.h"

#define LOOP_HEADER_SZ 4
#define LLC_HEADER_SZ 2

/*
 * Global packet number
 */
static uint64_t packet_number;

/*
 * Packet drops before dpi processing
 */
static uint64_t packet_dropped;
static uint64_t packet_filtered;

static struct pdi_pkt *packet_filter_and_build(const struct pcap_pkthdr *phdr,
       const u_char *pdata, int link_mode, int remove_llc, int link_mode_loop);

void reset_packet_counter(void)
{
    packet_number = 0;
}

/*
 * Alloc a new packet
 */
static inline struct pdi_pkt *packet_alloc(uint32_t caplen)
{
    struct pdi_pkt *packet;

    packet = malloc(sizeof(*packet) + caplen);

    if (packet == NULL) {
        fprintf(stderr, "Can't malloc new packet\n");
        return NULL;
    }

    memset(packet, 0, sizeof(*packet));

    packet->len = caplen;
    packet->data = (unsigned char *)(packet + 1);

    return packet;
}

/*
 * Free a packet
 */
void packet_free(struct pdi_pkt *p)
{
    free(p);
}

static inline void packet_get_link_mode(pcap_t *pcap, int *link_mode, int *remove_llc, int *link_mode_loop)
{
    *link_mode = QMDPI_PROTO_ETH;
    *remove_llc = 0;
    *link_mode_loop = 0;

    switch(pcap_datalink(pcap)) {
        case DLT_EN10MB:
            *link_mode = QMDPI_PROTO_ETH;
            break;
        case DLT_RAW:
            *link_mode = QMDPI_PROTO_IP;
            break;
        case DLT_LINUX_SLL:
            *link_mode = QMDPI_PROTO_ETH;
            *remove_llc = 1;
            break;
        case DLT_NULL:
        case DLT_LOOP:
            *link_mode = QMDPI_PROTO_ETH;
            *link_mode_loop = 1;
            break;
        default:
            break;
    }
}

/*
 * The function does some actions according to a device.
 * return 0 if device needs to be processed or device does not exist.
 *        1 otherwise.
 */
static int packet_act_on_device(device_ip_t *device)
{
    if (device && pdi_device_is_identified(device)) {
        /* Device has been identified.
         * We don't want anymore processing so return 1.
         */
        return 1;
    }

    return 0;
}


/*
 * The function checks if a device should be created from this packet.
 * It returns the device associated with
 * packet data. (Here we have only IPv4 addresses, others have already been filtered out)
 *
 * Upon exit *error is set to 1 if an error occurred otherwise 0.
 */
static device_ip_t *packet_check_new_device(struct pdi_pkt *packet, int link_mode, int *error)
{
    uint8_t *frame = packet->data;
    device_ip_t *device_entry = NULL;
    int new_device = 0;

    /* We have an IPv4 frame.
     * Create device if it does not exist.
     */
    uint32_t ip_addr;
    uint8_t *client_mac = NULL;
    uint8_t *addr       = NULL;

    *error = 0;

    if (link_mode == QMDPI_PROTO_ETH) {
        client_mac = &frame[6];
        addr       = &frame[14+12];
    } else if (link_mode == QMDPI_PROTO_IP) {
        const uint8_t dft_mac[6] = { 0, 0, 0, 0, 0, 0 };
        client_mac = (uint8_t *) &dft_mac[0]; /* here for debug purposes. */
        addr       = &frame[12];
    } else {
        /* In the event the device was not found or allocation failed. */
        fprintf(stderr, "[dispatch thread] packet %" PRIu64 " Link_mode not handled, cannot find MAC/IPv4 addrs to allocate device", packet->packet_number);
        *error = 1;
        return NULL;
    }

    memcpy(&ip_addr, addr, 4);

    if (ip_addr) {
        new_device = pdi_device_table_get_entry(ip_addr, &device_entry);
        if (new_device > 0) {
            DBG_PRINTF_1("[dispatch thread] packet %" PRIu64  " New device: " IP4_FMT " (" MAC_FMT ")\n",
                         packet->packet_number,
                         IP4_FMT_ARGS(ip_addr), MAC_FMT_ARGS(*client_mac));
        }

        if (!device_entry) {
            /* In the event the device was not found or allocation failed. */
            fprintf(stderr, "[dispatch thread] packet %" PRIu64 " Couldn't find or allocate device " MAC_FMT  " " IP4_FMT "\n",
                    packet->packet_number, MAC_FMT_ARGS(*client_mac), IP4_FMT_ARGS(ip_addr));
            *error = 1;
            return NULL;
        }
    } else {
        DBG_PRINTF_3("[dispatch thread] packet %" PRIu64  " IP: " IP4_FMT " (" MAC_FMT ")\n",
                     packet->packet_number,
                     IP4_FMT_ARGS(ip_addr), MAC_FMT_ARGS(*client_mac));
    }

    return device_entry;
}


/*
 * Dispatch pcap packets over thread queues
 */
int packet_dispatch_loop(pcap_t *pcap, void *arg)
{
    struct pdi_pkt *packet;
    int link_mode = QMDPI_PROTO_ETH;
    int remove_llc = 0;
    int link_mode_loop = 0;
    struct pcap_pkthdr *phdr;
    const u_char *pdata;
    unsigned int num_workers = *((unsigned int *) arg);

    while (pdi_loop && pcap_next_ex(pcap, &phdr, &pdata) >= 0) {
        ++packet_number;
        packet_get_link_mode(pcap, &link_mode, &remove_llc, &link_mode_loop);
        packet = packet_filter_and_build(phdr, pdata, link_mode, remove_llc, link_mode_loop);
        if (packet == NULL) {
            continue;
        }
        packet->packet_number = packet_number;

        /* Here packets have been filtered to only the L3 protocol we want to handle. */

        /* TODO: put device detection before building the packet. */
        int error = 0;
        struct device_ip *device = packet_check_new_device(packet, link_mode, &error);

        /* Filter packet depending on device. If identified, drop it. */
        int drop = packet_act_on_device(device);
        if (drop || error) {
            DBG_PRINTF_3("[dispatch thread] packet %" PRIu64 " Packet dropped: %s\n",
                         packet->packet_number,
                         error ? "no more device available" :"device not processed any more");
            packet_free(packet);
            continue ;
        }
        packet->device = device;

        /* Dispatch packet */
        uint32_t hashkey = qmdpi_packet_hashkey_get(pdata, phdr->caplen, link_mode);
        packet_queue(&threads[hashkey % num_workers], packet);
    }

    return 0;
}

/*
 * The function checks protocol in the packet and returns:
 * 1 if the packet should be dropped
 * 0 otherwise.
 */
static inline int packet_filter(uint8_t *frame)
{
    int drop = 1;
    uint16_t ethertype;

    /* We suppose we have an ethernet with an EtherType field. */
    ethertype = (frame[12] << 8) + frame[13];

    if (ethertype == 0x0800) {
        drop = 0;
    }

    return drop;
}

/*
 * Initialize packet with data, remove_llc flags
 * indicates if LLC header is present
 */
static struct pdi_pkt *
packet_filter_and_build(const struct pcap_pkthdr *phdr,
                         const u_char *pdata,
                         int link_mode,
                         int remove_llc,
                         int link_mode_loop)
{
    struct pdi_pkt *packet;
    uint32_t caplen;

    if (link_mode_loop && phdr->caplen >= LOOP_HEADER_SZ) {
        uint32_t pf_mode = *(uint32_t *)(pdata);
        if(pf_mode == PF_INET) {
            link_mode = QMDPI_PROTO_IP;
        } else if(pf_mode == PF_INET6) {
            link_mode = QMDPI_PROTO_IP6;
        } else {
            pf_mode = ntohl(pf_mode);
            if(pf_mode == PF_INET) {
                link_mode = QMDPI_PROTO_IP;
            } else if(pf_mode == PF_INET6) {
                link_mode = QMDPI_PROTO_IP6;
            }
        }

        caplen = phdr->caplen - LOOP_HEADER_SZ;
        pdata += LOOP_HEADER_SZ;
    } else if (remove_llc && phdr->caplen >= LLC_HEADER_SZ) {
        caplen = phdr->caplen - LLC_HEADER_SZ;
        pdata += LLC_HEADER_SZ;
    } else {
        caplen = phdr->caplen;
    }

    if (link_mode == QMDPI_PROTO_ETH && packet_filter((uint8_t *) pdata)) {
        ++packet_filtered;
        return NULL;
    }

    packet = packet_alloc(caplen);
    if (packet == NULL) {
        ++packet_dropped;
        return NULL;
    }

    packet->timestamp = phdr->ts;
    packet->link_mode = link_mode;
    packet->len = caplen;

    memcpy(packet->data, pdata, caplen);

    return packet;
}

