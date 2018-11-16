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
#include <inttypes.h>

#include <arpa/inet.h>

/* Qosmos ixEngine header */
#include "qmdpi.h"
#include "qmdpi_bundle_api.h"
#include "qmdevice.h"

/* Include Qosmos packets structures. */
#include "packet_helper.h"

#include "pdi_common.h"
#include "pdi_utils.h"
#include "pdi_device.h"

#define DHCP_MESSAGE_REQUEST                     3

#define DHCP_HOST_NAME                          12
#define DHCP_REQUESTED_IP_ADDR                  50
#define DHCP_PARAMETER_REQUEST_LIST             55
#define DHCP_VENDOR_CLASS_IDENTIFIER            60

#define DHCP_GET_OPTION_TYPE(attr_value) ( *(uint8_t *) (attr_value) )
#define DHCP_GET_MESSAGE_TYPE(attr_value) ( *(int *) (attr_value) )

struct pdi_attr_result {
    const char *value;
    int         proto_id;
    int         id;
    int         value_len;
    int         flags;
};

/*
 * The function adds a fingerprint to a group.
 * If the group does not exist, it creates one then adds the attributes.
 * On error, if the fingerprint group was created in this call, the allocated
 * data are destroyed and *fp_group_p is NULL.
 */
static void dpi_engine_add_fingerprint(struct pdi_thread               *ctx,
                                       device_ip_t                     *device,
                                       struct qmdev_fingerprint_group **fp_group_p,
                                       unsigned int                     deep_copy,
                                       unsigned int                     proto_id,
                                       unsigned int                     attr_id,
                                       unsigned int                     attr_flags,
                                       unsigned int                     attr_value_len,
                                       const char                      *attr_value)
{
#define FP_FMT   "%u:%u %u - %u - %u %.*s"
#define FP_ARGS  proto_id, attr_id, deep_copy, attr_flags, attr_value_len, attr_value_len, attr_value

    int ret = 0;
    struct qmdev_device_context *device_context;
    int created = 0;

    if (device == NULL) {
        fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: device is NULL\n", ctx->thread_id+1, ctx->pkt_nb);
        return ;
    }

    device_context = pdi_device_get_device_context(device);

    if (*fp_group_p == NULL) {
        created = 1;

        ret = qmdev_fingerprint_group_create(device_context, fp_group_p);
        if (ret) {
            fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: Can't create fingerprint group (%d) " FP_FMT "\n",
                            ctx->thread_id+1, ctx->pkt_nb, ret, FP_ARGS);
            *fp_group_p = NULL;
        }
    }
    struct qmdev_fingerprint_group *fp_group = *fp_group_p;

    ret = qmdev_fingerprint_set(fp_group, deep_copy, proto_id, attr_id, attr_flags,
                                attr_value_len, attr_value);
    if (ret) {
        /* NOTE: if the fingerprint can't be set, shall we destroy the group ? */
        if (created) {
            /* Destroy group if it was created now. */
            qmdev_fingerprint_group_destroy(fp_group);
            *fp_group_p = NULL;
        }
        fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: Can't set fingerprint (%d) " FP_FMT "\n",
                        ctx->thread_id+1, ctx->pkt_nb, ret, FP_ARGS);
    }

    /* All went well. */
    DBG_PRINTF_2("[dpi thread %d] packet %" PRIu64 " fingerprint added: " FP_FMT "\n",
                 ctx->thread_id+1, ctx->pkt_nb, FP_ARGS);
    fflush(stdout);
}

/* For DHCP: we need to extract:
 * + message type DHCP REQUEST
 *   - chaddr
 *   - host name
 *   - option 50: requested IP address (to create new device)
 *   - option 55: parameter request list
 *   - option 60: vendor class indentifier
 */
static int dpi_engine_handle_dhcp(struct pdi_thread      *ctx,
                                  device_ip_t           **device_entry_p,
                                  struct qmdev_fingerprint_group **fp_group_p,
                                  struct qmdpi_result    *result,
                                  struct pdi_attr_result *attr)
{
    uint32_t ip_addr = 0;
    uint8_t mac[6] = { 0 };
    struct pdi_attr_result options[4]; /* chaddr, host_name, opt: 55, 60 */
    unsigned int num_options = 0;
    unsigned int last_option = 0;
    unsigned int message_type = 0;

    memset(options, 0, sizeof(options));

    do {
        if (attr->proto_id != Q_PROTO_DHCP) {
            break;
        }

        if (attr->id == Q_DHCP_OPTION_TYPE) {
            last_option = DHCP_GET_OPTION_TYPE(attr->value);

        } else if (attr->id == Q_DHCP_MESSAGE_TYPE) {
            message_type = DHCP_GET_MESSAGE_TYPE(attr->value);

        } else if (attr->id == Q_DHCP_CHADDR) {
            options[num_options++] = *attr;
            memcpy(mac, attr->value, 6);

        } else if (attr->id == Q_DHCP_HOST_NAME) {
            options[num_options++] = *attr;

        } else if (attr->id == Q_DHCP_OPTION_VALUE_BUFFER) {
            switch (last_option) {
                case DHCP_REQUESTED_IP_ADDR:
                    memcpy(&ip_addr, attr->value, 4);
                    break;
                case DHCP_PARAMETER_REQUEST_LIST:
                    attr->id = Q_DHCP_PARAMETER_REQUEST_LIST;
                    options[num_options++] = *attr;
                    break;
                case DHCP_VENDOR_CLASS_IDENTIFIER:
                    attr->id = Q_DHCP_VENDOR_CLASS_IDENTIFIER;
                    options[num_options++] = *attr;
                    break;
                default:
                    break;
            }
        }
    }
    while(qmdpi_result_attr_getnext(result, &attr->proto_id, &attr->id,
                                    &attr->value, &attr->value_len, &attr->flags) == 0);

    /* We have saved the attributes we were interested in, now use them. */
    if (message_type == DHCP_MESSAGE_REQUEST && ip_addr) {

        /* Check if we need to create a new device. */
        int new_device = 0;
        device_ip_t *device_entry_tmp = *device_entry_p;
        new_device = pdi_device_table_get_entry(ip_addr, device_entry_p);

        if (*device_entry_p == NULL) {
            fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: no more device available\n",
                    ctx->thread_id+1, ctx->pkt_nb);
            return 0;
        }

        if (device_entry_tmp && device_entry_tmp != *device_entry_p) {
            fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " WARNING: something is odd %d %s\n",
                    ctx->thread_id+1, ctx->pkt_nb, __LINE__, __FILE__);
            return 0;
        }

        DBG_PRINTF_2("[dpi thread %d] packet %" PRIu64 " DHCPREQ %d - %u - " IP4_FMT " " MAC_FMT  " \n",
                     ctx->thread_id+1, ctx->pkt_nb, new_device, num_options, IP4_FMT_ARGS(ip_addr), MAC_FMT_ARGS(mac));

        int i;
        for(i = 0; i < num_options; i++) {
            dpi_engine_add_fingerprint(ctx, *device_entry_p, fp_group_p, QMDEV_DEEP_COPY,
                                       (unsigned) options[i].proto_id,
                                       (unsigned) options[i].id,
                                       (unsigned) options[i].flags,
                                       (unsigned) options[i].value_len,
                                       options[i].value);
        }

    }
    return 0;
}

#include "dpi_handle_tcp.h"

/*
 * DPI processing function.
 * Extract attributes from packets, create and dispatch fingerprints.
 */
void dpi_engine_process_result(struct pdi_thread   *ctx,
                               struct qmdpi_result *result)
{
    struct qmdpi_flow *f = qmdpi_result_flow_get(result);
    struct qmdpi_result_flags const *result_flags = qmdpi_result_flags_get(result);
    device_ip_t *device_entry = ctx->device;
    struct qmdev_fingerprint_group *fp_group = NULL;
    struct pdi_attr_result attr;
    int dhcp_seen = 0;

    if (f == NULL || result_flags == NULL) {
        return;
    }

    /* device_entry may be NULL in case of DHCP. */
    if (device_entry && !QMDPI_RESULT_FLAGS_FLOW_EXPIRED(result_flags)) {
        dpi_handle_tcp(ctx, device_entry, &fp_group, result, &attr);
    }

    while(qmdpi_result_attr_getnext(result, &attr.proto_id, &attr.id,
                                    &attr.value, &attr.value_len, &attr.flags) == 0) {

        if (attr.proto_id == Q_PROTO_DHCP) {
            dhcp_seen = 1;
            dpi_engine_handle_dhcp(ctx, &device_entry, &fp_group, result, &attr);
            /* note: device_entry may be NULL here. */
        } else {
            dpi_engine_add_fingerprint(ctx, device_entry, &fp_group, QMDEV_DEEP_COPY,
                                       attr.proto_id, attr.id, attr.flags, attr.value_len, attr.value);
        }
    }

    /* Send mac address only once: if no dhcp or if ethernet mac has not been sent. */
    if (device_entry && (!dhcp_seen && !pdi_device_fetch_and_set_mac_flag(device_entry))) {
        dpi_engine_add_fingerprint(ctx, device_entry, &fp_group, QMDEV_DEEP_COPY,
                                   Q_PROTO_ETH, Q_ETH_ADDRESS, 0, 6, (const char *) &ctx->wdata[6]);
    }

    if (fp_group != NULL) {
        /* process fp: send to device thread.
         * fp_group will be destroyed in the processing thread. */
        thread_fingerprint_queue(fp_group);
    }

    return ;
}
