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

/* Qosmos ixEngine header */
#include "qmdpi.h"
#include "qmdpi_bundle_api.h"
#include "qmdevice.h"

/* Include Qosmos packets structures. */
#include "packet_helper.h"

#include "pdi_common.h"
#include "pdi_utils.h"
#include "pdi_device.h"

static const struct {
    const char *proto;
    const char *attr;
} attributes[] = {
    { "http",       "user_agent" },
    { "http_proxy", "user_agent" },
    { "http2",      "user_agent" },
    { "quic",       "user_agent" },
    { "dhcp",       "message_type" },
    { "dhcp",       "chaddr" },
    { "dhcp",       "yiaddr" },
    { "dhcp",       "host_name" },
    { "dhcp",       "option_type" },
    { "dhcp",       "option_value_buffer" },
};

/* Qosmos ixEngine main objects */
static struct qmdpi_engine *engine = NULL;
static struct qmdpi_bundle *bundle = NULL;

struct qmdpi_engine *dpi_engine_get(void)
{
    return engine;
}

/* initialize Qosmos ixEngine */
int dpi_engine_init(const char *config)
{
    int ret = 0;
    int i;

    fprintf(stdout, "Initializing ixEngine...");
    fflush(stdout);

    /* create engine instance */
    engine = qmdpi_engine_create(config);
    if (engine == NULL) {
        fprintf(stderr, "ERROR: cannot create engine instance\n");
        return -1;
    }

    /* create bundle instance */
    bundle = qmdpi_bundle_create_from_file(engine, NULL);
    if (bundle == NULL) {
        fprintf(stderr, "ERROR: cannot create bundle instance\n");
        goto error_engine;
    }

    /* activate bundle */
    ret = qmdpi_bundle_activate(bundle);
    if (ret < 0) {
        fprintf(stderr, "ERROR: cannot activate bundle\n");
        goto error_bundle;
    }

    /* enable all signatures on bundle */
    ret = qmdpi_bundle_signature_enable_all(bundle);
    if (ret < 0) {
        fprintf(stderr, "ERROR: error enabling all protocols\n");
        goto error_bundle;
    }

    /* register attributes */
    for(i = 0; i < ARRAY_SIZE(attributes); i++) {
        const char *proto = attributes[i].proto;
        const char *attr  = attributes[i].attr;
        ret = qmdpi_bundle_attr_register(bundle, proto, attr);
        if (ret < 0) {
            fprintf(stderr, "ERROR: cannot add metadata %s:%s\n", proto, attr);
            goto error_bundle;
        }
    }
    fprintf(stdout, "Done.\n");
    fflush(stdout);

    return 0;

error_bundle:
    qmdpi_bundle_destroy(bundle);
error_engine:
    qmdpi_engine_destroy(engine);

    return -1;
}

void dpi_engine_exit(void) {

    fprintf(stdout, "Exiting ixEngine...");
    fflush(stdout);

    qmdpi_bundle_destroy(bundle);
    qmdpi_engine_destroy(engine);

    fprintf(stdout, "Done.\n");
    fflush(stdout);
}


/*
 * DPI processing thread function
 */
void *dpi_processing_thread_main(void *arg)
{
    struct pdi_pkt *pkt;
    struct pdi_thread *ctx = arg;
    int ret;

    ret = thread_cpu_setaffinity(ctx->cpu_id);
    if (ret == 0) {
        fprintf(stdout, "DPI thread %u started (CPU %d)\n", ctx->thread_id+1, ctx->cpu_id);
        fflush(stdout);
    } else {
        fprintf(stderr, "Cannot set affinity for thread %u: %s\n", ctx->thread_id, strerror(ret));
        fprintf(stdout, "DPI thread %u started\n", ctx->thread_id+1);
        fflush(stdout);
    }

    while ((pkt = packet_dequeue(ctx)) != NULL) {
        if (pkt == THREAD_PAUSE) {
            thread_synchronise();
            continue;
        }
        dpi_process_packet(pkt, ctx);
    }

    struct qmdpi_result *result;
    while(qmdpi_flow_expire_next(ctx->worker, NULL, &result) == 0) {
        /* Expire flows. */
    }

    return NULL;
}


/*
 * Main packet processing function
 */
int dpi_process_packet(struct pdi_pkt *pkt, struct pdi_thread *ctx)
{
    int ret;
    ctx->wdata = pkt->data;
    ctx->pkt_nb = pkt->packet_number;
    ctx->device = pkt->device;

    if (pkt->device && pdi_device_is_identified(pkt->device)) {
        /* It's possible there are some packets in the queue corresponding to
         * a device that has been identified in the meantime.
         * The packet is then ignored. */
        packet_free(pkt);
        return 0; /* continue */
    }

    ret = qmdpi_worker_pdu_set(ctx->worker, pkt->data, pkt->len, &pkt->timestamp,
                pkt->link_mode, QMDPI_DIR_DEFAULT, 0);
    if (ret != 0) {
        fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: qmdpi_worker_pdu_set failed (%s)\n",
                        ctx->thread_id+1, ctx->pkt_nb, qmdpi_error_get_string(NULL, ret));
        ++ctx->stats.errors;
        packet_free(pkt);
        return 0; /* continue */
    }

    do {
        struct qmdpi_result *result;
        ret = qmdpi_worker_process(ctx->worker, NULL, &result);
        if (ret < 0  && ret != QMDPI_EFLOW_LOOKUP) {
            fprintf(stderr, "[dpi thread %d] packet %" PRIu64 " ERROR: qmdpi_worker_process failed (%s)\n",
                            ctx->thread_id+1, ctx->pkt_nb, qmdpi_error_get_string(NULL, ret));
            break;
        }
        dpi_engine_process_result(ctx, result);
    } while (ret == QMDPI_PROCESS_MORE);

    /**
     * Get DPI stats
     */
    if (ret < 0) {
        ++ctx->stats.errors;
    } else {
        ++ctx->stats.processed;

        if(ret == QMDPI_PROCESS_IP_DEFRAG_DROP ||
                ret == QMDPI_PROCESS_BOUNDS_FAILURE ||
                ret == QMDPI_PROCESS_BOUNDS_DROP) {
            ++ctx->stats.dropped;
        }
    }

    if(ctx->last_packet_ts < pkt->timestamp.tv_sec) {
        struct qmdpi_result *result;

        int nb_remaining = 100;
        do {
            ret = qmdpi_flow_expire_next(ctx->worker, &pkt->timestamp, &result);
            if(ret != 0) {
                break;
            }

            nb_remaining --;
            dpi_engine_process_result(ctx, result);
        } while (nb_remaining);

        ctx->last_packet_ts = pkt->timestamp.tv_sec;
    }

    packet_free(pkt);

    return 0;
}
