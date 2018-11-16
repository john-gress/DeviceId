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

#include "qmdevice.h"

#include "pdi_common.h"
#include "pdi_utils.h"
#include "pdi_device.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static void output_identification(FILE *out, const char *value[]);
static void metadata_to_string(char *buf, unsigned int size, const char *value[]);

static const int metadata[QMDEV_MAX_METADATA_ID] = {
    [QMDEV_NIC_VENDOR] = QMDEV_NIC_VENDOR,
    [QMDEV_VENDOR]     = QMDEV_VENDOR,
    [QMDEV_MODEL]      = QMDEV_MODEL,
    [QMDEV_OS]         = QMDEV_OS,
    [QMDEV_OS_VERSION] = QMDEV_OS_VERSION,
    [QMDEV_OS_VENDOR]  = QMDEV_OS_VENDOR,
    [QMDEV_TYPE]       = QMDEV_TYPE
};

static const char *metadata_string[QMDEV_MAX_METADATA_ID] = {
    [QMDEV_NIC_VENDOR] = "nic_vendor",
    [QMDEV_VENDOR]     = "device_vendor",
    [QMDEV_MODEL]      = "device_model",
    [QMDEV_OS]         = "os_name",
    [QMDEV_OS_VERSION] = "os_version",
    [QMDEV_OS_VENDOR]  = "os_vendor",
    [QMDEV_TYPE]       = "device_type"
};

/*
 * Device identification thread function
 */
void *device_identification_thread_main(void *arg)
{
    int ret;
    struct pdi_thread *ctx = arg;

    ret = thread_cpu_setaffinity(ctx->cpu_id);
    if (ret == 0) {
        fprintf(stdout, "Device thread started (CPU %d)\n", ctx->cpu_id);
        fflush(stdout);
    } else {
        fprintf(stderr, "ERROR: Can not set affinity for thread %u: %s\n", ctx->thread_id, strerror(ret));
        fprintf(stdout, "Device thread started\n");
        fflush(stdout);
    }

    while (1) {
        /* Get data pointer from FIFO. */
        struct qmdev_fingerprint_group *fp_group = thread_fifo_pop(&device_queue);

        if (fp_group == THREAD_PAUSE) {
            thread_synchronise_device();
            continue;
        }

        if (fp_group == NULL) {
            break;
        }

        device_identification_process_fingerprint(fp_group);
    }

    fprintf(stdout, "Device thread exiting.\n");

    return NULL;
}

/*
 * fingerprint group processing and identification management function.
 */
void device_identification_process_fingerprint(struct qmdev_fingerprint_group *fp_group)
{
    int ret;
    unsigned int flags;
    struct qmdev_result *result;
    struct qmdev_device_context *device_context = NULL;
    struct device_ip *device_ip = NULL;

    if (fp_group == NULL) {
        return ;
    }

    ret = qmdev_fingerprint_group_device_context_get(fp_group, &device_context);
    if (ret != QMDEV_SUCCESS) {
        fprintf(stderr, "ERROR: can't get device context (%d)\n", ret);
        goto fpg_destroy;
    }
    ret = qmdev_device_context_user_handle_get(device_context, (void **) &device_ip);
    if (ret != QMDEV_SUCCESS) {
        fprintf(stderr, "ERROR: can't get user handle (%d)\n", ret);
        goto fpg_destroy;
    }

    /* A device could have been identified while some fingerprint groups are still in the queue.
     * If this occurs, don't process its fingerprint.
     */
    if (pdi_device_is_identified(device_ip)) {
        goto fpg_destroy;
    }

    ret = qmdev_device_process(fp_group, &result, &flags);
    if (ret != QMDEV_SUCCESS) {
        fprintf(stderr, "[device thread] ERROR: fingerprint processing. (%s)\n",
                        qmdev_error_get_string(ret));
        goto fpg_destroy;
    }

    struct qmdev_result_device *device = NULL;
    unsigned int score;
    unsigned int dev_flags;
    uint32_t ip = pdi_device_get_ip_addr(device_ip);

    while (qmdev_result_device_get_next(result, &device, &score, &dev_flags) == QMDEV_SUCCESS) {
        if (device == NULL) {
            break;
        }

        char buffer[256];
        const char *metadata_value[QMDEV_MAX_METADATA_ID];
        unsigned int metadata_value_id[QMDEV_MAX_METADATA_ID];
        unsigned int m_length;
        unsigned int m_flags;
        int i;

        /* Get all the metadata.
         * (we don't care about length and flags so there are overwritten each time)
         */
        for(i=0; i < ARRAY_SIZE(metadata); i++) {
            ret = qmdev_result_device_metadata_get(device, metadata[i],
                                                   &metadata_value_id[metadata[i]],
                                                   &metadata_value[metadata[i]],
                                                   &m_length,
                                                   &m_flags);
            if (ret != QMDEV_SUCCESS) {
                fprintf(stderr, "ERROR: qmdev_result_device_metadata_get() returned %d\n", ret);
            }
        }

        metadata_to_string(buffer, 256, metadata_value);

        unsigned int fp_matched = 0;
        ret = qmdev_device_context_fingerprint_get_count(device_context, 0, 0,
                                       QMDEV_NB_MATCHED_FINGERPRINTS, &fp_matched);
        if (ret != QMDEV_SUCCESS) {
            fprintf(stderr, "ERROR: qmdev_device_context_fingerprint_get_count() returned %d\n", ret);
        }

        /* We consider the device identified if:
         * + the score is above a certain threshold
         * + AND the number of fingerprints successfully matched is above a certain number. */
        if (score >= DEVICE_DEFAULT_SCORE && fp_matched >= FINGERPRINT_MATCHED_COUNT) {
            pdi_device_set_identified(device_ip, score, dev_flags, buffer);
            num_dev_ided++;

            output_identification(stdout, metadata_value);
        }

        DBG_PRINTF_1("[device thread] " IP4_FMT " %s: score %u (osv:os:osver:v:m:t:nic) - %s\n",
                     IP4_FMT_ARGS(ip),
                     score >= DEVICE_DEFAULT_SCORE ? "identified" : "result",
                     score, buffer);

        if (score >= DEVICE_DEFAULT_SCORE) {
            /* We are not interested in other results, exit loop. */
            break;
        }
    }

fpg_destroy:
    ret = qmdev_fingerprint_group_destroy(fp_group);
    if (ret) {
        fprintf(stderr, "[device thread] ERROR, can't destroy fingerprint group. (%d)\n", ret);
    }
}

static void output_identification(FILE *out, const char *value[])
{
    int i;
    for(i = 0; i < QMDEV_MAX_METADATA_ID; i++) {
        if (value[i]) {
            fprintf(out, "d(%d)/%s=%s\n", num_dev_ided, metadata_string[i], value[i]);
        }
    }
}

static void metadata_to_string(char *buf, unsigned int size, const char *value[])
{
    snprintf(buf, size, "%s:%s:%s:%s:%s:%s:%s",
             value[QMDEV_OS_VENDOR]  ? value[QMDEV_OS_VENDOR]  : "",
             value[QMDEV_OS]         ? value[QMDEV_OS]         : "",
             value[QMDEV_OS_VERSION] ? value[QMDEV_OS_VERSION] : "",
             value[QMDEV_VENDOR]     ? value[QMDEV_VENDOR]     : "",
             value[QMDEV_MODEL]      ? value[QMDEV_MODEL]      : "",
             value[QMDEV_TYPE]       ? value[QMDEV_TYPE]       : "",
             value[QMDEV_NIC_VENDOR] ? value[QMDEV_NIC_VENDOR] : "");
}
