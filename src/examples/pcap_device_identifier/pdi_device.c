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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <sys/queue.h>

#include "qmdpi.h"
#include "qmdevice.h"

#include "pdi_common.h"
#include "pdi_utils.h"

#include "pdi_device.h"

#define DEVICE_IP_LOOKUP_HASHSZ (1 << 10)
static SLIST_HEAD (,device_ip) device_ip_hash[DEVICE_IP_LOOKUP_HASHSZ];

/* read-write lock on device_ip linked list */
static pthread_rwlock_t device_ip_hash_rwlock[DEVICE_IP_LOOKUP_HASHSZ] = { PTHREAD_RWLOCK_INITIALIZER };

static struct qmdev_instance *qmdev_instance;

static inline uint64_t get_ip_address_hash_key(uint32_t ip)
{
    uint64_t hash_key = __murmur_hash64((uint8_t*)&(ip), sizeof(uint32_t));

    return hash_key % DEVICE_IP_LOOKUP_HASHSZ;
}


uint32_t pdi_device_get_ip_addr(device_ip_t *device_ip)
{
    return device_ip ? device_ip->ip_addr : 0;
}

struct qmdev_device_context *
pdi_device_get_device_context(device_ip_t *device_ip)
{
    return device_ip->device_context;
}

void pdi_device_table_init(struct qmdev_instance *instance)
{
    int i;
    for (i = 0; i < DEVICE_IP_LOOKUP_HASHSZ; ++i) {
        SLIST_INIT(&device_ip_hash[i]);
    }

    qmdev_instance = instance;
}

void pdi_device_table_destroy(void)
{
    /* Array of linked list heads is statically allocated.
     * But devices need to be destroyed. */
    pdi_device_remove_all();
}

int pdi_device_is_identified(device_ip_t *device)
{
    return device->is_identified;
}

void pdi_device_set_identified(device_ip_t *device,
                               unsigned int score,
                               unsigned int flags,
                               char *buf)
{
    pthread_rwlock_wrlock(&device->rwlock);

    device->is_identified = 1;
    device->score = score;
    device->flags = flags;
    device->detected_time = time(NULL);
    strncpy(device->metadata, buf, 128);
    buf[127] = '\0';

    pthread_rwlock_unlock(&device->rwlock);
}

/*
 * return 1 when a new device has been created, 0 otherwise
 */
int pdi_device_table_get_entry(uint32_t      ip,
                               device_ip_t **device)
{
    int ret = 0;
    uint64_t hash_key = get_ip_address_hash_key(ip);
    device_ip_t *device_entry = NULL;

    if (ip == 0) {
        return 0;
    }

    *device = NULL;

    pthread_rwlock_wrlock(&device_ip_hash_rwlock[hash_key]);

    SLIST_FOREACH(device_entry, &device_ip_hash[hash_key], next) {
        if(device_entry->ip_addr == ip) {
            *device = device_entry;
            break;
        }
    }
    if (!*device) {
        device_ip_t *new_device = NULL;

        new_device = malloc(sizeof(device_ip_t));
        if (new_device == NULL) {
            fprintf(stderr, "ERROR: can't allocate device entry\n");
            pthread_rwlock_unlock(&device_ip_hash_rwlock[hash_key]);
            return 0;
        }

        memset(new_device, 0, sizeof(device_ip_t));

        /* Init lock */
        ret = pthread_rwlock_init(&new_device->rwlock, NULL);
        if (ret < 0) {
            free(new_device);
            fprintf(stderr, "ERROR: can't initialise lock %d\n", ret);
            pthread_rwlock_unlock(&device_ip_hash_rwlock[hash_key]);
            return 0;
        }

        /* Create device context */
        ret = qmdev_device_context_create(qmdev_instance, &new_device->device_context);
        if (ret < 0) {
            pthread_rwlock_destroy(&new_device->rwlock);
            free(new_device);
            fprintf(stderr, "ERROR: can't allocate device context %d\n", ret);
            pthread_rwlock_unlock(&device_ip_hash_rwlock[hash_key]);
            return 0;
        }

        new_device->ip_addr = ip;
        ret = qmdev_device_context_user_handle_set(new_device->device_context, new_device);
        if (ret < 0) {
            qmdev_device_context_destroy(new_device->device_context);
            pthread_rwlock_destroy(&new_device->rwlock);
            free(new_device);
            fprintf(stderr, "ERROR: can't set user_handle %d\n", ret);
            pthread_rwlock_unlock(&device_ip_hash_rwlock[hash_key]);
            return 0;
        }

        SLIST_INSERT_HEAD(&device_ip_hash[hash_key], new_device, next);
        *device = new_device;
        ret = 1;
    }

    pthread_rwlock_unlock(&device_ip_hash_rwlock[hash_key]);

    return ret;
}

int pdi_device_fetch_and_set_mac_flag(device_ip_t *device)
{
    int ret = 0;

    if (device == NULL)
        return 0;

    pthread_rwlock_wrlock(&device->rwlock);
    ret = device->mac_sent;
    if (!ret)
        device->mac_sent = 1;
    pthread_rwlock_unlock(&device->rwlock);

    return ret;
}

void pdi_device_remove_all(void)
{
    int i;
    device_ip_t *device = NULL;

    for (i = 0; i < DEVICE_IP_LOOKUP_HASHSZ; ++i) {
        device = SLIST_FIRST(&device_ip_hash[i]);
        if (device) {
            pthread_rwlock_wrlock(&device_ip_hash_rwlock[i]);

            /* Go through the linked list of device. */
            while (device) {
                device_ip_t *device_next = SLIST_NEXT(device, next);

                /* remove device */
                SLIST_REMOVE(&device_ip_hash[i], device, device_ip, next);

                /* Free allocations. */
                qmdev_device_context_destroy(device->device_context);
                pthread_rwlock_destroy(&device->rwlock);
                free(device);

                device = device_next;
            }

            pthread_rwlock_unlock(&device_ip_hash_rwlock[i]);
        }
    }
}

void pdi_device_dump_table(FILE *out)
{
    int i;
    device_ip_t *device = NULL;

    fprintf(out, "%-16s Score OS vendor:OS name:OS version:vendor:model:type:nic\n", "IP address");

    for (i = 0; i < DEVICE_IP_LOOKUP_HASHSZ; ++i) {
        int j = 0;
        SLIST_FOREACH(device, &device_ip_hash[i], next) {
            char str[20];
            char t[20] = { 0 };

            j++;
            snprintf(str, 20, IP4_FMT, IP4_FMT_ARGS(device->ip_addr));
            if (device->is_identified) {
                struct tm *tm;
                tm = localtime(&device->detected_time);
                strftime(t, 26, " %Y:%m:%d %H:%M:%S", tm);
            }

            fprintf(out, "%-16s %3u   %s%s\n", str, device->score, device->metadata, t);
        }
    }
    fflush(out);
}
