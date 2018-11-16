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

#ifndef __PDI_UTILS_H__
#define __PDI_UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

struct device_ip {
    SLIST_ENTRY(device_ip) next;
    uint32_t               ip_addr;
    uint8_t                mac_addr[6];
    uint8_t                is_identified:1;
    uint8_t                mac_sent:1;
    unsigned int           score;
    unsigned int           flags;
    time_t                 detected_time;
    char                   metadata[128];
    struct qmdev_device_context *device_context;
    pthread_rwlock_t       rwlock;//read-write lock on device_ip struct
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define IP_STRING(ip) \
    ((uint8_t*) &(ip))[0], ((uint8_t*) &(ip))[1], ((uint8_t*) &(ip))[2], ((uint8_t*) &(ip))[3]

#define MAC_STRING(mac) \
        ((uint8_t*)&mac)[0], ((uint8_t*)&mac)[1], ((uint8_t*)&mac)[2], ((uint8_t*)&mac)[3], ((uint8_t*)&mac)[4], ((uint8_t*)&mac)[5]

#define PRINTF_IP(ip) \
        PRINTF_DEBUG("IP: %hhu.%hhu.%hhu.%hhu\n",((uint8_t*) &(ip))[0], ((uint8_t*) &(ip))[1], ((uint8_t*) &(ip))[2], ((uint8_t*) &(ip))[3])

#define IP4_FMT_A "%3hhu.%3hhu.%3hhu.%3hhu"
#define IP4_FMT "%hhu.%hhu.%hhu.%hhu"
#define IP4_FMT_ARGS(ip) \
    ((uint8_t*) &(ip))[0], ((uint8_t*) &(ip))[1], ((uint8_t*) &(ip))[2], ((uint8_t*) &(ip))[3]

#define MAC_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MAC_FMT_ARGS(mac) \
        ((uint8_t*)&mac)[0], ((uint8_t*)&mac)[1], ((uint8_t*)&mac)[2], ((uint8_t*)&mac)[3], ((uint8_t*)&mac)[4], ((uint8_t*)&mac)[5]


#define DBG_PRINTF_0(...) do { \
                              fprintf(stdout, __VA_ARGS__); \
                          } while (0)

#define DBG_PRINTF_1(...) do { \
                              if (pdi_options.v >= 1) {\
                                  fprintf(stdout, __VA_ARGS__); \
                              }; \
                          } while (0)

#define DBG_PRINTF_2(...) do { \
                              if (pdi_options.v >= 2) {\
                                  fprintf(stdout, __VA_ARGS__); \
                              }; \
                          } while (0)

#define DBG_PRINTF_3(...) do { \
                              if (pdi_options.v >= 3) {\
                                  fprintf(stdout, __VA_ARGS__); \
                              }; \
                          } while (0)

#define DBG_GET_LEVEL()   (pdi_options.v)

uint64_t __murmur_hash64(const uint8_t *data, unsigned long len) __attribute__((weak));
uint64_t __murmur_hash64(const uint8_t *data, unsigned long len)
{
    const uint64_t m = 0xc6a4a7935bd1e995ull;
    const int r = 47;
    const unsigned int seed = 0x9747b28c;

    uint64_t h = seed ^ (len * m);

    const uint64_t * lptr = (const uint64_t *)data;
    unsigned int lstep = len / sizeof(*lptr);

    while(lstep--)
    {
        uint64_t k = *lptr++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    data = (const uint8_t *)lptr;

    switch(len % sizeof(*lptr))
    {
        case 7: h ^= (uint64_t)(data[6]) << 48;
        case 6: h ^= (uint64_t)(data[5]) << 40;
        case 5: h ^= (uint64_t)(data[4]) << 32;
        case 4: h ^= (uint64_t)(data[3]) << 24;
        case 3: h ^= (uint64_t)(data[2]) << 16;
        case 2: h ^= (uint64_t)(data[1]) << 8;
        case 1: h ^= (uint64_t)(data[0]);
                h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;
    return h;
}

#endif
