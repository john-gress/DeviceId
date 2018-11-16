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

#ifndef __PDI_COMMON_H__
#define __PDI_COMMON_H__

#include <pthread.h>
#include <pcap.h>

#define NUM_DPI_WORKERS_DEFAULT     2
#define NUM_FLOWS_DEFAULT         100

#define NUM_UNMATCHED_FP_PER_DEV_DEFAULT 1
#define NUM_RESULTS_DEFAULT              5
#define NUM_DEVICES_DEFAULT              10000

#define DEVICE_DEFAULT_SCORE       75
#define FINGERPRINT_MATCHED_COUNT   5

/**
 * Structure that keeps configuration value
 */
struct config {
    char *key;
    int value;
};

#define MAX_CONFIG   64

/**
 * Structure that keeps configuration value list
 */
struct config_store {
    struct config config[MAX_CONFIG];
    size_t nb;
};

struct opt {
    struct config_store dpi_cs;
    struct config_store dev_cs;
    char           *csv;
    char          **pcaps;
    int             pcap_if_index;
    int             num_pcap;
    unsigned int    num_dpi_workers;
    int             live;      /* boolean 1: net interface, 0: pcap files */
    int             v;
};


struct device_ip;
/*
 * Packet definition
 */
struct pdi_pkt {
    uint64_t          packet_number;
    uint8_t          *data;
    int32_t           len;
    struct timeval    timestamp;
    int32_t           link_mode;
    int32_t           thread_id;
    struct device_ip *device;
};


struct pdi_dpi_stats {
    uint64_t processed;
    uint64_t errors;
    uint64_t dropped;
};

#define THREAD_PAUSE  ((void *) 0x0001)

/* Simple FIFO of pointers for inter-thread communication.
 * 1 consummer, multiple producers. */
#define FIFO_INDEX(_value)  ((_value) & FIFO_QUEUEMASK)
#define FIFO_QUEUESZ        (1 << 13)
#define FIFO_QUEUEMASK      (FIFO_QUEUESZ - 1)
struct thread_fifo {
    void              *data[FIFO_QUEUESZ];
    size_t             read_index;
    size_t             write_index;
    pthread_mutex_t    mutex;
    pthread_cond_t     not_full;
    pthread_cond_t     not_empty;
};

#define PACKET_INDEX(_value)  ((_value) & PACKET_QUEUEMASK)
#define PACKET_QUEUESZ        (1 << 13)
#define PACKET_QUEUEMASK      (PACKET_QUEUESZ - 1)
struct pdi_thread {
    uint8_t              *wdata; /* worker data pointer
                                    that reference current
                                    pkt data to get mac address */
    struct qmdpi_worker  *worker;
    pthread_t             handle;         /* thread handle */
    int                   thread_id;
    int                   cpu_id;
    struct device_ip     *device;
    size_t                read_index;
    size_t                write_index;
    uint64_t              pkt_nb;
    uint64_t              last_packet_ts;
    pthread_mutex_t       lock;
    struct pdi_dpi_stats  stats;
    struct pdi_pkt       *packets[PACKET_QUEUESZ];
};

struct pdi_dev_ctx {
    pthread_t             handle;         /* thread handle */
    int                   thread_id;
    int                   cpu_id;
};


extern int pdi_loop;
extern uint32_t num_dev_ided;
extern struct opt pdi_options;
extern struct pdi_thread *threads;
extern struct thread_fifo device_queue;

void thread_init(struct pdi_thread* th);
void thread_wait(unsigned int nb_workers);
void thread_stop(unsigned int nb_workers);
void thread_synchronise(void);
void thread_synchronise_device(void);
int thread_cpu_setaffinity(int cpu_id);

int thread_packet_loop_function(pcap_t *pcap, void *arg);

struct qmdpi_engine;
int thread_launch(unsigned int nb_workers, struct qmdpi_engine *engine);
int packet_dispatch_loop(pcap_t *pcap, void *arg);
void reset_packet_counter(void);

int packet_dispatch_loop_amp(pcap_t *pcap, void *arg);

void thread_fifo_init(struct thread_fifo *queue);
void thread_fifo_destroy(struct thread_fifo *queue);
void thread_fifo_push(struct thread_fifo *queue, void *ptr);
void *thread_fifo_pop(struct thread_fifo *queue);
void thread_fifo_lock(struct thread_fifo *queue);
void thread_fifo_unlock(struct thread_fifo *queue);

struct qmdev_fingerprint_group;
void pdi_dev_thread_process_fingerprint(struct qmdev_fingerprint_group *fp_group);
void *device_identification_thread_main(void *arg);
void device_identification_process_fingerprint(struct qmdev_fingerprint_group *fp_group);
void thread_fingerprint_queue(struct qmdev_fingerprint_group *fp_group);

void print_usage(void);
int parse_parameters(int argc, char *argv[], struct opt *opt);

int dpi_engine_init(const char *config);
void dpi_engine_exit(void);
struct qmdpi_engine *dpi_engine_get(void);
struct qmdpi_result;
void dpi_engine_process_result(struct pdi_thread *th,
                               struct qmdpi_result *result);

void packet_queue(struct pdi_thread *thread, struct pdi_pkt *packet);
struct pdi_pkt *packet_dequeue(struct pdi_thread *thread);
void packet_free(struct pdi_pkt *p);

int dpi_process_packet(struct pdi_pkt *pkt, struct pdi_thread *ctx);
void *dpi_processing_thread_main(void *arg);

void remove_devices(void);
#endif /* __PDI_COMMON_H__ */
