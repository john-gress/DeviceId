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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <sched.h>

/* Qosmos ixEngine header */
#include "qmdpi.h"

#include "pdi_common.h"
#include "pdi_device.h"

static struct pdi_thread dev_thread;
static unsigned int thread_num_dpi_worker;

static pthread_barrier_t barrier;
static pthread_barrier_t barrier_dev;

/*
 * Initialize thread context
 */
void thread_init(struct pdi_thread* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cpu_id = -1;
}

int thread_cpu_setaffinity(int cpu_id)
{
    int s;
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    s = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    return s;
}

/*
 * Wait for all threads to terminate
 */
void thread_wait(unsigned int nb_workers)
{
    int ret;
    unsigned int i;

    for (i = 0; i < nb_workers; i++) {
        ret = pthread_join(threads[i].handle, NULL);
        if (ret) {
            printf("ERROR pthread_join[%d] %d\n", i, ret);
        }
        pthread_mutex_destroy(&threads[i].lock);
    }

    ret = pthread_join(dev_thread.handle, NULL);
    if (ret) {
        printf("ERROR pthread_join dev %d\n", ret);
    }
    pthread_mutex_destroy(&dev_thread.lock);
}

/*
 * Send NULL packet to all thread to stop them
 */
void thread_stop(unsigned int nb_workers)
{
    unsigned int i;

    for (i = 0; i < nb_workers; ++i) {
        packet_queue(&threads[i], NULL);
    }

    thread_fifo_push(&device_queue, NULL);
}
/*
 * Enqueue a fingerprint to be processed by the libdevice thread.
 */
void thread_fingerprint_queue(struct qmdev_fingerprint_group *fp_group)
{
    if (fp_group == NULL) {
        return ;
    }

    thread_fifo_push(&device_queue, fp_group);
}

/*
 * DPI and libdevice threads creation
 */
int thread_launch(unsigned int nb_workers, struct qmdpi_engine *engine)
{
    int ret;
    unsigned int i;

    thread_num_dpi_worker = nb_workers;

    /* Initialise thread barriers for dpi threads and device thread. */
    pthread_barrier_init(&barrier, NULL, nb_workers + 1);
    pthread_barrier_init(&barrier_dev, NULL, 2);

    for (i = 0; i < nb_workers; ++i) {
        threads[i].thread_id = i;
        threads[i].worker = qmdpi_worker_create(engine);
        pthread_mutex_init(&threads[i].lock, NULL);
        ret = pthread_create(&threads[i].handle, NULL, dpi_processing_thread_main, &threads[i]);
        if (ret != 0) {
            fprintf(stderr, "ERROR: Starting dpi thread failed.\n");
            return ret;
        }
    }

    /* Launch libdevice thread. */
    dev_thread.cpu_id = i;
    dev_thread.thread_id = i;
    pthread_mutex_init(&dev_thread.lock, NULL);
    ret = pthread_create(&dev_thread.handle, NULL, device_identification_thread_main,
                         &dev_thread);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Starting device thread failed.\n");
        return ret;
    }

    return 0;
}

int thread_packet_loop_function(pcap_t *pcap, void *arg)
{
    return packet_dispatch_loop(pcap, arg);
}

void thread_synchronise(void)
{
    pthread_barrier_wait(&barrier);
}

void thread_synchronise_device(void)
{
    pthread_barrier_wait(&barrier_dev);
}

/*
 * Clean up devices table.
 *
 * The function waits till all threads queues are empty AND
 * threads have finished their processing.
 * It sends pause message and waits they received the message.
 *
 * The function MUST be called from the packet dispatcher thread.
 */
void remove_devices(void)
{
    unsigned int i;

    /* Pause DPI threads */
    for(i = 0; i < thread_num_dpi_worker; i++) {
        packet_queue(&threads[i], THREAD_PAUSE);
    }
    thread_synchronise();

    /* Pause device thread */
    thread_fifo_push(&device_queue, THREAD_PAUSE);
    thread_synchronise_device();

    /* We are good to go ... */
    pdi_device_remove_all();
}

/*
 * Inter thread queue functions
 * It is a single producer - single consumer queue
 */

/*
 * Enqueue packet in thread ring
 */
void packet_queue(struct pdi_thread *thread,
                  struct pdi_pkt *packet)
{
    size_t next_index;

    if (packet != NULL && packet != THREAD_PAUSE) {
        packet->thread_id = thread->thread_id;
    }

    next_index = PACKET_INDEX(thread->write_index + 1);

    while (next_index == thread->read_index) {
        /**
         * Chances are that all thread queues are full. So going to sleep should
         * be ok, letting writer threads a chance to process some packets.
         */
        usleep(10);
    }

    thread->packets[thread->write_index] = packet;

    /**
     * This mutex lock is mainly used as a memory barrier to force reading cpu
     * to get the packet modification before the write_index one.
     */
    pthread_mutex_lock(&thread->lock);
    thread->write_index = next_index;
    pthread_mutex_unlock(&thread->lock);
}

/*
 * Dequeue packet in thread ring
 */
struct pdi_pkt *packet_dequeue(struct pdi_thread *thread)
{
    struct pdi_pkt *packet;

    pthread_mutex_lock(&thread->lock);

    while (thread->read_index == thread->write_index) {
        /**
         * Let other threads go
         */
        pthread_mutex_unlock(&thread->lock);
        sched_yield();
        pthread_mutex_lock(&thread->lock);
    }

    packet = thread->packets[thread->read_index];

    /*
     * Mutex lock is only needed for write index. This is more used as a memory
     * barrier for packet coherency
     */
    thread->read_index = PACKET_INDEX(thread->read_index + 1);
    pthread_mutex_unlock(&thread->lock);

    return packet;
}

/*
 * Inter thread FIFO functions
 * It is a multiple producer - multiple consumer FIFO
 */

void thread_fifo_init(struct thread_fifo *fifo)
{
    fifo->read_index = fifo->write_index = 0;
    pthread_mutex_init(&fifo->mutex, NULL);
    pthread_cond_init(&fifo->not_full, NULL);
    pthread_cond_init(&fifo->not_empty, NULL);
}

void thread_fifo_destroy(struct thread_fifo *fifo)
{
    fifo->read_index = fifo->write_index = 0;
    pthread_mutex_destroy(&fifo->mutex);
    pthread_cond_destroy(&fifo->not_full);
    pthread_cond_destroy(&fifo->not_empty);
}

void thread_fifo_push(struct thread_fifo *fifo, void *ptr)
{
    size_t next_index;

    pthread_mutex_lock(&fifo->mutex);
    while (1) {
        next_index = FIFO_INDEX(fifo->write_index + 1);

        if (next_index == fifo->read_index) {
            pthread_cond_wait(&fifo->not_full, &fifo->mutex);
            continue;
        }
        fifo->data[fifo->write_index] = ptr;
        fifo->write_index = next_index;
        break;
    }

    pthread_cond_broadcast(&fifo->not_empty);
    pthread_mutex_unlock(&fifo->mutex);
}

void *thread_fifo_pop(struct thread_fifo *fifo)
{
    void *data;

    pthread_mutex_lock(&fifo->mutex);

    while (fifo->read_index == fifo->write_index) {
        pthread_cond_wait(&fifo->not_empty, &fifo->mutex);
    }

    data = fifo->data[fifo->read_index];

    fifo->read_index = FIFO_INDEX(fifo->read_index + 1);

    pthread_cond_broadcast(&fifo->not_full);
    pthread_mutex_unlock(&fifo->mutex);

    return data;
}

void thread_fifo_lock(struct thread_fifo *fifo)
{
    pthread_mutex_lock(&fifo->mutex);
}

void thread_fifo_unlock(struct thread_fifo *fifo)
{
    pthread_mutex_unlock(&fifo->mutex);
}
