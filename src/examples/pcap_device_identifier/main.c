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
#include <signal.h>

#include <pcap.h>

#include "qmdpi.h"
#include "qmdevice.h"

#include "pdi_common.h"
#include "pdi_utils.h"

#include "pdi_device.h"

/* Global variable so the modules can access debug field. */
struct opt pdi_options;

struct pdi_thread *threads;
struct thread_fifo device_queue;

/* Use this variable to stop processing and exit cleanly. */
int pdi_loop = 1;

static FILE *dump_file;

/* Number of device identified. */
uint32_t num_dev_ided = 0;

static struct qmdev_instance *qmdev_instance;
#define BUFFER_SIZE 1024
static char buffer[BUFFER_SIZE];

static pcap_t *pcap_trace_open(const char *filename);
static pcap_t *pcap_trace_get_next(struct opt *opt);
static void pcap_trace_close(pcap_t *p);
static pcap_t *pcap_interface_open(const char *net_if);

static char *dpi_get_config(struct opt *opt);
static char *dev_get_config(struct opt *opt);

static int app_init(struct opt *param);
static void app_exit(struct opt *param);

void sig_handler(int signal)
{
    switch (signal) {
        case SIGUSR1:
            pdi_device_dump_table(stdout);
            break;

        case SIGINT:
            pdi_loop = 0;
            break;
    }
}

void install_sig_handler(void)
{
    struct sigaction sa;

    sa.sa_handler = &sig_handler;

    sa.sa_flags = SA_RESTART;

    sigfillset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("ERROR: can't set handler for SIGUSR1");
    }

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("ERROR: can't set handler for SIGINT");
    }
}

int main(int argc, char *argv[])
{
    int ret;
    pcap_t *pcap = NULL;

    ret = parse_parameters(argc, argv, &pdi_options);
    if (ret < 0) {
        print_usage();
        return 1;
    }

    /* Set default number of threads. */
    if (!pdi_options.num_dpi_workers) {
        pdi_options.num_dpi_workers = NUM_DPI_WORKERS_DEFAULT;
    }

    install_sig_handler();

    ret = app_init(&pdi_options);
    if(ret < 0) {
        return 1;
    }

    ret = thread_launch(pdi_options.num_dpi_workers, dpi_engine_get());
    if (ret < 0) {
        return 1;
    }

    if (pdi_options.live) {
        pcap = pcap_interface_open(pdi_options.pcaps[0]);
    } else {
        pcap = pcap_trace_open(pdi_options.pcaps[0]);
    }
    if (pcap == NULL) {
        return 1;
    }

    /* Loop on packet */
    while (pdi_loop && pcap) {
        thread_packet_loop_function(pcap, &pdi_options.num_dpi_workers);

        pcap_trace_close(pcap);

        if (!pdi_options.live) {
            /* Open next pcap */
            pcap = pcap_trace_get_next(&pdi_options);

            /* Clean up few things. */
            remove_devices();
            num_dev_ided = 0;
            reset_packet_counter();
        }
    }

    thread_stop(pdi_options.num_dpi_workers);
    thread_wait(pdi_options.num_dpi_workers);

    app_exit(&pdi_options);

    return 0;
}

/**
 * Initialize misc modules
 */
static int app_init(struct opt *param)
{
    int ret;
    unsigned int i;
    unsigned int num_threads;

    num_threads = param->num_dpi_workers ? param->num_dpi_workers : 1;

    threads = (struct pdi_thread *) malloc(num_threads * sizeof(*threads));
    if (threads == NULL) {
        fprintf(stderr, "Can't malloc threads\n");
        return -1;
    }

    for (i = 0; i < num_threads; ++i) {
        thread_init(&threads[i]);
        threads[i].cpu_id = i;
    }

    /* Init Qosmos ixEngine */
    ret = dpi_engine_init(dpi_get_config(param));
    if (ret < 0) {
        goto exit_th;
    }

    /* Init libdevice */
    ret = qmdev_instance_create(dev_get_config(param), &qmdev_instance);
    fflush(stdout);
    if (ret != QMDEV_SUCCESS) {
        fprintf(stderr, "Can't initialise libqmdevice: %d\n", ret);
        goto exit_ixe;
    }

    /* Set-up logging of unknown fingerprints. */
    if (pdi_options.csv) {
        dump_file = fopen(pdi_options.csv, "w+");
        if (dump_file == NULL) {
            fprintf(stderr, "Can't open file %s for dumping: %s\n", pdi_options.csv, strerror(errno));
            goto exit_dev;
        }
        ret = qmdev_instance_logger_dump_info_set(qmdev_instance, dump_file, (qmdev_output_fn_t) fprintf);
        if (ret != QMDEV_SUCCESS) {
            fprintf(stderr, "Can't initialise the logger: %d\n", ret);
            if (fclose(dump_file)) {
                fprintf(stderr, "Can't close file %s: %s\n", pdi_options.csv, strerror(errno));
            }
            dump_file = NULL;
            goto exit_dev;
        }
    }

    /* Init devices table. */
    pdi_device_table_init(qmdev_instance);

    /* Init device FIFO queue. */
    thread_fifo_init(&device_queue);

    return 0;

exit_dev:
    qmdev_instance_destroy(qmdev_instance);
exit_ixe:
    dpi_engine_exit();
exit_th:
    free(threads);
    threads = NULL;

    return -1;
}

static void app_exit(struct opt *param)
{
    int i;
    unsigned int nb_workers = param->num_dpi_workers;

    if (!nb_workers) {
        /* There is at least a thread context and a DPI worker. */
        nb_workers++;
    }

    for (i = 0; i < nb_workers; ++i) {
        qmdpi_worker_destroy(threads[i].worker);
    }

    free(threads);
    threads = NULL;

    dpi_engine_exit();

    pdi_device_table_destroy();

    qmdev_instance_destroy(qmdev_instance);
    qmdev_instance = NULL;

    if (dump_file) {
        if (fclose(dump_file)) {
            fprintf(stderr, "Can't close file %s: %s\n", pdi_options.csv, strerror(errno));
        }
    }
}

/*
 * Open a pcap by its filename
 */
static pcap_t *pcap_trace_open(const char *filename)
{
    pcap_t *pcap = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (filename == NULL) {
        return NULL;
    }

    pcap = pcap_open_offline(filename, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "On trace %s, pcap_open: %s\n", filename, errbuf);
        return NULL;
    }
    fprintf(stdout, "Opening trace %s\n", filename);
    fflush(stdout);

    return pcap;
}

static pcap_t *pcap_trace_get_next(struct opt *opt)
{
    pcap_t *pcap = NULL;

    ++opt->pcaps;
    if (opt->pcaps == NULL) {
        return pcap;
    }

    pcap = pcap_trace_open(*opt->pcaps);

    return pcap;
}
/*
 * Close a pcap
 */
static void pcap_trace_close(pcap_t *p)
{
    pcap_close(p);
}

/* open an ethernet interface for packet reading */
static pcap_t *pcap_interface_open(const char *net_if)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;

    /* open interface */
    if (net_if) {
        pcap = pcap_open_live(net_if, 65535, 1, 0, errbuf);

    } else {
        /* check for a default interface */
        char *dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "\rERROR: Couldn't find default device: %s\n", errbuf);
            return NULL;
        }
        fprintf(stdout, "Opening interface %s\n", dev);
        pcap = pcap_open_live(dev, 65535, 1, 0, errbuf);
    }

    if (!pcap) {
        fprintf(stderr, "\rERROR: libpcap: pcap_open(%s): %s\n", net_if, errbuf);
        return NULL;
    }

    return pcap;
}

static char *dpi_get_config(struct opt *opt)
{
    int i;
    int pos = 0;

    pos += snprintf(buffer, BUFFER_SIZE - pos, "injection_mode=packet;");

    for(i = 0; i < opt->dpi_cs.nb; i++) {
        pos += snprintf(buffer + pos,
                        BUFFER_SIZE - pos,
                        "%s%s=%d",
                        pos > 0 ? ";" : "",
                        opt->dpi_cs.config[i].key,
                        opt->dpi_cs.config[i].value);
    }

    if (!opt->dpi_cs.nb) {
        unsigned int num_workers = 1;

        if (opt->num_dpi_workers) {
            num_workers = opt->num_dpi_workers;
        }

        snprintf(buffer + pos, BUFFER_SIZE - pos, "nb_workers=%d;nb_flows=%d",
                               num_workers, NUM_FLOWS_DEFAULT);
    }

    return buffer;
}

static char *dev_get_config(struct opt *opt)
{
    int i;
    int pos = 0;

    for(i = 0; i < opt->dev_cs.nb; i++) {
        pos += snprintf(buffer + pos,
                        BUFFER_SIZE - pos,
                        "%s%s=%d",
                        pos > 0 ? ";" : "",
                        opt->dev_cs.config[i].key,
                        opt->dev_cs.config[i].value);
    }

    if (!opt->dev_cs.nb) {
        snprintf(buffer, BUFFER_SIZE - pos, "nb_unmatched_fingerprints_per_device=%d;nb_device_contexts=%d;nb_devices_per_result=%d",
                               NUM_UNMATCHED_FP_PER_DEV_DEFAULT, NUM_DEVICES_DEFAULT, NUM_RESULTS_DEFAULT);
    }

    return buffer;
}
