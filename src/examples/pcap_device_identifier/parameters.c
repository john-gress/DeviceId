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
#include <getopt.h>

#include "qmdpi.h"

#include "pdi_common.h"


static int parse_config(char *optarg, struct config_store *cs);


#define EXE_NAME  "pcap_device_identifier"

void print_usage(void)
{
    printf("Usage:\n\t%s [options] pcap_files|interface\n\n", EXE_NAME);
    printf("Options:\n"
           "\t--dpi_config <key>=<value>    Set ixEngine configuration value\n"
           "\t--dev_config <key>=<value>    Set libqmdevice configuration value\n"
           "\t--live                        Live capture from interface instead of pcap_files.\n"
           "\t                              By default tries the first interface if none given\n"
           "\t--csv <file>                  Set output CSV file path (default: ./output.csv)\n"
          );
}

int parse_parameters(int argc, char *argv[], struct opt *opt)
{
    int ret = 0;
    int c, opti;
    unsigned int num_params = 1;

    static struct option opts[] = {
        {"dpi_config", 1, 0, 'i'},
        {"dev_config", 1, 0, 'e'},
        {"live"      , 0, 0, 'l'},
        {"csv"       , 1, 0, 'c'},
        {"dpi_thread", 1, 0, 'p'},
        {0, 0, 0, 0},
    };

    memset(opt, 0, sizeof(*opt));

    while ((c = getopt_long(argc, argv, "v", opts, &opti)) != -1) {
        ret = 0;
        switch (c) {
            case 'v':
                opt->v++;
                num_params++;
                break;
            case 'i':
                ret = parse_config(optarg, &opt->dpi_cs);
                num_params += 2;
                break;
            case 'e':
                ret = parse_config(optarg, &opt->dev_cs);
                num_params += 2;
                break;
            case 'c':
                opt->csv = optarg;
                num_params += 2;
                break;
            case 'l':
                opt->live = 1;
                num_params++;
                break;
            case 'p':
                opt->num_dpi_workers = (unsigned int) atoi(optarg);
                num_params += 2;
                break;
            default: /* '?' */
                /* unknown option */
                ret = -1;
                break;
        }
        if (ret) {
            return -1;
        }
    }

    /* Check params for live or pcap files. */
    opt->num_pcap = argc - num_params;
    if (opt->num_pcap == 0 && !opt->live) {
        /* Only live options allows no interface or pcap */
        ret = -1;
    } else if (opt->num_pcap > 1 && opt->live) {
        /* live option takes one or none argument. */
        ret = -1;
    } else if (opt->num_pcap < 0) {
        /* No files specified. */
        ret = -1;
    } else {
        ret = 0;
        opt->pcap_if_index = num_params;
        opt->pcaps = &argv[num_params];
    }

    return ret;
}

#define CONFIG_SET(c, k, v) do {                                        \
    (c)->key = k;                                                       \
    (c)->value = v;                                                     \
} while(0)

#define CONFIG_STORE_ADD(hc, k, v) do {                                 \
    if((hc)->nb == MAX_CONFIG) {                                        \
        fprintf(stderr,                                                 \
                    "Max config reached; cannot add config %s=%d",      \
                    k, v);                                              \
    } else {                                                            \
        CONFIG_SET(&((hc)->config[(hc)->nb]), k, v);                    \
        ++(hc)->nb;                                                     \
    }                                                                   \
} while(0)

static int parse_config(char *optarg, struct config_store *cs)
{
    char *start;
    char *saveptr = NULL;
    char *token;

    for(start = optarg; (token = strtok_r(start, ";", &saveptr)) != NULL; start = NULL) {
        char *key = strtok(token, "=");
        char *value = strtok(NULL, ";");
        if(key == NULL || value == NULL) {
            fprintf(stderr, "Unable to parse configuration value `%s'\n", optarg);
            return -1;
        }
        CONFIG_STORE_ADD(cs, key, atoi(value));
    }

    return 0;
}
