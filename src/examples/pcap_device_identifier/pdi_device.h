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

#ifndef _PDI_DEVICE_TABLE_H_
#define _PDI_DEVICE_TABLE_H_

struct qmdev_instance;
struct device_ip;

typedef struct device_ip device_ip_t;

void pdi_device_table_init(struct qmdev_instance *instance);
void pdi_device_table_destroy(void);

int pdi_device_table_get_entry(uint32_t ip, device_ip_t **current_device_ip_entry);
void pdi_device_table_destroy(void);
int pdi_device_is_identified(device_ip_t *device);

struct qmdev_device_context *pdi_device_get_device_context(device_ip_t *device_ip);
uint32_t pdi_device_get_ip_addr(device_ip_t *device_ip);

int pdi_device_is_identified(device_ip_t *device);
void pdi_device_set_identified(device_ip_t *device,
                               unsigned int score,
                               unsigned int flags,
                               char *buf);

int pdi_device_fetch_and_set_mac_flag(device_ip_t *device);
void pdi_device_remove_all(void);
void pdi_device_dump_table(FILE *out);
#endif /* _PDI_DEVICE_TABLE_H_ */
