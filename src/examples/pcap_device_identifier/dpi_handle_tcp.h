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

#ifndef __DPI_HANDLE_TCP__
#define __DPI_HANDLE_TCP__

#define TCP_HEADER_OPTIONS_LENGTH(tcp_hdr)  ( (unsigned int) ( (tcp_hdr->doff << 2) - 20) )

/*
 * Add fingerprint for TCP window size and TCP header options
 */
static inline void dpi_handle_tcp(struct pdi_thread               *ctx,
                                  device_ip_t                     *device_entry,
                                  struct qmdev_fingerprint_group **fp_group_p,
                                  struct qmdpi_result             *result,
                                  struct pdi_attr_result          *attr)
{
    int proto_id;
    struct qmdpi_worker *worker = ctx->worker;
    int ind;

    for(ind = 0; (proto_id = qmdpi_worker_pdu_ntuple_get_proto(worker, ind)) > 0; ind++) {
        if (proto_id == Q_PROTO_TCP) {
            struct qm_tcp_hdr *tcp = NULL;

            /* When new TCP connection: add window size and tcp options if any. */
            tcp = (struct qm_tcp_hdr *)qmdpi_worker_pdu_ntuple_get_header(worker, ind);
            if(tcp->syn && !tcp->ack) {
                dpi_engine_add_fingerprint(ctx, device_entry, fp_group_p, QMDEV_DEEP_COPY,
                                           Q_PROTO_TCP, Q_TCP_WINDOW, 0, 2,
                                           (const char *) &tcp->window);

                DBG_PRINTF_2("[dpi thread %d] packet %" PRIu64 " Window size: %u\n",
                             ctx->thread_id+1, ctx->pkt_nb, (unsigned) ntohs(tcp->window));

                if (tcp->doff) {
                    /* TCP options present. Add them. */
                    dpi_engine_add_fingerprint(ctx, device_entry, fp_group_p, QMDEV_DEEP_COPY,
                            Q_PROTO_TCP, Q_TCP_HEADER_OPTIONS, 0,
                            TCP_HEADER_OPTIONS_LENGTH(tcp), (const char *) (tcp + 1));

                    DBG_PRINTF_2("[dpi thread %d] packet %" PRIu64 " TCP options: %u - %02hhx %02hhx %02hhx %02hhx\n",
                                 ctx->thread_id+1, ctx->pkt_nb, TCP_HEADER_OPTIONS_LENGTH(tcp),
                                 ((uint8_t *)(tcp+1))[0], ((uint8_t *)(tcp+1))[1],
                                 ((uint8_t *)(tcp+1))[2], ((uint8_t *)(tcp+1))[3]);
                }
            }
            break;
        }
    } /* for */
}
#endif
