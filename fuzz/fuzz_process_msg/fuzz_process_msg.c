/*
 * Copyright(c) 2021 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dds/dds.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/q_thread.h"
#include "dds/ddsi/q_config.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/q_entity.h"
#include "dds/ddsi/q_radmin.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/q_transmit.h"
#include "dds/ddsi/q_xmsg.h"
#include "dds/ddsi/q_addrset.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsi/ddsi_sertype.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "dds/ddsi/ddsi_builtin_topic_if.h"
#include "dds/ddsi/ddsi_security_omg.h"
#include "dds/ddsi/ddsi_rhc.h"
#include "dds/ddsi/ddsi_vnet.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/ddsi/q_bswap.h"
#include "dds__whc.h"
#include "dds__types.h"

static void null_log_sink(void *varg, const dds_log_data_t *msg)
{
    (void)varg;
    (void)msg;
}

static ssize_t fakeconn_write(ddsi_tran_conn_t conn, const ddsi_locator_t *dst, size_t niov, const ddsrt_iovec_t *iov, uint32_t flags)
{
    return (ssize_t)niov;
}

static ssize_t fakeconn_read(ddsi_tran_conn_t conn, unsigned char *buf, size_t len, bool allow_spurious, ddsi_locator_t *srcloc)
{
    return (ssize_t)len;
}

/**********************************/

static struct cfgst *cfgst;
static struct ddsi_domaingv gv;
static ddsi_tran_conn_t fakeconn;
static ddsi_tran_factory_t fakenet;
static struct thread_state1 *ts1;
// static struct ddsi_tkmap_instance *tk;
static struct nn_rbufpool *rbpool;

// /usr/bin/ld: /src/cyclonedds/fuzz/fuzz_process_msg/fuzz_process_msg.c:157: undefined reference to `free_special_types'

static void _free_conns (struct ddsi_domaingv *gv)
{
  // Depending on settings, various "conn"s can alias others, this makes sure we free each one only once
  // FIXME: perhaps store them in a table instead?
  ddsi_tran_conn_t cs[4 + MAX_XMIT_CONNS] = { gv->disc_conn_mc, gv->data_conn_mc, gv->disc_conn_uc, gv->data_conn_uc };
  for (size_t i = 0; i < MAX_XMIT_CONNS; i++)
    cs[4 + i] = gv->xmit_conns[i];
  for (size_t i = 0; i < sizeof (cs) / sizeof (cs[0]); i++)
  {
    if (cs[i] == NULL)
      continue;
    for (size_t j = i + 1; j < sizeof (cs) / sizeof (cs[0]); j++)
      if (cs[i] == cs[j])
        cs[j] = NULL;
    ddsi_conn_free (cs[i]);
  }
}

void _rtps_fini (struct ddsi_domaingv *gv)
{
  /* Shut down the GC system -- no new requests will be added */
  gcreq_queue_free (gv->gcreq_queue);

  /* No new data gets added to any admin, all synchronous processing
     has ended, so now we can drain the delivery queues to end up with
     the expected reference counts all over the radmin thingummies. */
  nn_dqueue_free (gv->builtins_dqueue);

#ifdef DDS_HAS_NETWORK_CHANNELS
  chptr = gv->config.channels;
  while (chptr)
  {
    nn_dqueue_free (chptr->dqueue);
    chptr = chptr->next;
  }
#else
  nn_dqueue_free (gv->user_dqueue);
#endif

#ifdef DDS_HAS_SECURITY
  q_omg_security_deinit (gv->security_context);
#endif

  xeventq_free (gv->xevents);

  // if sendq thread is started
  ddsrt_mutex_lock (&gv->sendq_running_lock);
  if (gv->sendq_running)
  {
    nn_xpack_sendq_stop (gv);
    nn_xpack_sendq_fini (gv);
  }
  ddsrt_mutex_unlock (&gv->sendq_running_lock);

#ifdef DDS_HAS_NETWORK_CHANNELS
  chptr = gv->config.channels;
  while (chptr)
  {
    if (chptr->evq)
    {
      xeventq_free (chptr->evq);
    }
    if (chptr->transmit_conn != gv->data_conn_uc)
    {
      ddsi_conn_free (chptr->transmit_conn);
    }
    chptr = chptr->next;
  }
#endif

  (void) joinleave_spdp_defmcip (gv, 0);
  for (int i = 0; i < gv->n_interfaces; i++)
    gv->intf_xlocators[i].conn = NULL;
  _free_conns (gv);
  free_group_membership(gv->mship);
  ddsi_tran_factories_fini (gv);

  if (gv->pcap_fp)
  {
    ddsrt_mutex_destroy (&gv->pcap_lock);
    fclose (gv->pcap_fp);
  }

  unref_addrset (gv->as_disc);
  unref_addrset (gv->as_disc_group);

  /* Must delay freeing of rbufpools until after *all* references have
     been dropped, which only happens once all receive threads have
     stopped, defrags and reorders have been freed, and all delivery
     queues been drained.  I.e., until very late in the game. */
  for (uint32_t i = 0; i < gv->n_recv_threads; i++)
  {
    if (gv->recv_threads[i].arg.mode == RTM_MANY)
      os_sockWaitsetFree (gv->recv_threads[i].arg.u.many.ws);
    nn_rbufpool_free (gv->recv_threads[i].arg.rbpool);
  }

  ddsi_tkmap_free (gv->m_tkmap);
  entity_index_free (gv->entity_index);
  gv->entity_index = NULL;
  deleted_participants_admin_free (gv->deleted_participants);
  lease_management_term (gv);
  ddsrt_mutex_destroy (&gv->participant_set_lock);
  ddsrt_cond_destroy (&gv->participant_set_cond);
//   free_special_types (gv);

#ifdef DDS_HAS_TOPIC_DISCOVERY
#ifndef NDEBUG
  {
    struct ddsrt_hh_iter it;
    assert (ddsrt_hh_iter_first (gv->topic_defs, &it) == NULL);
  }
#endif
  ddsrt_hh_free (gv->topic_defs);
  ddsrt_mutex_destroy (&gv->topic_defs_lock);
#endif /* DDS_HAS_TOPIC_DISCOVERY */
#ifndef NDEBUG
  {
    struct ddsrt_hh_iter it;
    assert (ddsrt_hh_iter_first (gv->sertypes, &it) == NULL);
  }
#endif
  ddsrt_hh_free (gv->sertypes);
  ddsrt_mutex_destroy (&gv->sertypes_lock);
#ifdef DDS_HAS_TYPE_DISCOVERY
#ifndef NDEBUG
  {
    struct ddsrt_hh_iter it;
    assert (ddsrt_hh_iter_first (gv->tl_admin, &it) == NULL);
  }
#endif
  ddsrt_hh_free (gv->tl_admin);
  ddsrt_mutex_destroy (&gv->tl_admin_lock);
#endif /* DDS_HAS_TYPE_DISCOVERY */
#ifdef DDS_HAS_SECURITY
  q_omg_security_free (gv);
  ddsi_xqos_fini (&gv->builtin_stateless_xqos_wr);
  ddsi_xqos_fini (&gv->builtin_stateless_xqos_rd);
  ddsi_xqos_fini (&gv->builtin_secure_volatile_xqos_wr);
  ddsi_xqos_fini (&gv->builtin_secure_volatile_xqos_rd);
#endif
#ifdef DDS_HAS_TYPE_DISCOVERY
  ddsi_xqos_fini (&gv->builtin_volatile_xqos_wr);
  ddsi_xqos_fini (&gv->builtin_volatile_xqos_rd);
#endif
  ddsi_xqos_fini (&gv->builtin_endpoint_xqos_wr);
  ddsi_xqos_fini (&gv->builtin_endpoint_xqos_rd);
  ddsi_xqos_fini (&gv->spdp_endpoint_xqos);
  ddsi_plist_fini (&gv->default_local_plist_pp);

  ddsrt_mutex_destroy (&gv->lock);

  while (gv->recvips)
  {
    struct config_in_addr_node *n = gv->recvips;
    /* The compiler doesn't realize that n->next is always initialized. */
    DDSRT_WARNING_MSVC_OFF(6001);
    gv->recvips = n->next;
    DDSRT_WARNING_MSVC_ON(6001);
    ddsrt_free (n);
  }

  for (int i = 0; i < (int) gv->n_interfaces; i++)
    ddsrt_free (gv->interfaces[i].name);

  ddsi_serdatapool_free (gv->serpool);
  nn_xmsgpool_free (gv->xmsgpool);
  GVLOG (DDS_LC_CONFIG, "Finis.\n");
}

int LLVMFuzzerTestOneInput(
    const uint8_t *data,
    size_t size)
{
    ddsi_iid_init();
    thread_states_init(64);

    memset(&dds_global, 0, sizeof(dds_global));
    ddsrt_mutex_init(&dds_global.m_mutex);

    ddsi_config_init_default(&gv.config);

    memset(&gv, 0, sizeof(gv));
    cfgst = config_init("<Tr><V>none</></>", &gv.config, DDS_DOMAIN_DEFAULT);
    rtps_config_prep(&gv, cfgst);
    dds_set_log_sink(null_log_sink, NULL);
    dds_set_trace_sink(null_log_sink, NULL);

    rtps_init(&gv);

    /* Abuse some other code to get a "connection" independent of the actual network stack
     and for which we can safely override the "read" and "write" functions.  The "123" is
     arbitrary, anything goes as long as the locator type in "vnet_init" doesn't collide
     with an existing one. */
    ddsi_vnet_init(&gv, "fake", 123);
    fakenet = ddsi_factory_find(&gv, "fake");
    // assert(fakenet);
    ddsi_factory_create_conn(&fakeconn, fakenet, 0, &(const struct ddsi_tran_qos){
                                                        .m_purpose = DDSI_TRAN_QOS_XMIT, /* this happens to work, even if it needs ... */
                                                        .m_interface = &gv.interfaces[0] /* ... a lie! who cares? */
                                                    });
    /* really want to have a place to store the data ... it is actually a little bit larger
     than the sizeof, so while this does work, don't try this at home! */
    fakeconn = ddsrt_realloc(fakeconn, sizeof(struct ddsi_tran_conn) + 128);
    fakeconn->m_read_fn = &fakeconn_read;
    fakeconn->m_write_fn = &fakeconn_write;

    rtps_start(&gv);

    ts1 = lookup_thread_state();
    /* Processing incoming packets doesn't like to run on anything other than a thread
     created internally by rtps_start(), so fake it.  At that point, the "gv" pointer
     must also be set and tied to the one domain. */
    ts1->state = THREAD_STATE_ALIVE;
    ddsrt_atomic_stvoidp(&ts1->gv, &gv);

    thread_state_awake(ts1, &gv);
    thread_state_asleep(ts1);

    rbpool = nn_rbufpool_new(&gv.logconfig, gv.config.rbuf_size, gv.config.rmsg_chunk_size);
    nn_rbufpool_setowner(rbpool, ddsrt_thread_self());

    /* Actual fuzzing begins here. Previous code is mostly init stuff, so will be moved into an init function in the future */

    do_packet(ts1, &gv, fakeconn, NULL, rbpool, data, size);

    /* Actual fuzzing ends here. */

    printf("After do_packet\n");

    _rtps_fini(&gv);

    printf("After rtps_fini\n");

    config_fini(cfgst);

    printf("After config_fini\n");
}