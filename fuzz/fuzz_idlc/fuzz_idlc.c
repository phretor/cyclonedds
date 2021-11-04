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
#include "config.h"

#include <assert.h>
#include <errno.h>
#if HAVE_GETOPT_H
# include <getopt.h>
#else
# include "getopt.h"
#endif
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "idl/tree.h"
#include "idl/string.h"
#include "idl/processor.h"
#include "idl/file.h"
#include "idl/version.h"
#include "idl/stream.h"

#include "mcpp_lib.h"
#include "mcpp_out.h"

#include "plugin.h"
#include "options.h"

#if 0
#define IDLC_DEBUG_PREPROCESSOR (1u<<2)
#define IDLC_DEBUG_SCANNER (1u<<3)
#define IDLC_DEBUG_PARSER (1u<<4)
#endif

static struct {
  char *file; /* path of input file or "-" for STDIN */
  const char *lang;
  int compile;
  int preprocess;
  int keylist;
  int case_sensitive;
  int help;
  int version;
  /* (emulated) command line options for mcpp */
  int argc;
  char **argv;
} config;

/* mcpp does not accept userdata */
static idl_retcode_t retcode = IDL_RETCODE_OK;
static idl_pstate_t *pstate = NULL;

#define CHUNK (4096)

static int idlc_putn(const char *str, size_t len)
{
  assert(pstate->flags & IDL_WRITE);

  /* tokenize to free up space */
  if ((pstate->buffer.size - pstate->buffer.used) <= len) {
    if ((retcode = idl_parse(pstate)) == IDL_RETCODE_NEED_REFILL)
      retcode = IDL_RETCODE_OK;
    /* move non-tokenized data to start of buffer */
    pstate->buffer.used =
      (uintptr_t)pstate->scanner.limit - (uintptr_t)pstate->scanner.cursor;
    memmove(pstate->buffer.data, pstate->scanner.cursor, pstate->buffer.used);
    pstate->scanner.cursor = pstate->buffer.data;
    pstate->scanner.limit = pstate->scanner.cursor + pstate->buffer.used;
  }

  if (retcode != IDL_RETCODE_OK)
    return -1;

  /* expand buffer if necessary */
  if ((pstate->buffer.size - pstate->buffer.used) <= len) {
    size_t size = pstate->buffer.size + (((len / CHUNK) + 1) * CHUNK);
    char *buf = realloc(pstate->buffer.data, size + 2 /* '\0' + '\0' */);
    if (buf == NULL) {
      retcode = IDL_RETCODE_NO_MEMORY;
      return -1;
    }
    /* update scanner location */
    pstate->scanner.cursor = buf + (pstate->scanner.cursor - pstate->buffer.data);
    pstate->scanner.limit = buf + pstate->buffer.used;
    /* update input buffer */
    pstate->buffer.data = buf;
    pstate->buffer.size = size;
  }

  /* write to buffer */
  memcpy(pstate->buffer.data + pstate->buffer.used, str, len);
  pstate->buffer.used += len;
  assert(pstate->buffer.used <= pstate->buffer.size);
  /* update scanner location */
  pstate->scanner.limit = pstate->buffer.data + pstate->buffer.used;

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  config.compile = 0;
  config.preprocess = 0;

  idlc_putn(data, size);
  idl_delete_pstate(pstate);

  return 0;
}
