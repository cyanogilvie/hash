#ifndef _HASH_H
#define _HASH_H

#if HAVE_CONFIG_H
#   include <config.h>
#endif

#define NS "::hash"

#include <stdint.h>

#include "tclstuff.h"

// areon.c internal API
int areion_init(Tcl_Interp* interp);

#endif
