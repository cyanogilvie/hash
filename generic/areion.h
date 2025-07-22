#ifndef _HASH_AREION_H
#define _HASH_AREION_H

#include <stdint.h>
#include <string.h>

#ifndef AREION_DEBUG
#define AREION_DEBUG 0
#endif

#if HAVE_AES_NI
#	include "areion_x86.h"
#elif HAVE_AES_NEON
#	include "areion_neon.h"
#else
#	include "areion_software.h"
#endif

typedef struct {
	uint8_t		state[32];
	uint8_t		buffer[32];
	uint64_t	total_len;
	uint32_t	buffer_len;
} vil_context;

#endif

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4 noexpandtab
