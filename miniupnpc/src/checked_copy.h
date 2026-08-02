#ifndef MINIUPNPC_CHECKED_COPY_H_INCLUDED
#define MINIUPNPC_CHECKED_COPY_H_INCLUDED

#include <stddef.h>
#include <string.h>

#include "../include/upnpcommands.h"

/* Copy one XML value without truncation. NULL destinations are optional.
 * A non-NULL destination is cleared on every capacity or source failure. */
static int
copyCheckedValue(char * destination, size_t capacity, const char * source)
{
	size_t length;
	if(!destination)
		return 1;
	if(!source || capacity == 0) {
		if(capacity != 0)
			destination[0] = '\0';
		return 0;
	}
	length = strlen(source);
	if(length >= capacity) {
		destination[0] = '\0';
		return 0;
	}
	memcpy(destination, source, length + 1);
	return 1;
}

/* A malformed payload must dominate even a misleading errorCode=0. */
static int
checkedResponseResult(int responseResult, int malformed)
{
	return malformed
		? UPNPCOMMAND_INVALID_RESPONSE
		: responseResult;
}

#endif
