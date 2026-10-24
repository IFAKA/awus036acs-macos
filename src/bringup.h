// Shared chip bring-up: open, power on, firmware, MAC/BB/RF init, set channel, sanity readback.
#ifndef BRINGUP_H
#define BRINGUP_H
#include <stddef.h>
#include "rtl.h"

// Returns 0 on success. On failure returns nonzero, *step = failing step name ("open", "power_on", ...)
// and reason (size rn) = human text. Leaves the device open (caller calls rtl_close).
int rtl_bringup(rtl_t *r, int channel, const char **step, char *reason, size_t rn);
#endif
