#ifndef PAYLOAD_H
#define PAYLOAD_H

/*
 * Generated injection payload interface.
 *
 * build flow:
 *  - src/code_to_inject/amd64_xor.s is assembled to a raw binary blob
 *  - generate_payload.sh converts that blob into a C array:
 *      unsigned char INJECTION_PAYLOAD_64[] = { ... };
 *
 * prepare_payload() then copies this template and patches placeholders
 * (key/address/size/jump).
 */

#include <stdint.h>
#include <stddef.h>

extern unsigned char INJECTION_PAYLOAD_64[];
extern const size_t INJECTION_PAYLOAD_64_SIZE;

#endif // PAYLOAD_H
