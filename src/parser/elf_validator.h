#ifndef ELF_VALIDATOR_H
#define ELF_VALIDATOR_H

#include "woody.h"
#include <elf.h>

// Validation function prototypes
bool validate_elf_header(t_woody_context *context);

#endif // ELF_VALIDATOR_H
