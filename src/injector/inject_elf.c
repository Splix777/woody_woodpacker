#include "woody.h"

/*
 * Injection orchestrator.
 *
 * By the time inject_elf() is called:
 *  - argument_parse() has filled file paths + verbose flag
 *  - import_context_data() has mmap()'d the input file into file_buff
 *  - validate_headers() has confirmed the input is ELF64/x86_64
 *
 * inject_elf() then:
 *  - initialize_struct(): copies headers/sections into owned memory and unmaps
 *    the original mapping (we mutate the copies from here on).
 *  - encrypt_text_section(): XOR-encrypts ".text" and prints the key
 *  - inject_code(): inserts a new ".woody" section containing the loader stub
 *  - write_elf(): serializes the new ELF to disk
 */
static int inject_code(t_woody_context *context)
{
    print_verbose(context, "Attempting to find a code cave...\n");
    if (find_code_cave(context) == SUCCESS)
        return SUCCESS;
    print_verbose(context, "Inserting a new section...\n");
    if (insert_new_section(context) == SUCCESS)
        return SUCCESS;

    return ERR_INJECTION;
}

int inject_elf(t_woody_context *context)
{
    print_verbose(context, "Injecting 64-bit ELF\n");
    if (!context->elf.is_64bit)
        return ERR_INVALID_ELF;
    if (initialize_struct(context) != SUCCESS)
        return ERR_INVALID_ELF;
    if (encrypt_text_section(context) != SUCCESS)
        return ERR_ENCRYPTION;
    if (inject_code(context) != SUCCESS)
        return ERR_INJECTION;
    if (write_elf(context) != SUCCESS)
        return ERR_FILE_WRITE;

    return SUCCESS;
}
