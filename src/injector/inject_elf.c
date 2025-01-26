#include "woody.h"

static int inject_code(t_woody_context *context)
{
    print_verbose(context, "Attempting to find a code cave...\n");
    // if (find_code_cave(context) == SUCCESS)
    //     return SUCCESS;
    print_verbose(context, "Inserting a new section...\n");
    if (insert_new_section(context) == SUCCESS)
        return SUCCESS;

    return ERR_INJECTION;
}

int inject_elf(t_woody_context *context)
{
    print_verbose(context, "Injecting 64-bit ELF\n");
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