#include "woody.h"

static int inject_code(t_woody_context *context)
{
    // We will try three methods to inject the code:
    // 1. Find a code cave in the .text section
    // 2. Section Insertion (Add a new section)
    // 3. Segment Insertion (Add a new segment)

    // Method 1: Find a code cave in the .text section
    print_verbose(context, "Attempting to find a code cave...\n");
    if (find_code_cave(context) == SUCCESS)
        return SUCCESS;
    // if (insert_section(context) == SUCCESS)
    //     return SUCCESS;
    // if (insert_segment(context) == SUCCESS)
    //     return SUCCESS;

    return ERR_INJECTION;
}

int inject_elf64(t_woody_context *context)
{
    print_verbose(context, "Injecting 64-bit ELF\n");
    if (initialize_struct(context) != SUCCESS)
        return ERR_INVALID_ELF;
    if (encrypt_text_section(context) != SUCCESS)
        return ERR_ENCRYPTION;
    if (inject_code(context) != SUCCESS)
        return ERR_INJECTION;
    if (write_output_file(context) != SUCCESS)
        return ERR_FILE_WRITE;

    return SUCCESS;
}