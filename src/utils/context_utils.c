// src/utils/context_utils.c

#include "woody.h"    // t_woody_context, ERR_FILE_OPEN
#include <stdlib.h>   // malloc, free
#include <string.h>   // memset
#include <unistd.h>   // close, remove
#include <sys/mman.h> // munmap

// Initialize the woody context
bool init_woody_context(
    t_woody_context *context,
    const char *input_file,
    const char *output_file)
{
    if (!context || !input_file || !output_file)
        return false;

    // Zero out the context to avoid uninitialized values
    memset(context, 0, sizeof(t_woody_context));

    // Set file paths
    context->input_file_path = input_file;
    context->output_file_path = output_file;

    // Load file into memory
    if (!load_file_to_memory(context))
        return false;

    // Mark context as initialized
    context->initialized = true;
    context->error_code = ERR_NONE;

    return true;
}

// Cleanup the woody context
void cleanup_context(t_woody_context *context)
{
    if (!context)
        return;

    // Close file descriptors
    if (context->input_fd > 0)
        close(context->input_fd);
    if (context->output_fd > 0)
        close(context->output_fd);

    // Free file buffer
    if (context->file_buffer)
    {
        // mmap doesnt work like malloc, so we need to unmap the memory
        munmap(context->file_buffer, context->file_size);
        context->file_buffer = NULL;
    }

    // Delete output file if it was created
    if (context->output_file_path)
        remove(context->output_file_path);

    // Free ELF-specific data
    if (context->elf_header)
    {
        free(context->elf_header);
        context->elf_header = NULL;
    }
    if (context->program_headers)
    {
        free(context->program_headers);
        context->program_headers = NULL;
    }

    // Free encryption key
    if (context->encryption_key)
        free(context->encryption_key);

    // Free dynamically allocated memory
    for (size_t i = 0; i < context->allocation_count; i++)
    {
        free(context->dynamic_allocations[i]);
    }

    // Reset the context
    memset(context, 0, sizeof(t_woody_context));
}

// Print woody structure for debugging
void print_woody_context(t_woody_context *context)
{
    if (!context)
        return;

    printf("Woody Context:\n");
    printf("  Input File: %s\n", context->input_file_path);
    printf("  Output File: %s\n", context->output_file_path);
    printf("  Input FD: %d\n", context->input_fd);
    printf("  Output FD: %d\n", context->output_fd);
    printf("  File Size: %zu\n", context->file_size);

    // ELF Header
    printf("  ELF Header: %p\n", (void *)context->elf_header);
    if (context->elf_header)
    {
        printf("  ELF Header Contents:\n");
        printf("    e_ident: %s\n", context->elf_header->e_ident);
        printf("    e_ident[EI_MAG0]: 0x%x\n", context->elf_header->e_ident[EI_MAG0]);
        printf("    e_ident[EI_MAG1]: 0x%x\n", context->elf_header->e_ident[EI_MAG1]);
        printf("    e_ident[EI_MAG2]: 0x%x\n", context->elf_header->e_ident[EI_MAG2]);
        printf("    e_ident[EI_MAG3]: 0x%x\n", context->elf_header->e_ident[EI_MAG3]);
        printf("    e_type: 0x%x\n", context->elf_header->e_type);
        printf("    e_machine: 0x%x\n", context->elf_header->e_machine);
        printf("    e_version: 0x%x\n", context->elf_header->e_version);
        printf("    e_entry: 0x%lx\n", (unsigned long)context->elf_header->e_entry);
        printf("    e_phoff: 0x%lx\n", (unsigned long)context->elf_header->e_phoff);
        printf("    e_shoff: 0x%lx\n", (unsigned long)context->elf_header->e_shoff);
        printf("    e_flags: 0x%x\n", context->elf_header->e_flags);
        printf("    e_ehsize: 0x%x\n", context->elf_header->e_ehsize);
        printf("    e_phentsize: 0x%x\n", context->elf_header->e_phentsize);
        printf("    e_phnum: 0x%x\n", context->elf_header->e_phnum);
        printf("    e_shentsize: 0x%x\n", context->elf_header->e_shentsize);
        printf("    e_shnum: 0x%x\n", context->elf_header->e_shnum);
        printf("    e_shstrndx: 0x%x\n", context->elf_header->e_shstrndx);
    }
    else
    {
        printf("  ELF Header: NULL or not initialized\n");
    }

    printf("  Text Section Offset: %zu\n", context->text_section_offset);
    printf("  Text Section Size: %zu\n", context->text_section_size);
    printf("  Encryption Key: %p\n", context->encryption_key);
    printf("  Key Size: %zu\n", context->key_size);
    printf("  Encryption Done: %s\n", context->encryption_done ? "true" : "false");
    printf("  Error Code: %d\n", context->error_code);
    printf("  Initialized: %s\n", context->initialized ? "true" : "false");
    printf("  Allocation Count: %zu\n", context->allocation_count);
    for (size_t i = 0; i < context->allocation_count; i++)
    {
        printf("  Allocation %zu: %p\n", i, context->dynamic_allocations[i]);
    }
}