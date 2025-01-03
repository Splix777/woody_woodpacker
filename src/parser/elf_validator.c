#include "elf_validator.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <elf.h>

// Parse section headers and store them in the context
bool validate_elf_header(t_woody_context *context)
{
    if (!context || !context->file_buffer || context->file_size < sizeof(Elf64_Ehdr))
    {
        fprintf(stderr, "Invalid context or file buffer.\n");
        context->error_code = ERR_INVALID_CONTEXT;
        return false;
    }
    // Validate ELF header offsets and counts
    if (context->file_size < sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + sizeof(Elf64_Shdr))
    {
        fprintf(stderr, "Invalid section header offset or count.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }
    // Read the ELF header
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *)context->file_buffer;
    printf("Class: %d\n", elf_header->e_ident[EI_CLASS]);
    printf("Machine: %d\n", elf_header->e_machine);
    printf("Type: %d\n", elf_header->e_type);
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0)
    {
        fprintf(stderr, "Invalid ELF magic number.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64 || elf_header->e_machine != EM_X86_64)
    {
        // Check what is wrong with the ELF file
        fprintf(stderr, "Invalid ELF class, machine, or type.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }
    if (elf_header->e_type != ET_EXEC && elf_header->e_type != ET_DYN)
    {
        fprintf(stderr, "Invalid ELF type.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }

    // Validate the ELF header
    if (elf_header->e_shoff == 0 || elf_header->e_shnum == 0 || elf_header->e_shstrndx == SHN_UNDEF)
    {
        fprintf(stderr, "Invalid section header offset, count, or index.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }
    // Validate the program header
    if (elf_header->e_phoff == 0 || elf_header->e_phnum == 0)
    {
        fprintf(stderr, "Invalid program header offset or count.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }
    // Validate the entry point
    if (elf_header->e_entry == 0)
    {
        fprintf(stderr, "Invalid entry point.\n");
        context->error_code = ERR_INVALID_ELF;
        return false;
    }

    // Allocate memory for the ELF header in context and copy the data
    context->elf_header = malloc(sizeof(Elf64_Ehdr));
    if (context->elf_header == NULL)
    {
        perror("Memory allocation failed for ELF header");
        context->error_code = ERR_FILE_PARSE;
        return false;
    }
    memcpy(context->elf_header, elf_header, sizeof(Elf64_Ehdr));

    return true;
}
