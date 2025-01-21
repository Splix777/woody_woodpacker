#include "woody.h"

static const char *section_flags_to_string(uint64_t flags)
{
    static char buffer[128];
    buffer[0] = '\0';

    if (flags & SHF_WRITE)
        strcat(buffer, "WRITE | ");
    if (flags & SHF_ALLOC)
        strcat(buffer, "ALLOC | ");
    if (flags & SHF_EXECINSTR)
        strcat(buffer, "EXEC | ");
    if (flags & SHF_MERGE)
        strcat(buffer, "MERGE | ");
    if (flags & SHF_STRINGS)
        strcat(buffer, "STRINGS | ");
    if (flags & SHF_INFO_LINK)
        strcat(buffer, "INFO_LINK | ");
    if (flags & SHF_LINK_ORDER)
        strcat(buffer, "LINK_ORDER | ");
    if (flags & SHF_OS_NONCONFORMING)
        strcat(buffer, "OS_NONCONFORMING | ");
    if (flags & SHF_GROUP)
        strcat(buffer, "GROUP | ");
    if (flags & SHF_TLS)
        strcat(buffer, "TLS | ");

    // Remove trailing " | " if there are flags
    if (buffer[0])
        buffer[strlen(buffer) - 3] = '\0';
    else
        strcpy(buffer, "NONE");

    return buffer;
}

static const char *program_flags_to_string(uint64_t flags)
{
    static char buffer[128];
    buffer[0] = '\0';

    if (flags & PF_R)
        strcat(buffer, "READ | ");
    if (flags & PF_W)
        strcat(buffer, "WRITE | ");
    if (flags & PF_X)
        strcat(buffer, "EXECUTE | ");

    // Remove trailing " | " if there are flags
    if (buffer[0])
        buffer[strlen(buffer) - 3] = '\0';
    else
        strcpy(buffer, "NONE");

    return buffer;
}

static char *format_size(size_t size)
{
    static char buffer[32];
    const char *suffixes[5] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double dblSize = size;

    while (dblSize >= 1024 && i < 4)
    {
        dblSize /= 1024.0;
        i++;
    }

    snprintf(buffer, sizeof(buffer), "%.2f %s", dblSize, suffixes[i]);
    return buffer;
}

static char *format_address(uint64_t address)
{
    static char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%016lx", (unsigned long)address);
    return buffer;
}

static void print_section_data(t_woody_context *context)
{
    if (!context)
        return;

    printf("Section Data:\n");
    if (context->elf.is_64bit)
    {
        for (unsigned int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            if (context->elf.elf64.shdr[i].sh_type != SHT_NOBITS)
            {
                printf("  %s:\n", find_elf_section_name(context, i));
                printf("    Data: ");
                if (i == (size_t)context->elf.elf64.payload_section_index)
                {
                    for (size_t j = 0; j < context->elf.elf64.shdr[i].sh_size + INJECTION_PAYLOAD_64_SIZE; j++)
                        printf("%02x", (unsigned char)context->elf.elf64.section_data[i][j]);
                }
                else
                {
                    for (size_t j = 0; j < context->elf.elf64.shdr[i].sh_size; j++)
                        printf("%02x", (unsigned char)context->elf.elf64.section_data[i][j]);
                }
                printf("\n");
            }
        }
    }
    else
    {
        // Implement for 32-bit if needed
    }
}

static void print_section_header(t_woody_context *context)
{
    if (!context)
        return;

    printf("Section Headers:\n");
    if (context->elf.is_64bit)
    {
        for (unsigned int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            Elf64_Shdr *shdr = context->elf.elf64.shdr + i;
            printf("  [%2u] %-17s:\n", i, find_elf_section_name(context, i));
            printf("    Type:             %s\n", shdr->sh_type == SHT_PROGBITS ? "PROGBITS" : shdr->sh_type == SHT_SYMTAB ? "SYMTAB"
                                                                                          : shdr->sh_type == SHT_STRTAB   ? "STRTAB"
                                                                                                                          : "OTHER");
            printf("    Flags:            %s\n", section_flags_to_string(shdr->sh_flags));
            printf("    Address:          %s\n", format_address(shdr->sh_addr));
            printf("    Offset:           %s (%s)\n", format_address(shdr->sh_offset), format_size(shdr->sh_offset));
            printf("    Size:             %s (%s)\n", format_address(shdr->sh_size), format_size(shdr->sh_size));
            printf("    Link:             %lu\n", (unsigned long)shdr->sh_link);
            printf("    Info:             %lu\n", (unsigned long)shdr->sh_info);
            printf("    Alignment:        0x%lx\n", (unsigned long)shdr->sh_addralign);
            printf("    Entry Size:       0x%lx\n", (unsigned long)shdr->sh_entsize);
        }
    }
    else
    {
        // Implement for 32-bit if needed
    }
}

static void print_program_header(t_woody_context *context)
{
    if (!context)
        return;

    printf("Program Headers:\n");
    if (context->elf.is_64bit)
    {
        for (unsigned int i = 0; i < context->elf.elf64.ehdr->e_phnum; i++)
        {
            Elf64_Phdr *phdr = context->elf.elf64.phdr + i;
            printf("  [%2u]\n", i);
            printf("    Type:             %s\n", phdr->p_type == PT_LOAD ? "LOAD" : phdr->p_type == PT_DYNAMIC ? "DYNAMIC"
                                                                                : phdr->p_type == PT_INTERP    ? "INTERP"
                                                                                                               : "OTHER");
            printf("    Flags:            %s\n", program_flags_to_string(phdr->p_flags));
            printf("    Offset:           %s (%s)\n", format_address(phdr->p_offset), format_size(phdr->p_offset));
            printf("    Virtual Address:  %s\n", format_address(phdr->p_vaddr));
            printf("    Physical Address: %s\n", format_address(phdr->p_paddr));
            printf("    File Size:        %s (%s)\n", format_address(phdr->p_filesz), format_size(phdr->p_filesz));
            printf("    Memory Size:      %s (%s)\n", format_address(phdr->p_memsz), format_size(phdr->p_memsz));
            printf("    Alignment:        0x%lx\n", (unsigned long)phdr->p_align);
        }
    }
    else
    {
        // Implement for 32-bit if needed
    }
}

static void print_elf_header(t_woody_context *context)
{
    if (!context)
        return;

    printf("ELF Header:\n");
    printf("  64-bit ELF: %s\n", context->elf.is_64bit ? "true" : "false");

    if (context->elf.is_64bit)
    {
        printf("  ELF64 Header:\n");
        printf("    Magic: ");
        for (int i = 0; i < EI_NIDENT; i++)
            printf("%02x", context->elf.elf64.ehdr->e_ident[i]);
        printf("\n");
        printf("    Entry Point: %s\n", format_address(context->elf.elf64.ehdr->e_entry));
        printf("    Program Header Offset: %s (%s)\n", format_address(context->elf.elf64.ehdr->e_phoff), format_size(context->elf.elf64.ehdr->e_phoff));
        printf("    Section Header Offset: %s (%s)\n", format_address(context->elf.elf64.ehdr->e_shoff), format_size(context->elf.elf64.ehdr->e_shoff));
        printf("    Program Header Entry Size: %u\n", context->elf.elf64.ehdr->e_phentsize);
        printf("    Program Header Entry Count: %u\n", context->elf.elf64.ehdr->e_phnum);
        printf("    Section Header Entry Size: %u\n", context->elf.elf64.ehdr->e_shentsize);
        printf("    Section Header Entry Count: %u\n", context->elf.elf64.ehdr->e_shnum);
    }
    else
    {
        // Implement for 32-bit if needed
    }
}

void print_woody_context(t_woody_context *context)
{
    if (!context)
        return;

    printf("Woody File Context:\n");
    printf("  Input File: %s\n", context->file.input_file_path);
    printf("  Output File: %s\n", context->file.output_file_path);
    printf("  Input FD: %d\n", context->file.input_fd);
    printf("  Output FD: %d\n", context->file.output_fd);
    printf("  File Size: %s\n", format_size(context->file.file_size));

    // Print ELF information
    printf("ELF Information:\n");
    print_elf_header(context);
    print_program_header(context);
    print_section_header(context);
    print_section_data(context);

    // Encryption Information
    printf("Verbose Output: %s\n", context->verbose ? "true" : "false");
}

void print_verbose(t_woody_context *context, const char *format, ...)
{
    if (!format || !context || !context->verbose)
        return;

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}