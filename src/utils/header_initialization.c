#include "woody.h"

static int allocate_elf_header(t_woody_context* context) {
    if (context->elf.is_64bit) {
        context->elf.elf64.ehdr = malloc(sizeof(Elf64_Ehdr));
        if (!context->elf.elf64.ehdr) {
            print_verbose(context, "Failed to allocate ELF64 header\n");
            return ERR_MEMORY_ALLOC;
        }
        memcpy(context->elf.elf64.ehdr, context->file.file_buff,
            sizeof(Elf64_Ehdr));
    } else {
        context->elf.elf32.ehdr = malloc(sizeof(Elf32_Ehdr));
        if (!context->elf.elf32.ehdr) {
            print_verbose(context, "Failed to allocate ELF32 header\n");
            return ERR_MEMORY_ALLOC;
        }
        memcpy(context->elf.elf32.ehdr, context->file.file_buff,
            sizeof(Elf32_Ehdr));
    }

    return SUCCESS;
}

static int allocate_program_header(t_woody_context* context) {
    if (context->elf.is_64bit) {
        size_t phdr_size
            = sizeof(Elf64_Phdr) * context->elf.elf64.ehdr->e_phnum;
        if (context->file.file_size < sizeof(Elf64_Ehdr) + phdr_size) {
            print_verbose(context, "Invalid ELF64 program header\n");
            return ERR_INVALID_ELF;
        }
        context->elf.elf64.phdr = malloc(phdr_size);
        if (!context->elf.elf64.phdr) {
            print_verbose(
                context, "Failed to allocate ELF64 program header\n");
            return ERR_MEMORY_ALLOC;
        }
        memcpy(context->elf.elf64.phdr,
            context->file.file_buff + context->elf.elf64.ehdr->e_phoff,
            phdr_size);
    } else {
        size_t phdr_size
            = sizeof(Elf32_Phdr) * context->elf.elf32.ehdr->e_phnum;
        if (context->file.file_size < sizeof(Elf32_Ehdr) + phdr_size) {
            print_verbose(context, "Invalid ELF32 program header\n");
            return ERR_INVALID_ELF;
        }
        context->elf.elf32.phdr = malloc(phdr_size);
        if (!context->elf.elf32.phdr) {
            print_verbose(
                context, "Failed to allocate ELF32 program header\n");
            return ERR_MEMORY_ALLOC;
        }
        memcpy(context->elf.elf32.phdr,
            context->file.file_buff + context->elf.elf32.ehdr->e_phoff,
            phdr_size);
    }

    return SUCCESS;
}

static int allocate_section_header(t_woody_context* context) {
    if (context->elf.is_64bit) {
        size_t shdr_size
            = sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum;
        context->elf.elf64.shdr = malloc(shdr_size);
        if (!context->elf.elf64.shdr) {
            print_verbose(
                context, "Failed to allocate ELF64 section header\n");
            return ERR_MEMORY_ALLOC;
        }

        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
            if (context->file.file_size < context->elf.elf64.ehdr->e_shoff
                    + (i * sizeof(Elf64_Shdr))) {
                print_verbose(context, "Invalid ELF64 section header\n");
                return ERR_INVALID_ELF;
            }
            memcpy(&context->elf.elf64.shdr[i],
                context->file.file_buff + context->elf.elf64.ehdr->e_shoff
                    + (i * sizeof(Elf64_Shdr)),
                sizeof(Elf64_Shdr));
        }
    } else {
        size_t shdr_size
            = sizeof(Elf32_Shdr) * context->elf.elf32.ehdr->e_shnum;
        context->elf.elf32.shdr = malloc(shdr_size);
        if (!context->elf.elf32.shdr) {
            print_verbose(
                context, "Failed to allocate ELF32 section header\n");
            return ERR_MEMORY_ALLOC;
        }

        for (size_t i = 0; i < context->elf.elf32.ehdr->e_shnum; i++) {
            if (context->file.file_size < context->elf.elf32.ehdr->e_shoff
                    + (i * sizeof(Elf32_Shdr))) {
                print_verbose(context, "Invalid ELF32 section header\n");
                return ERR_INVALID_ELF;
            }
            memcpy(&context->elf.elf32.shdr[i],
                context->file.file_buff + context->elf.elf32.ehdr->e_shoff
                    + (i * sizeof(Elf32_Shdr)),
                sizeof(Elf32_Shdr));
        }
    }

    return SUCCESS;
}

static int allocate_section_data(t_woody_context* context) {
    if (context->elf.is_64bit) {
        size_t number_of_sections
            = sizeof(char*) * context->elf.elf64.ehdr->e_shnum;
        context->elf.elf64.section_data = malloc(number_of_sections);
        if (!context->elf.elf64.section_data) {
            print_verbose(context, "Failed to allocate ELF64 section data\n");
            return ERR_MEMORY_ALLOC;
        }

        size_t elf_section_size;
        for (int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
            Elf64_Shdr* shdr = context->elf.elf64.shdr + i;
            // SHT_NOBITS sections dont occupy space in the file
            if (shdr->sh_type == SHT_NOBITS)
                context->elf.elf64.section_data[i] = NULL;
            else {
                if (context->file.file_size
                    < context->elf.elf64.shdr[i].sh_offset) {
                    print_verbose(context, "Invalid ELF64 section data\n");
                    return ERR_INVALID_ELF;
                }

                elf_section_size = context->elf.elf64.shdr[i].sh_size;
                context->elf.elf64.section_data[i] = malloc(elf_section_size);
                if (!context->elf.elf64.section_data[i]) {
                    print_verbose(
                        context, "Failed to allocate ELF64 section data\n");
                    return ERR_MEMORY_ALLOC;
                }
                memcpy(context->elf.elf64.section_data[i],
                    context->file.file_buff
                        + context->elf.elf64.shdr[i].sh_offset,
                    elf_section_size);
            }
        }
    } else {
        size_t number_of_sections
            = sizeof(char*) * context->elf.elf32.ehdr->e_shnum;
        context->elf.elf32.section_data = malloc(number_of_sections);
        if (!context->elf.elf32.section_data) {
            print_verbose(context, "Failed to allocate ELF32 section data\n");
            return ERR_MEMORY_ALLOC;
        }

        size_t elf_section_size;
        for (int i = 0; i < context->elf.elf32.ehdr->e_shnum; i++) {
            Elf32_Shdr* shdr = context->elf.elf32.shdr + i;
            // SHT_NOBITS sections dont occupy space in the file
            if (shdr->sh_type == SHT_NOBITS)
                context->elf.elf32.section_data[i] = NULL;
            else {
                if (context->file.file_size
                    < context->elf.elf32.shdr[i].sh_offset) {
                    print_verbose(context, "Invalid ELF32 section data\n");
                    return ERR_INVALID_ELF;
                }

                elf_section_size = context->elf.elf32.shdr[i].sh_size;
                context->elf.elf32.section_data[i] = malloc(elf_section_size);
                if (!context->elf.elf32.section_data[i]) {
                    print_verbose(
                        context, "Failed to allocate ELF32 section data\n");
                    return ERR_MEMORY_ALLOC;
                }
                memcpy(context->elf.elf32.section_data[i],
                    context->file.file_buff
                        + context->elf.elf32.shdr[i].sh_offset,
                    elf_section_size);
            }
        }
    }

    return SUCCESS;
}

int initialize_struct(t_woody_context* context) {
    if (allocate_elf_header(context) != SUCCESS)
        return ERR_MEMORY_ALLOC;
    if (allocate_program_header(context) != SUCCESS)
        return ERR_MEMORY_ALLOC;
    if (allocate_section_header(context) != SUCCESS)
        return ERR_MEMORY_ALLOC;
    if (allocate_section_data(context) != SUCCESS)
        return ERR_MEMORY_ALLOC;

    munmap(context->file.file_buff, context->file.file_size);

    return SUCCESS;
}
