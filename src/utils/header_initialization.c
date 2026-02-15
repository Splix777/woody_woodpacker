#include "woody.h"

/*
 * initialize_struct():
 *  - Allocates owned copies of ELF header, program header table, section header
 *    table, and each section's data (except SHT_NOBITS).
 *  - Performs bounds checks before copying from the original mmap() buffer.
 *  - Unmaps the original input mapping once the owned copies are created.
 *
 * After this step, the rest of the pipeline mutates only the owned buffers.
 */
static bool is_in_file_bounds(size_t file_size, size_t offset, size_t size) {
    return offset <= file_size && size <= (file_size - offset);
}

static int allocate_elf_header(t_woody_context* context) {
    context->elf.elf64.ehdr = malloc(sizeof(Elf64_Ehdr));
    if (!context->elf.elf64.ehdr) {
        print_verbose(context, "Failed to allocate ELF64 header\n");
        return ERR_MEMORY_ALLOC;
    }

    memcpy(context->elf.elf64.ehdr, context->file.file_buff, sizeof(Elf64_Ehdr));
    return SUCCESS;
}

static int allocate_program_header(t_woody_context* context) {
    size_t phdr_size = sizeof(Elf64_Phdr) * context->elf.elf64.ehdr->e_phnum;

    if (!is_in_file_bounds(
            context->file.file_size, context->elf.elf64.ehdr->e_phoff, phdr_size)) {
        print_verbose(context, "Invalid ELF64 program header\n");
        return ERR_INVALID_ELF;
    }

    context->elf.elf64.phdr = malloc(phdr_size);
    if (!context->elf.elf64.phdr) {
        print_verbose(context, "Failed to allocate ELF64 program header\n");
        return ERR_MEMORY_ALLOC;
    }

    memcpy(context->elf.elf64.phdr,
        context->file.file_buff + context->elf.elf64.ehdr->e_phoff, phdr_size);
    return SUCCESS;
}

static int allocate_section_header(t_woody_context* context) {
    size_t shdr_size = sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum;

    context->elf.elf64.shdr = malloc(shdr_size);
    if (!context->elf.elf64.shdr) {
        print_verbose(context, "Failed to allocate ELF64 section header\n");
        return ERR_MEMORY_ALLOC;
    }

    for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
        size_t offset = context->elf.elf64.ehdr->e_shoff + (i * sizeof(Elf64_Shdr));
        if (!is_in_file_bounds(
                context->file.file_size, offset, sizeof(Elf64_Shdr))) {
            print_verbose(context, "Invalid ELF64 section header\n");
            return ERR_INVALID_ELF;
        }

        memcpy(&context->elf.elf64.shdr[i], context->file.file_buff + offset,
            sizeof(Elf64_Shdr));
    }

    return SUCCESS;
}

static int allocate_section_data(t_woody_context* context) {
    size_t number_of_sections = sizeof(char*) * context->elf.elf64.ehdr->e_shnum;

    context->elf.elf64.section_data = malloc(number_of_sections);
    if (!context->elf.elf64.section_data) {
        print_verbose(context, "Failed to allocate ELF64 section data\n");
        return ERR_MEMORY_ALLOC;
    }

    for (int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
        Elf64_Shdr* shdr = &context->elf.elf64.shdr[i];

        if (shdr->sh_type == SHT_NOBITS) {
            context->elf.elf64.section_data[i] = NULL;
            continue;
        }

        if (!is_in_file_bounds(
                context->file.file_size, shdr->sh_offset, shdr->sh_size)) {
            print_verbose(context, "Invalid ELF64 section range\n");
            return ERR_INVALID_ELF;
        }

        context->elf.elf64.section_data[i] = malloc(shdr->sh_size);
        if (!context->elf.elf64.section_data[i]) {
            print_verbose(context, "Failed to allocate ELF64 section data\n");
            return ERR_MEMORY_ALLOC;
        }

        memcpy(context->elf.elf64.section_data[i],
            context->file.file_buff + shdr->sh_offset, shdr->sh_size);
    }

    return SUCCESS;
}

int initialize_struct(t_woody_context* context) {
    t_error_code ret;

    if ((ret = allocate_elf_header(context)) != SUCCESS)
        return ret;
    if ((ret = allocate_program_header(context)) != SUCCESS)
        return ret;
    if ((ret = allocate_section_header(context)) != SUCCESS)
        return ret;
    if ((ret = allocate_section_data(context)) != SUCCESS)
        return ret;

    munmap(context->file.file_buff, context->file.file_size);
    context->file.file_buff = NULL;

    return SUCCESS;
}
