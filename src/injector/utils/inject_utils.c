#include "woody.h"

/*
 * Small ELF query/mutation helpers used during injection.
 *
 * Conventions:
 *  - "segment index" refers to an index into Elf64_Phdr[] (program headers).
 *  - "section index" refers to an index into Elf64_Shdr[] (section headers).
 */
int find_elf_segment_index_by_section(t_woody_context* context, int section_index) {
    for (size_t i = 0; i < context->elf.elf64.ehdr->e_phnum; i++) {
        if (context->elf.elf64.phdr[i].p_offset
                <= context->elf.elf64.shdr[section_index].sh_offset
            && (context->elf.elf64.phdr[i].p_offset
                   + context->elf.elf64.phdr[i].p_filesz)
                >= context->elf.elf64.shdr[section_index].sh_offset)
            return i;
    }

    return -1;
}

char* find_elf_section_name(t_woody_context* context, int index) {
    int shstrndx = context->elf.elf64.ehdr->e_shstrndx;
    return (char*)context->elf.elf64.section_data[shstrndx]
        + context->elf.elf64.shdr[index].sh_name;
}

int find_elf_section_index(t_woody_context* context, char* name) {
    for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
        char* section_name = find_elf_section_name(context, i);
        if (strcmp(section_name, name) == 0)
            return i;
    }

    return -1;
}

int find_text_section_index(t_woody_context* context) {
    for (size_t i = 0; i < context->elf.elf64.ehdr->e_phnum; i++) {
        if (context->elf.elf64.phdr[i].p_type == PT_LOAD
            && context->elf.elf64.ehdr->e_entry
                < context->elf.elf64.phdr[i].p_vaddr
                    + context->elf.elf64.phdr[i].p_filesz
            && context->elf.elf64.ehdr->e_entry
                >= context->elf.elf64.phdr[i].p_vaddr)
            return i;
    }

    return -1;
}

void set_elf_segment_permission(t_woody_context* context, int index, int flags) {
    context->elf.elf64.phdr[index].p_flags |= flags;
}

int find_last_segment_by_type(t_woody_context* context, unsigned int type) {
    for (size_t i = context->elf.elf64.ehdr->e_phnum; i-- > 0;) {
        if (context->elf.elf64.phdr[i].p_type == type)
            return i;
    }

    return -1;
}

int find_last_section_in_segment(t_woody_context* context, int segment_index) {
    Elf64_Phdr* segment = &context->elf.elf64.phdr[segment_index];

    for (size_t i = context->elf.elf64.ehdr->e_shnum; i-- > 0;) {
        Elf64_Shdr* section = &context->elf.elf64.shdr[i];
        if (section->sh_addr >= segment->p_vaddr
            && section->sh_addr < (segment->p_vaddr + segment->p_memsz))
            return i;
    }

    return -1;
}

Elf64_Shdr* initialized_section_header_64(void) {
    Elf64_Shdr* section_header = malloc(sizeof(Elf64_Shdr));
    if (section_header == NULL)
        return NULL;

    section_header->sh_name      = 0;
    section_header->sh_type      = SHT_PROGBITS;
    section_header->sh_flags     = SHF_EXECINSTR | SHF_ALLOC;
    section_header->sh_addr      = 0;
    section_header->sh_offset    = 0;
    section_header->sh_size      = 0;
    section_header->sh_link      = 0;
    section_header->sh_info      = 0;
    section_header->sh_addralign = 16;
    section_header->sh_entsize   = 0;

    return section_header;
}
