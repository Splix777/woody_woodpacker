#include "woody.h"

/*
 * ELF section insertion (".woody"):
 *
 * Strategy:
 *  - Locate the last PT_LOAD segment
 *  - Locate the last section that resides within that segment
 *  - Grow the section header table by 1 and insert a new SHT_PROGBITS section
 *    right after that last-in-segment section
 *  - Append ".woody" to the section header string table (.shstrtab)
 *  - Build the payload stub (prepare_payload) and store it as the new section's
 *    data
 *  - Expand the target PT_LOAD segment sizes and permissions so the loader is
 *    mapped executable at runtime
 *
 * Offsets/size note:
 *  We place the injected section at p_offset + p_memsz. If p_memsz > p_filesz
 *  (common when a segment contains BSS), this creates a file "gap" which is
 *  serialized as explicit zeros by write_elf() padding logic.
 */
static int update_string_table(t_woody_context* context) {
    char*  updated_shstrtab;
    char*  new_section_name     = ".woody";
    size_t new_section_name_len = strlen(new_section_name) + 1;

    Elf64_Shdr* shstrtab
        = &context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx];
    size_t shstrtab_size = shstrtab->sh_size;
    char*  shstrtab_data
        = context->elf.elf64.section_data[context->elf.elf64.ehdr->e_shstrndx];

    size_t new_shstrtab_size = shstrtab_size + new_section_name_len;

    updated_shstrtab = realloc(shstrtab_data, new_shstrtab_size);
    if (updated_shstrtab == NULL) {
        print_verbose(context, "Failed to reallocate section data\n");
        return ERR_INJECTION;
    }

    memcpy(updated_shstrtab + shstrtab_size, new_section_name,
        new_section_name_len);

    context->elf.elf64.section_data[context->elf.elf64.ehdr->e_shstrndx]
        = updated_shstrtab;
    context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx].sh_size
        = new_shstrtab_size;

    return SUCCESS;
}

/*
 * When we insert a new section header, all section indices >= insert_at shift by +1.
 * Any section headers that *reference* other section indices (via sh_link/sh_info)
 * must be adjusted conditionally, otherwise tools like readelf will report broken
 * metadata (and debuggers/reloc processing can break).
 */
static void update_section_index_references(t_woody_context* context,
    size_t insert_at) {
    for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
        Elf64_Shdr* sh = &context->elf.elf64.shdr[i];

        switch (sh->sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM:
        case SHT_DYNAMIC:
        case SHT_HASH:
        case SHT_GNU_HASH:
        case SHT_GROUP:
        case SHT_SYMTAB_SHNDX:
            if (sh->sh_link >= insert_at)
                sh->sh_link += 1;
            break;
        case SHT_REL:
        case SHT_RELA:
            if (sh->sh_link >= insert_at)
                sh->sh_link += 1; /* symbol table */
            if (sh->sh_info >= insert_at)
                sh->sh_info += 1; /* relocated section */
            break;
        default:
            break;
        }
    }
}

static int update_segment_values(t_woody_context* context, int segment_index) {
    size_t new_segment_size = context->elf.elf64.phdr[segment_index].p_memsz
        + INJECTION_PAYLOAD_64_SIZE;

    context->elf.elf64.phdr[segment_index].p_filesz = new_segment_size;
    context->elf.elf64.phdr[segment_index].p_memsz  = new_segment_size;
    set_elf_segment_permission(context, segment_index, PF_W | PF_X | PF_R);

    return SUCCESS;
}

static int update_section_values(t_woody_context* context, int section_index) {
    for (int i = section_index + 1; i < context->elf.elf64.ehdr->e_shnum - 1;
         i++) {
        context->elf.elf64.shdr[i + 1].sh_offset = context->elf.elf64.shdr[i].sh_offset
            + context->elf.elf64.shdr[i].sh_size;
    }

    int sh_count = context->elf.elf64.ehdr->e_shnum;
    context->elf.elf64.ehdr->e_shoff
        = context->elf.elf64.shdr[sh_count - 1].sh_offset
        + context->elf.elf64.shdr[sh_count - 1].sh_size;

    return SUCCESS;
}

static int update_text_permissions(t_woody_context* context) {
    /* Despite the name, find_text_section_index() returns a PT_LOAD index. */
    int text_segment_index = find_text_section_index(context);
    if (text_segment_index == -1) {
        print_verbose(context, "Failed to find text section index\n");
        return ERR_INJECTION;
    }

    set_elf_segment_permission(context, text_segment_index, PF_W | PF_X | PF_R);

    return SUCCESS;
}

static int create_new_section(
    t_woody_context* context, int segment_index, int section_index) {
    char**      updated_section_data;
    char*       payload;
    Elf64_Shdr* updated_section_headers;
    const int   old_shnum = (int)context->elf.elf64.ehdr->e_shnum;

    /*
     * We insert a new section header *after* `section_index`.
     * All existing section headers in [insert_at, old_shnum) are shifted by +1.
     */
    const size_t insert_at = (size_t)section_index + 1;
    context->elf.elf64.ehdr->e_shnum = (Elf64_Half)(old_shnum + 1);

    updated_section_headers = realloc(context->elf.elf64.shdr,
        sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum);
    if (updated_section_headers == NULL) {
        print_verbose(context, "Failed to reallocate section headers\n");
        return ERR_INJECTION;
    }
    context->elf.elf64.shdr = updated_section_headers;

    updated_section_data = realloc(context->elf.elf64.section_data,
        sizeof(char*) * context->elf.elf64.ehdr->e_shnum);
    if (updated_section_data == NULL) {
        print_verbose(context, "Failed to reallocate section data\n");
        return ERR_INJECTION;
    }
    context->elf.elf64.section_data = updated_section_data;

    Elf64_Shdr* payload_section = initialized_section_header_64();
    if (payload_section == NULL) {
        print_verbose(context, "Failed to initialize section header\n");
        return ERR_INJECTION;
    }

    payload_section->sh_name
        = context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx].sh_size;
    payload_section->sh_offset = context->elf.elf64.phdr[segment_index].p_offset
        + context->elf.elf64.phdr[segment_index].p_memsz;
    payload_section->sh_addr = context->elf.elf64.phdr[segment_index].p_vaddr
        + context->elf.elf64.phdr[segment_index].p_memsz;
    payload_section->sh_size = INJECTION_PAYLOAD_64_SIZE;

    if ((int)insert_at < old_shnum) {
        const size_t count = (size_t)(old_shnum - (int)insert_at);

        memmove(&context->elf.elf64.shdr[insert_at + 1],
            &context->elf.elf64.shdr[insert_at], count * sizeof(Elf64_Shdr));

        memmove(&context->elf.elf64.section_data[insert_at + 1],
            &context->elf.elf64.section_data[insert_at],
            count * sizeof(char*));
    }

    if (context->elf.elf64.ehdr->e_shstrndx >= insert_at)
        context->elf.elf64.ehdr->e_shstrndx += 1;

    if (update_string_table(context) != SUCCESS) {
        free(payload_section);
        print_verbose(context, "Failed to update string table\n");
        return ERR_INJECTION;
    }

    memcpy(&context->elf.elf64.shdr[insert_at], payload_section,
        sizeof(Elf64_Shdr));

    char* section_data = malloc(payload_section->sh_size);
    if (section_data == NULL) {
        free(payload_section);
        print_verbose(context, "Failed to allocate section data\n");
        return ERR_INJECTION;
    }

    if (update_text_permissions(context) != SUCCESS) {
        free(payload_section);
        free(section_data);
        print_verbose(context, "Failed to update text permissions\n");
        return ERR_INJECTION;
    }

    context->elf.elf64.text_offset           = payload_section->sh_addr;
    context->elf.elf64.payload_section_index = (int)insert_at;

    payload = prepare_payload(context);
    if (payload == NULL) {
        context->elf.elf64.section_data[insert_at] = NULL;
        free(payload_section);
        free(section_data);
        print_verbose(context, "Failed to prepare payload\n");
        return ERR_INJECTION;
    }

    memcpy(section_data, payload, payload_section->sh_size);
    context->elf.elf64.section_data[insert_at] = section_data;

    free(payload_section);
    free(payload);

    update_section_index_references(context, insert_at);

    return SUCCESS;
}

int insert_new_section(t_woody_context* context) {
    if (!context->elf.is_64bit)
        return ERR_INVALID_ELF;

    int last_load_segment = find_last_segment_by_type(context, PT_LOAD);
    if (last_load_segment == -1) {
        print_verbose(context, "Failed to find last load segment\n");
        return ERR_INJECTION;
    }

    int last_section_in_segment
        = find_last_section_in_segment(context, last_load_segment);
    if (last_section_in_segment == -1) {
        print_verbose(context, "Failed to find last section in segment\n");
        return ERR_INJECTION;
    }

    if (create_new_section(context, last_load_segment, last_section_in_segment)
        != SUCCESS) {
        print_verbose(context, "Failed to create new section\n");
        return ERR_INJECTION;
    }

    if (update_segment_values(context, last_load_segment) != SUCCESS) {
        print_verbose(context, "Failed to update segment values\n");
        return ERR_INJECTION;
    }

    if (update_section_values(context, last_section_in_segment) != SUCCESS) {
        print_verbose(context, "Failed to update section values\n");
        return ERR_INJECTION;
    }

    return SUCCESS;
}
