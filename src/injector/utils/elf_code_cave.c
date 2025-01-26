#include "woody.h"

static unsigned int calculate_cave_size(t_woody_context* context, int i) {
    if (context->elf.is_64bit) {
        if (i == (context->elf.elf64.ehdr->e_shnum - 1)) {
            return context->elf.elf64.ehdr->e_shoff
                - (context->elf.elf64.shdr[i].sh_offset
                    + context->elf.elf64.shdr[i].sh_size);
        } else {
            return context->elf.elf64.shdr[i + 1].sh_offset
                - (context->elf.elf64.shdr[i].sh_offset
                    + context->elf.elf64.shdr[i].sh_size);
        }
    } else {
        if (i == (context->elf.elf32.ehdr->e_shnum - 1)) {
            return context->elf.elf32.ehdr->e_shoff
                - (context->elf.elf32.shdr[i].sh_offset
                    + context->elf.elf32.shdr[i].sh_size);
        } else {
            return context->elf.elf32.shdr[i + 1].sh_offset
                - (context->elf.elf32.shdr[i].sh_offset
                    + context->elf.elf32.shdr[i].sh_size);
        }
    }
}

static int find_elf_code_cave_index(t_woody_context* context) {
    int num_sections = context->elf.is_64bit
        ? context->elf.elf64.ehdr->e_shnum
        : context->elf.elf32.ehdr->e_shnum;
    int payload_size = context->elf.is_64bit ? INJECTION_PAYLOAD_64_SIZE
                                             : INJECTION_PAYLOAD_32_SIZE;

    for (int i = 0; i < num_sections - 1; i++) {
        if ((context->elf.is_64bit
                && (context->elf.elf64.shdr[i].sh_type == SHT_NOBITS
                    || context->elf.elf64.shdr[i].sh_size == 0))
            || (!context->elf.is_64bit
                && (context->elf.elf32.shdr[i].sh_type == SHT_NOBITS
                    || context->elf.elf32.shdr[i].sh_size == 0))) {
            continue;
        }

        unsigned int cave_size = calculate_cave_size(context, i);
        print_verbose(context, "Space between section %d and %d: %u\n", i,
            i + 1, cave_size);

        if (cave_size >= (unsigned int)payload_size) {
            int segment_index = find_elf_segment_index_by_section(context, i);
            if (segment_index != -1
                && (context->elf.is_64bit
                        ? context->elf.elf64.phdr[segment_index].p_type
                            == PT_LOAD
                        : context->elf.elf32.phdr[segment_index].p_type
                            == PT_LOAD)) {
                print_verbose(context,
                    "Found code cave in section %d, segment %d, "
                    "with size %u\n",
                    i, segment_index, cave_size);
                return i;
            }
        }
    }

    print_verbose(context, "No code cave found\n");
    return -1;
}

static int adjust_cave_segment_values(
    t_woody_context* context, int segment_index) {
    int payload_size = context->elf.is_64bit ? INJECTION_PAYLOAD_64_SIZE
                                             : INJECTION_PAYLOAD_32_SIZE;

    print_verbose(context, "Adjusting segment %d size\n", segment_index);
    if (context->elf.is_64bit) {
        context->elf.elf64.phdr[segment_index].p_memsz += payload_size;
        context->elf.elf64.phdr[segment_index].p_filesz += payload_size;
    } else {
        context->elf.elf32.phdr[segment_index].p_memsz += payload_size;
        context->elf.elf32.phdr[segment_index].p_filesz += payload_size;
    }

    print_verbose(
        context, "Setting segment %d permissions to RWX\n", segment_index);
    set_elf_segment_permission(context, segment_index, PF_W | PF_X);

    int text_segment_index = find_text_section_index(context);
    if (text_segment_index == -1)
        return -1;

    print_verbose(context, "Setting text segment %d permissions to RWX\n",
        text_segment_index);
    set_elf_segment_permission(context, text_segment_index, PF_W);

    return SUCCESS;
}

static int cave_insert_payload(t_woody_context* context, int section_index) {
    int    payload_size     = context->elf.is_64bit ? INJECTION_PAYLOAD_64_SIZE
                                                    : INJECTION_PAYLOAD_32_SIZE;
    int    old_section_size = context->elf.is_64bit
           ? context->elf.elf64.shdr[section_index].sh_size
           : context->elf.elf32.shdr[section_index].sh_size;
    size_t new_size         = old_section_size + payload_size;

    char* new_section_data = realloc(context->elf.is_64bit
            ? context->elf.elf64.section_data[section_index]
            : context->elf.elf32.section_data[section_index],
        new_size);
    if (new_section_data == NULL) {
        print_verbose(
            context, "Failed to reallocate memory for new section data\n");
        return ERR_MEMORY_ALLOC;
    }

    if (context->elf.is_64bit) {
        context->elf.elf64.section_data[section_index] = new_section_data;
        context->elf.elf64.text_offset
            = context->elf.elf64.shdr[section_index].sh_addr
            + old_section_size;
        context->elf.elf64.cave = true;
    } else {
        context->elf.elf32.section_data[section_index] = new_section_data;
        context->elf.elf32.text_offset
            = context->elf.elf32.shdr[section_index].sh_addr
            + old_section_size;
        context->elf.elf32.cave = true;
    }

    char* payload = prepare_payload(context);
    if (payload == NULL)
        return ERR_MEMORY_ALLOC;

    memcpy(new_section_data + old_section_size, payload, payload_size);
    free(payload);

    return SUCCESS;
}

int find_code_cave(t_woody_context* context) {
    int section_cave_index = find_elf_code_cave_index(context);
    if (section_cave_index == -1)
        return NO_CODE_CAVE;

    if (context->elf.is_64bit)
        context->elf.elf64.payload_section_index = section_cave_index;
    else
        context->elf.elf32.payload_section_index = section_cave_index;

    int segment_cave_index
        = find_elf_segment_index_by_section(context, section_cave_index);
    if (segment_cave_index == -1)
        return NO_CODE_CAVE;

    if (adjust_cave_segment_values(context, segment_cave_index) != SUCCESS)
        return NO_CODE_CAVE;

    if (cave_insert_payload(context, section_cave_index) != SUCCESS)
        return NO_CODE_CAVE;

    return SUCCESS;
}