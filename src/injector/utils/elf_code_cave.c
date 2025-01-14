#include "woody.h"

// Find Elf Code Cave Index
static int find_elf_code_cave_index(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        for (int i = 0; i < context->elf.elf64.ehdr->e_shnum - 1; i++)
        {
            if (context->elf.elf64.shdr[i].sh_type == SHT_NOBITS ||
                context->elf.elf64.shdr[i].sh_size == 0)
                continue;

            uint64_t cave_size;
            cave_size = context->elf.elf64.shdr[i + 1].sh_offset -
                        (context->elf.elf64.shdr[i].sh_offset +
                         context->elf.elf64.shdr[i].sh_size);

            print_verbose(context,
                          "Space between section %d and %d: %ld\n",
                          i, i + 1, cave_size);

            if (cave_size >= INJECTION_PAYLOAD_SIZE)
            {
                int segment_index = find_elf_segment_index_by_section(context, i);
                char *section_name = find_elf_section_name(context, i);
                if (context->elf.elf64.phdr[segment_index].p_type == PT_LOAD)
                {
                    print_verbose(
                        context,
                        "Found code cave in section %d, segment %d, with size %ld\n",
                        i, segment_index, cave_size);
                    print_verbose(
                        context,
                        "The cave is in section %s\n",
                        section_name);
                    return i;
                }
            }
        }
    }
    else
    {
        for (int i = 0; i < context->elf.elf32.ehdr->e_shnum - 1; i++)
        {
            if (context->elf.elf32.shdr[i].sh_type == SHT_NOBITS ||
                context->elf.elf32.shdr[i].sh_size == 0)
                continue;

            uint32_t cave_size;
            cave_size = context->elf.elf32.shdr[i + 1].sh_offset -
                        (context->elf.elf32.shdr[i].sh_offset +
                         context->elf.elf32.shdr[i].sh_size);

            print_verbose(context,
                          "Space between section %d and %d: %d\n",
                          i, i + 1, cave_size);

            if (cave_size >= INJECTION_PAYLOAD_SIZE)
            {
                int segment_index = find_elf_segment_index_by_section(context, i);
                char *section_name = find_elf_section_name(context, i);
                if (context->elf.elf32.phdr[segment_index].p_type == PT_LOAD)
                {
                    print_verbose(
                        context,
                        "Found code cave in section %d, segment %d, with size %ld\n",
                        i, segment_index, cave_size);
                    print_verbose(
                        context,
                        "The cave is in section %s\n",
                        section_name);
                    return i;
                }
            }
        }
    }

    print_verbose(context, "No code cave found\n");
    return -1;
}

// Set Elf Segment Permissions
static void set_elf_segment_permission(t_woody_context *context, int index, int flags)
{
    if (context->elf.is_64bit)
        context->elf.elf64.phdr[index].p_flags |= flags;
    else
        context->elf.elf32.phdr[index].p_flags |= flags;
}

// Set cave segment permission
static int adjust_cave_segment_values(t_woody_context *context, int segment_index)
{
    if (context->elf.is_64bit)
    {
        print_verbose(context, "Adjusting segment %d size\n", segment_index);
        context->elf.elf64.phdr[segment_index].p_memsz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf64.phdr[segment_index].p_filesz += INJECTION_PAYLOAD_SIZE;
    }
    else
    {
        print_verbose(context, "Adjusting segment %d size\n", segment_index);
        context->elf.elf32.phdr[segment_index].p_memsz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf32.phdr[segment_index].p_filesz += INJECTION_PAYLOAD_SIZE;
    }

    print_verbose(
        context,
        "Setting segment %d permissions to RWX\n",
        segment_index);
    set_elf_segment_permission(context, segment_index, PF_X | PF_W | PF_R);

    int text_segment_index = find_text_section_index(context);
    if (text_segment_index == -1)
        return -1;

    print_verbose(
        context,
        "Setting text segment %d permissions to RWX\n",
        text_segment_index);
    set_elf_segment_permission(context, text_segment_index, PF_W | PF_R);

    return 0;
}

// Insert payload into code cave
static int cave_insert_payload(t_woody_context *context, int section_index, unsigned int old_section_size)
{
    char *new_section_data;
    unsigned char *payload;

    if (context->elf.is_64bit)
    {
        new_section_data = realloc(
            context->elf.elf64.section_data[section_index],
            old_section_size + INJECTION_PAYLOAD_SIZE);
        if (new_section_data == NULL)
        {
            print_verbose(
                context,
                "Failed to allocate memory for new section data\n");
            return -1;
        }

        context->elf.elf64.section_data[section_index] = new_section_data;

        payload = prepare_payload(context);
        if (payload == NULL)
            return -1;

        memcpy(
            context->elf.elf64.section_data[section_index] + old_section_size,
            payload,
            INJECTION_PAYLOAD_SIZE);

        // Update section size
        context->elf.elf64.shdr[section_index].sh_size += INJECTION_PAYLOAD_SIZE;

        free(payload);
    }

    return SUCCESS;
}

int find_code_cave(t_woody_context *context)
{
    int section_cave_index = find_elf_code_cave_index(context);
    if (section_cave_index == -1)
        return NO_CODE_CAVE;

    if (context->elf.is_64bit)
        context->injection.cave64.section_index = section_cave_index;
    else
        context->injection.cave32.section_index = section_cave_index;

    int segment_cave_index = find_elf_segment_index_by_section(context, section_cave_index);
    if (segment_cave_index == -1)
        return NO_CODE_CAVE;

    if (adjust_cave_segment_values(context, segment_cave_index) == -1)
        return NO_CODE_CAVE;

    unsigned int old_section_size;
    if (context->elf.is_64bit)
        old_section_size = context->elf.elf64.shdr[section_cave_index].sh_size;
    else
        old_section_size = context->elf.elf32.shdr[section_cave_index].sh_size;

    if (cave_insert_payload(context, section_cave_index, old_section_size) == -1)
        return NO_CODE_CAVE;

    if (context->elf.is_64bit)
    {
        context->elf.elf64.ehdr->e_entry = context->elf.elf64.shdr[section_cave_index].sh_addr + old_section_size;
    }
    else
    {
        context->elf.elf32.ehdr->e_entry = context->elf.elf32.shdr[section_cave_index].sh_addr + old_section_size;
    }

    return SUCCESS;
}