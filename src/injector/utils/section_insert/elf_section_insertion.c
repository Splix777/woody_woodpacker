#include "woody.h"

static int update_string_table(t_woody_context *context)
{
    char *updated_shstrtab;
    char *new_section_name = ".woody";
    size_t new_section_name_len = strlen(new_section_name) + 1;

    if (context->elf.is_64bit)
    {
        Elf64_Shdr *shstrtab = &context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx];
        size_t shstrtab_size = shstrtab->sh_size;
        char *shstrtab_data = context->elf.elf64.section_data[context->elf.elf64.ehdr->e_shstrndx];

        size_t new_shstrtab_size = shstrtab_size + new_section_name_len;

        updated_shstrtab = realloc(shstrtab_data, new_shstrtab_size);
        if (updated_shstrtab == NULL)
        {
            print_verbose(context, "Failed to reallocate section data\n");
            return ERR_INJECTION;
        }
        memcpy(updated_shstrtab + shstrtab_size, new_section_name, new_section_name_len);

        context->elf.elf64.section_data[context->elf.elf64.ehdr->e_shstrndx] = updated_shstrtab;
        context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx].sh_size = new_shstrtab_size;
    }
    else
    {
        Elf32_Shdr *shstrtab = &context->elf.elf32.shdr[context->elf.elf32.ehdr->e_shstrndx];
        size_t shstrtab_size = shstrtab->sh_size;
        char *shstrtab_data = context->elf.elf32.section_data[context->elf.elf32.ehdr->e_shstrndx];

        size_t new_shstrtab_size = shstrtab_size + new_section_name_len;

        updated_shstrtab = realloc(shstrtab_data, new_shstrtab_size);
        if (updated_shstrtab == NULL)
        {
            print_verbose(context, "Failed to reallocate section data\n");
            return ERR_INJECTION;
        }
        memcpy(updated_shstrtab + shstrtab_size, new_section_name, new_section_name_len);

        context->elf.elf32.section_data[context->elf.elf32.ehdr->e_shstrndx] = updated_shstrtab;
        context->elf.elf32.shdr[context->elf.elf32.ehdr->e_shstrndx].sh_size = new_shstrtab_size;
    }

    return SUCCESS;
}

static int update_symtab_sh_link(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            char *section_name = find_elf_section_name(context, i);
            if (strcmp(section_name, ".symtab") == 0)
                context->elf.elf64.shdr[i].sh_link += 1;
        }
    }
    else
    {
        for (size_t i = 0; i < context->elf.elf32.ehdr->e_shnum; i++)
        {
            char *section_name = find_elf_section_name(context, i);
            if (strcmp(section_name, ".symtab") == 0)
                context->elf.elf32.shdr[i].sh_link += 1;
        }
    }

    return SUCCESS;
}

static int update_section_symtab_sh_link_count(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
            if (context->elf.elf64.shdr[i].sh_type == SHT_SYMTAB)
                context->elf.elf64.shdr[i].sh_link += 1;
    }
    else
    {
        for (size_t i = 0; i < context->elf.elf32.ehdr->e_shnum; i++)
            if (context->elf.elf32.shdr[i].sh_type == SHT_SYMTAB)
                context->elf.elf32.shdr[i].sh_link += 1;
    }

    return SUCCESS;
}

static int update_segment_values(t_woody_context *context, int segment_index)
{
    if (context->elf.is_64bit)
    {
        context->elf.elf64.phdr[segment_index].p_filesz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf64.phdr[segment_index].p_memsz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf64.phdr[segment_index].p_flags |= PF_W;
        context->elf.elf64.phdr[segment_index].p_flags |= PF_X;
        context->elf.elf64.phdr[segment_index].p_flags |= PF_R;
    }
    else
    {
        context->elf.elf32.phdr[segment_index].p_filesz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf32.phdr[segment_index].p_memsz += INJECTION_PAYLOAD_SIZE;
        context->elf.elf32.phdr[segment_index].p_flags |= PF_W;
        context->elf.elf32.phdr[segment_index].p_flags |= PF_X;
        context->elf.elf32.phdr[segment_index].p_flags |= PF_R;
    }

    return SUCCESS;
}

static int update_section_values(t_woody_context *context, int section_index)
{
    if (context->elf.is_64bit)
    {
        for (int i = section_index + 1; i < context->elf.elf64.ehdr->e_shnum - 1; i++)
            context->elf.elf64.shdr[i + 1].sh_offset = context->elf.elf64.shdr[i].sh_offset + context->elf.elf64.shdr[i].sh_size;

        int sh_count = context->elf.elf64.ehdr->e_shnum;
        context->elf.elf64.ehdr->e_shoff = context->elf.elf64.shdr[sh_count - 1].sh_offset + context->elf.elf64.shdr[sh_count - 1].sh_size;
    }
    else
    {
        for (int i = section_index + 1; i < context->elf.elf32.ehdr->e_shnum - 1; i++)
            context->elf.elf32.shdr[i + 1].sh_offset = context->elf.elf32.shdr[i].sh_offset + context->elf.elf32.shdr[i].sh_size;

        int sh_count = context->elf.elf32.ehdr->e_shnum;
        context->elf.elf32.ehdr->e_shoff = context->elf.elf32.shdr[sh_count - 1].sh_offset + context->elf.elf32.shdr[sh_count - 1].sh_size;
    }

    return SUCCESS;
}

static int create_new_section(t_woody_context *context, int segment_index, int section_index)
{
    char **updated_section_data;
    char *payload;

    if (context->elf.is_64bit)
    {
        Elf64_Shdr *updated_section_headers;
        context->elf.elf64.ehdr->e_shnum += 1;

        // Resize section headers and section data
        updated_section_headers = realloc(context->elf.elf64.shdr, sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum);
        if (updated_section_headers == NULL)
        {
            print_verbose(context, "Failed to reallocate section headers\n");
            return ERR_INJECTION;
        }
        context->elf.elf64.shdr = updated_section_headers;

        updated_section_data = realloc(context->elf.elf64.section_data, sizeof(char *) * context->elf.elf64.ehdr->e_shnum);
        if (updated_section_data == NULL)
        {
            print_verbose(context, "Failed to reallocate section data\n");
            return ERR_INJECTION;
        }
        context->elf.elf64.section_data = updated_section_data;

        // Create new section header where the payload will be injected
        Elf64_Shdr *payload_section = initialized_section_header_64();
        if (payload_section == NULL)
        {
            print_verbose(context, "Failed to initialize new section header\n");
            return ERR_INJECTION;
        }
        payload_section->sh_name = context->elf.elf64.shdr[context->elf.elf64.ehdr->e_shstrndx].sh_size;
        payload_section->sh_offset = context->elf.elf64.phdr[segment_index].p_offset + context->elf.elf64.phdr[segment_index].p_filesz;
        payload_section->sh_addr = context->elf.elf64.phdr[segment_index].p_vaddr + context->elf.elf64.phdr[segment_index].p_memsz;
        payload_section->sh_size = INJECTION_PAYLOAD_SIZE;

        context->elf.elf64.text_offset = payload_section->sh_addr;

        payload = prepare_payload(context);
        if (payload == NULL)
        {
            print_verbose(context, "Failed to prepare payload\n");
            return ERR_INJECTION;
        }

        // Calculate remaining size to move for section headers and section data
        size_t remaining_size_to_move = (context->elf.elf64.ehdr->e_shnum - section_index - 1);

        // Move the section headers to create space for the new section header
        memmove(&context->elf.elf64.shdr[section_index + 1],
                &context->elf.elf64.shdr[section_index],
                remaining_size_to_move * sizeof(Elf64_Shdr));

        // Move the section data pointers to make room for the new section data
        memmove(&context->elf.elf64.section_data[section_index + 1],
                &context->elf.elf64.section_data[section_index],
                remaining_size_to_move * sizeof(char *)); // Multiply by size of pointer

        section_index += 1;

        // If the section name string table needs to be updated
        if (context->elf.elf64.ehdr->e_shstrndx >= section_index)
            context->elf.elf64.ehdr->e_shstrndx += 1;

        // Update the string table to include the new section name
        if (update_string_table(context) != SUCCESS)
        {
            print_verbose(context, "Failed to update string table\n");
            return ERR_INJECTION;
        }

        // Insert the new section header
        memcpy(&context->elf.elf64.shdr[section_index], payload_section, sizeof(Elf64_Shdr));

        char *section_data = malloc(payload_section->sh_size);
        if (section_data == NULL)
        {
            free(payload);
            free(payload_section);
            print_verbose(context, "Failed to allocate section data\n");
            return ERR_INJECTION;
        }
        memcpy(section_data, payload, payload_section->sh_size);
        context->elf.elf64.section_data[section_index] = section_data;

        free(payload_section);
    }
    else
    {
        Elf32_Shdr *updated_section_headers;
        context->elf.elf32.ehdr->e_shnum += 1;

        // Resize section headers and section data
        updated_section_headers = realloc(context->elf.elf32.shdr, sizeof(Elf32_Shdr) * context->elf.elf32.ehdr->e_shnum);
        if (updated_section_headers == NULL)
        {
            print_verbose(context, "Failed to reallocate section headers\n");
            return ERR_INJECTION;
        }
        context->elf.elf32.shdr = updated_section_headers;

        updated_section_data = realloc(context->elf.elf32.section_data, sizeof(char *) * context->elf.elf32.ehdr->e_shnum);
        if (updated_section_data == NULL)
        {
            print_verbose(context, "Failed to reallocate section data\n");
            return ERR_INJECTION;
        }
        context->elf.elf32.section_data = updated_section_data;

        // Create new section header where the payload will be injected
        Elf32_Shdr *payload_section = initialized_section_header_32();
        if (payload_section == NULL)
        {
            print_verbose(context, "Failed to initialize new section header\n");
            return ERR_INJECTION;
        }
        payload_section->sh_name = context->elf.elf32.shdr[context->elf.elf32.ehdr->e_shstrndx].sh_size;
        payload_section->sh_offset = context->elf.elf32.phdr[segment_index].p_offset + context->elf.elf32.phdr[segment_index].p_memsz;
        payload_section->sh_addr = context->elf.elf32.phdr[segment_index].p_vaddr + context->elf.elf32.phdr[segment_index].p_memsz;
        payload_section->sh_size = INJECTION_PAYLOAD_SIZE;

        context->elf.elf32.text_offset = payload_section->sh_addr;

        payload = prepare_payload(context);
        if (payload == NULL)
        {
            print_verbose(context, "Failed to prepare payload\n");
            return ERR_INJECTION;
        }

        // Calculate remaining size to move for section headers and section data
        size_t remaining_size_to_move = (context->elf.elf32.ehdr->e_shnum - section_index - 1) * sizeof(Elf32_Shdr);
        size_t remaining_count = (context->elf.elf32.ehdr->e_shnum - section_index - 1);

        // Move the section headers to create space for the new section header
        memmove(&context->elf.elf32.shdr[section_index + 2],
                &context->elf.elf32.shdr[section_index + 1],
                remaining_size_to_move);
        memmove(&context->elf.elf32.section_data[section_index + 2],
                &context->elf.elf32.section_data[section_index + 1],
                remaining_count * sizeof(char *)); // Multiply by size of pointer

        section_index += 1;

        // If the section name string table needs to be updated
        if (context->elf.elf32.ehdr->e_shstrndx >= section_index)
            context->elf.elf32.ehdr->e_shstrndx += 1;

        // Update the string table to include the new section name
        if (update_string_table(context) != SUCCESS)
        {
            print_verbose(context, "Failed to update string table\n");
            return ERR_INJECTION;
        }

        // Insert the new section header
        memcpy(&context->elf.elf32.shdr[section_index], payload_section, sizeof(Elf32_Shdr));

        char *section_data = malloc(payload_section->sh_size);
        if (section_data == NULL)
        {
            free(payload);
            free(payload_section);
            print_verbose(context, "Failed to allocate section data\n");
            return ERR_INJECTION;
        }
        memcpy(section_data, payload, payload_section->sh_size);
        context->elf.elf32.section_data[section_index] = section_data;
    }
    free(payload);

    if (update_symtab_sh_link(context) != SUCCESS)
    {
        print_verbose(context, "Failed to update symtab sh_link\n");
        return ERR_INJECTION;
    }

    if (update_section_symtab_sh_link_count(context) != SUCCESS)
    {
        print_verbose(context, "Failed to update section symtab sh_link count\n");
        return ERR_INJECTION;
    }

    return SUCCESS;
}

int insert_new_section(t_woody_context *context)
{
    int last_load_segment = find_last_segment_by_type(context, PT_LOAD);
    if (last_load_segment == -1)
    {
        print_verbose(context, "Failed to find last load segment\n");
        return ERR_INJECTION;
    }

    int last_section_in_segment = find_last_section_in_segment(context, last_load_segment);
    if (last_section_in_segment == -1)
    {
        print_verbose(context, "Failed to find last section in segment\n");
        return ERR_INJECTION;
    }

    if (create_new_section(context, last_load_segment, last_section_in_segment) != SUCCESS)
    {
        print_verbose(context, "Failed to create new section\n");
        return ERR_INJECTION;
    }

    if (update_segment_values(context, last_load_segment) != SUCCESS)
    {
        print_verbose(context, "Failed to update segment values\n");
        return ERR_INJECTION;
    }

    if (update_section_values(context, last_section_in_segment) != SUCCESS)
    {
        print_verbose(context, "Failed to update section values\n");
        return ERR_INJECTION;
    }

    if (update_entry_point(context, last_section_in_segment + 1) != SUCCESS)
    {
        print_verbose(context, "Failed to update entry point\n");
        return ERR_INJECTION;
    }

    return SUCCESS;
}