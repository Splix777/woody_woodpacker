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

static int
prepare_new_section(t_woody_context *context, int last_segment, int last_section)
{
    if (context->elf.is_64bit)
    {
        Elf64_Phdr *segment_header = &context->elf.elf64.phdr[last_segment];
        Elf64_Shdr *new_section = malloc(sizeof(Elf64_Shdr));

        new_section->sh_name = 0;
        new_section->sh_type = SHT_PROGBITS;
        new_section->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
        new_section->sh_addr = segment_header->p_vaddr + segment_header->p_memsz;
        new_section->sh_offset = segment_header->p_offset + segment_header->p_filesz;
        new_section->sh_size = INJECTION_PAYLOAD_SIZE;
        new_section->sh_link = 0;
        new_section->sh_info = 0;
        new_section->sh_addralign = 16;
        new_section->sh_entsize = 0;

        memcpy(context->elf.elf64.shdr + last_section, new_section, sizeof(Elf64_Shdr));
        context->elf.elf64.text_offset = new_section->sh_addr;
    }
    else
    {
        Elf32_Phdr *segment_header = &context->elf.elf32.phdr[last_segment];
        Elf32_Shdr *new_section = malloc(sizeof(Elf32_Shdr));

        new_section->sh_name = 0;
        new_section->sh_type = SHT_PROGBITS;
        new_section->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
        new_section->sh_addr = segment_header->p_vaddr + segment_header->p_memsz;
        new_section->sh_offset = segment_header->p_offset + segment_header->p_filesz;
        new_section->sh_size = INJECTION_PAYLOAD_SIZE;
        new_section->sh_link = 0;
        new_section->sh_info = 0;
        new_section->sh_addralign = 16;
        new_section->sh_entsize = 0;

        memcpy(context->elf.elf32.shdr + last_section, new_section, sizeof(Elf32_Shdr));
        context->elf.elf32.text_offset = new_section->sh_addr;
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

        payload = prepare_payload(context);
        if (payload == NULL)
        {
            print_verbose(context, "Failed to prepare payload\n");
            return ERR_INJECTION;
        }

        size_t post_insertion_size = sizeof(Elf64_Shdr) * (context->elf.elf64.ehdr->e_shnum - section_index - 1);
        size_t remaining_section_size = sizeof(char *) * (context->elf.elf64.ehdr->e_shnum - section_index - 1);

        memmove(context->elf.elf64.shdr + section_index + 1, context->elf.elf64.shdr + section_index, post_insertion_size);
        memmove(context->elf.elf64.section_data + section_index + 1, context->elf.elf64.section_data + section_index, remaining_section_size);

        section_index += 1;

        if (context->elf.elf64.ehdr->e_shstrndx >= section_index)
            context->elf.elf64.ehdr->e_shstrndx += 1;

    }
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

    return SUCCESS;
}