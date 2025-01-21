#include "woody.h"

unsigned char jmp_placeholder_64[4] = {0x8e, 0xff, 0xff, 0xff};
uint64_t key_placeholde_64 = 0xaaaaaaaaaaaaaaaa;
uint64_t text_data_entry_placeholder_64 = 0xbbbbbbbbbbbbbbbb;
uint64_t text_data_size_placeholder_64 = 0xcccccccccccccccc;
uint64_t text_data_offset_placeholder_64 = 0xdddddddddddddddd;

unsigned char jmp_placeholder_32[4] = {0x79, 0xff, 0xff, 0x0f};
uint32_t key_placeholder_32 = 0xaaaaaaaa;
uint32_t text_data_entry_placeholder_32 = 0xbbbbbbbb;
uint32_t text_data_size_placeholder_32 = 0xcccccccc;
uint32_t text_data_offset_placeholder_32 = 0xdddddddd;

static uint64_t find_pattern(
    const char *bin,
    size_t size,
    const unsigned char *pattern,
    size_t pattern_size)
{
    if (size < pattern_size || !bin || !pattern)
        return (uint64_t)-1;

    for (uint64_t i = 0; i <= size - pattern_size; i++)
    {
        if (memcmp(bin + i, pattern, pattern_size) == 0)
            return i;
    }
    return (uint64_t)-1;
}

static int validate_offsets(
    t_woody_context *context,
    uint64_t offset,
    size_t required_space,
    const char *what)
{
    if (context->elf.is_64bit)
    {
        if (offset == (uint64_t)-1)
        {
            print_verbose(context, "Failed to find %s placeholder\n", what);
            return -1;
        }

        if (offset + required_space > INJECTION_PAYLOAD_64_SIZE)
        {
            print_verbose(context, "Not enough space for %s (needs %zu bytes)\n",
                          what, required_space);
            return -1;
        }
    }
    else
    {
        if (offset == (uint64_t)-1)
        {
            print_verbose(context, "Failed to find %s placeholder\n", what);
            return -1;
        }

        if (offset + required_space > INJECTION_PAYLOAD_32_SIZE)
        {
            print_verbose(context, "Not enough space for %s (needs %zu bytes)\n",
                          what, required_space);
            return -1;
        }
    }

    return 0;
}

static int patch_key_info(t_woody_context *context, char *patched_bin)
{
    if (context->elf.is_64bit)
    {
        uint64_t key_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_64_SIZE,
            (unsigned char *)&key_placeholde_64,
            sizeof(uint64_t));

        if (validate_offsets(context, key_offset, sizeof(uint64_t), "key") != 0)
            return -1;

        memcpy(patched_bin + key_offset, &context->encryption.key64, sizeof(uint64_t));

        print_verbose(context, "Key: ");
        for (size_t i = 0; i < sizeof(uint64_t); i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[key_offset + i]);
        print_verbose(context, "\n");
    }
    else
    {
        uint64_t key_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_32_SIZE,
            (unsigned char *)&key_placeholder_32,
            sizeof(uint32_t));

        if (validate_offsets(context, key_offset, sizeof(uint32_t), "key") != 0)
            return -1;

        memcpy(patched_bin + key_offset, &context->encryption.key32, sizeof(uint32_t));

        print_verbose(context, "Key: ");
        for (size_t i = 0; i < sizeof(uint32_t); i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[key_offset + i]);
        print_verbose(context, "\n");
    }

    return SUCCESS;
}

static int patch_text_data_entry_info(t_woody_context *context, char *patched_bin)
{
    if (context->elf.is_64bit)
    {
        const size_t entry_size = sizeof(uint64_t);
        uint64_t text_data_entry_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_64_SIZE,
            (unsigned char *)&text_data_entry_placeholder_64,
            entry_size);
        uint64_t text_data_size_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_64_SIZE,
            (unsigned char *)&text_data_size_placeholder_64,
            entry_size);
        uint64_t text_data_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_64_SIZE,
            (unsigned char *)&text_data_offset_placeholder_64,
            entry_size);

        // Validate all offsets
        if (validate_offsets(
                context, text_data_entry_offset, entry_size, "text data entry") != 0 ||
            validate_offsets(
                context, text_data_size_offset, entry_size, "text data size") != 0 ||
            validate_offsets(
                context, text_data_offset, entry_size, "entry offset") != 0)
            return -1;

        memcpy(patched_bin + text_data_entry_offset, &context->elf.elf64.text_entry, entry_size);
        memcpy(patched_bin + text_data_size_offset, &context->elf.elf64.text_size, entry_size);
        memcpy(patched_bin + text_data_offset, &context->elf.elf64.text_offset, entry_size);

        print_verbose(
            context,
            "Text Data Entry: %lx, Size: %lx, Offset: %lx\n",
            context->elf.elf64.text_entry,
            context->elf.elf64.text_size,
            context->elf.elf64.text_offset);
    }
    else
    {
        const size_t entry_size = sizeof(uint32_t);
        uint64_t text_data_entry_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_32_SIZE,
            (unsigned char *)&text_data_entry_placeholder_32,
            entry_size);
        uint64_t text_data_size_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_32_SIZE,
            (unsigned char *)&text_data_size_placeholder_32,
            entry_size);
        uint64_t text_data_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_32_SIZE,
            (unsigned char *)&text_data_offset_placeholder_32,
            entry_size);

        // Validate all offsets
        if (validate_offsets(
                context, text_data_entry_offset, entry_size, "text data entry") != 0 ||
            validate_offsets(
                context, text_data_size_offset, entry_size, "text data size") != 0 ||
            validate_offsets(
                context, text_data_offset, entry_size, "entry offset") != 0)
            return -1;

        memcpy(patched_bin + text_data_entry_offset, &context->elf.elf32.text_entry, entry_size);
        memcpy(patched_bin + text_data_size_offset, &context->elf.elf32.text_size, entry_size);
        memcpy(patched_bin + text_data_offset, &context->elf.elf32.text_offset, entry_size);

        print_verbose(
            context,
            "Text Data Entry: %x, Size: %x, Offset: %x\n",
            context->elf.elf32.text_entry,
            context->elf.elf32.text_size,
            context->elf.elf32.text_offset);
    }

    return SUCCESS;
}

static int patch_entry_point(t_woody_context *context, char *patched_bin)
{
    if (context->elf.is_64bit)
    {
        int32_t jump_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_64_SIZE,
            jmp_placeholder_64,
            sizeof(jmp_placeholder_64));

        if (validate_offsets(context, jump_offset, sizeof(int32_t), "jump") != 0)
            return -1;

        Elf64_Addr new_entry_point;
        Elf64_Addr old_entry_point = context->elf.elf64.ehdr->e_entry;
        Elf64_Shdr relevant_section = context->elf.elf64.shdr[context->elf.elf64.payload_section_index];
        if (context->elf.elf64.cave)
            new_entry_point = relevant_section.sh_addr + relevant_section.sh_size;
        else
            new_entry_point = relevant_section.sh_addr;

        context->elf.elf64.ehdr->e_entry = new_entry_point;

        int32_t jump = old_entry_point - (context->elf.elf64.ehdr->e_entry + INJECTION_PAYLOAD_64_SIZE - 32);

        print_verbose(context, "Jump: %lx\n", jump);

        memcpy(patched_bin + jump_offset, &jump, sizeof(int32_t));
    }
    else
    {
        int32_t jump_offset = find_pattern(
            patched_bin,
            INJECTION_PAYLOAD_32_SIZE,
            jmp_placeholder_32,
            sizeof(jmp_placeholder_32));

        if (validate_offsets(context, jump_offset, sizeof(int32_t), "jump") != 0)
            return -1;

        Elf32_Addr new_entry_point;
        Elf32_Addr old_entry_point = context->elf.elf32.ehdr->e_entry;
        Elf32_Shdr relevant_section = context->elf.elf32.shdr[context->elf.elf32.payload_section_index];
        if (context->elf.elf32.cave)
            new_entry_point = relevant_section.sh_addr + relevant_section.sh_size;
        else
            new_entry_point = relevant_section.sh_addr;

        context->elf.elf32.ehdr->e_entry = new_entry_point;

        int32_t jump = old_entry_point - (context->elf.elf32.ehdr->e_entry + INJECTION_PAYLOAD_32_SIZE - 16);

        print_verbose(context, "Jump: %x\n", jump);

        memcpy(patched_bin + jump_offset, &jump, sizeof(int32_t));
    }

    return SUCCESS;
}

char *prepare_payload(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        char *patched_bin = malloc(INJECTION_PAYLOAD_64_SIZE);
        if (!patched_bin)
        {
            print_verbose(context, "Failed to allocate memory for patched binary\n");
            return NULL;
        }

        memcpy(patched_bin, INJECTION_PAYLOAD_64, INJECTION_PAYLOAD_64_SIZE);

        print_verbose(context, "Payload:\n");
        for (size_t i = 0; i < INJECTION_PAYLOAD_64_SIZE; i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
        print_verbose(context, "\n");

        if (patch_key_info(context, patched_bin) != SUCCESS ||
            patch_text_data_entry_info(context, patched_bin) != SUCCESS ||
            patch_entry_point(context, patched_bin) != SUCCESS)
        {
            free(patched_bin);
            return NULL;
        }

        print_verbose(context, "Patched payload:\n");
        for (size_t i = 0; i < INJECTION_PAYLOAD_64_SIZE; i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
        print_verbose(context, "\n");

        return patched_bin;
    }
    else
    {
        char *patched_bin = malloc(INJECTION_PAYLOAD_32_SIZE);
        if (!patched_bin)
        {
            print_verbose(context, "Failed to allocate memory for patched binary\n");
            return NULL;
        }

        memcpy(patched_bin, INJECTION_PAYLOAD_32, INJECTION_PAYLOAD_32_SIZE);

        print_verbose(context, "Payload:\n");
        for (size_t i = 0; i < INJECTION_PAYLOAD_32_SIZE; i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
        print_verbose(context, "\n");

        if (patch_key_info(context, patched_bin) != SUCCESS ||
            patch_text_data_entry_info(context, patched_bin) != SUCCESS ||
            patch_entry_point(context, patched_bin) != SUCCESS)
        {
            free(patched_bin);
            return NULL;
        }

        print_verbose(context, "Patched payload:\n");
        for (size_t i = 0; i < INJECTION_PAYLOAD_32_SIZE; i++)
            print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
        print_verbose(context, "\n");

        return patched_bin;
    }
}
