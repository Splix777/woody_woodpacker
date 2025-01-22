#include "woody.h"

static uint64_t generate_64_bit_key(void)
{
    uint64_t key = 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        print_verbose(NULL, "Cannot open /dev/urandom\n");
        return 0;
    }

    ssize_t bytes_read = read(fd, &key, sizeof(key));
    if (bytes_read != sizeof(key))
    {
        print_verbose(NULL, "Failed to read from /dev/urandom\n");
        close(fd);
        return 0;
    }

    close(fd);
    return key;
}

static uint32_t generate_32_bit_key(void)
{
    uint32_t key = 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        print_verbose(NULL, "Cannot open /dev/urandom\n");
        return 0;
    }

    ssize_t bytes_read = read(fd, &key, sizeof(key));
    if (bytes_read != sizeof(key))
    {
        print_verbose(NULL, "Failed to read from /dev/urandom\n");
        close(fd);
        return 0;
    }

    close(fd);
    return key;
}

static int generate_key(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        if (!context->encryption.key64)
            context->encryption.key64 = generate_64_bit_key();
        if (context->encryption.key64 == 0)
            return ERR_ENCRYPTION;

        print_verbose(context, "Key: ");
        for (size_t i = 0; i < sizeof(uint64_t); i++)
            print_verbose(context,
                          "%02x",
                          (unsigned char)(context->encryption.key64 >> (i * 8)));
        print_verbose(context, "\n");
    }
    else
    {
        if (!context->encryption.key32)
            context->encryption.key32 = generate_32_bit_key();
        if (context->encryption.key32 == 0)
            return ERR_ENCRYPTION;

        print_verbose(context, "Key: ");
        for (size_t i = 0; i < sizeof(uint32_t); i++)
            print_verbose(context,
                          "%02x",
                          (unsigned char)(context->encryption.key32 >> (i * 8)));
        print_verbose(context, "\n");
    }

    return SUCCESS;
}

static int encrypt_32a(char *data, size_t data_size, uint32_t key)
{
    uint32_t n_rotations = sizeof(uint32_t);
    uint32_t int_bits = sizeof(uint32_t) * 8;

    for (size_t i = 0; i < data_size; i++)
    {
        data[i] ^= (char)key;
        key = (key >> n_rotations) | (key << (int_bits - n_rotations));
    }

    return 0;
}

int encrypt_text_section(t_woody_context *context)
{
    int text_index = find_elf_section_index(context, ".text");
    if (text_index < 0)
    {
        print_verbose(context, "Failed to find .text section to encrypt\n");
        return ERR_ENCRYPTION;
    }
    print_verbose(context, "Encrypting .text - Section %d\n", text_index);

    if (context->elf.is_64bit)
    {
        char *text_data = (char *)context->elf.elf64.section_data[text_index];

        context->elf.elf64.text_size = context->elf.elf64.shdr[text_index].sh_size;
        context->elf.elf64.text_entry = context->elf.elf64.shdr[text_index].sh_addr;

        if (generate_key(context) != SUCCESS)
            return ERR_ENCRYPTION;

        if (encrypt_64(text_data,
                       context->elf.elf64.text_size,
                       context->encryption.key64) != 0)
            return ERR_ENCRYPTION;
    }
    else
    {
        char *text_data = (char *)context->elf.elf32.section_data[text_index];

        context->elf.elf32.text_size = context->elf.elf32.shdr[text_index].sh_size;
        context->elf.elf32.text_entry = context->elf.elf32.shdr[text_index].sh_addr;

        if (generate_key(context) != SUCCESS)
            return ERR_ENCRYPTION;

        if (encrypt_32a(text_data,
                        context->elf.elf32.text_size,
                        context->encryption.key32) != 0)
            return ERR_ENCRYPTION;
    }

    print_verbose(context, "Encrypted .text section\n");
    return SUCCESS;
}
