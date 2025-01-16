#include "woody.h"

// To keep track of the bytes written for the padding
size_t offset = 0;

static int open_file(const char *file_path, int flags, int mode)
{
    int fd = open(file_path, flags, mode);
    if (fd < 0)
        return -1;

    return fd;
}

static off_t get_file_size(int fd)
{
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0)
        return 0;

    if ((size_t)file_size > SIZE_MAX)
        return 0;

    if (lseek(fd, 0, SEEK_SET) == -1)
        return 0;

    return file_size;
}

static uint8_t *map_file_to_memory(int fd, size_t file_size, bool shared)
{
    uint8_t *file_buffer = mmap(
        NULL,                                // Let the system choose address
        file_size,                           // File size
        PROT_READ | PROT_WRITE,              // Read and write permissions
        (shared ? MAP_SHARED : MAP_PRIVATE), // Shared or private mapping
        fd,                                  // File descriptor
        0                                    // Offset
    );

    if (file_buffer == MAP_FAILED)
        return NULL;

    return file_buffer;
}

static int load_files_to_memory(t_woody_context *context)
{
    context->file.file_size = get_file_size(context->file.input_fd);
    if (context->file.file_size == 0)
    {
        print_verbose(context,
                      "Error getting FD %d file size\n",
                      context->file.input_fd);
        return ERR_INVALID_BINARY;
    }
    print_verbose(context,
                  "Input file size (bytes): %ld\n",
                  context->file.file_size);

    context->file.file_buff = map_file_to_memory(
        context->file.input_fd,
        context->file.file_size,
        false);
    if (!context->file.file_buff)
    {
        print_verbose(context,
                      "Error mapping file %s to memory\n",
                      context->file.input_file_path);
        return ERR_INVALID_BINARY;
    }
    print_verbose(context, "Input file mapped to memory\n");

    return SUCCESS;
}

static int open_files(t_woody_context *context)
{
    context->file.input_fd = open_file(
        context->file.input_file_path,
        O_RDONLY,
        0644);
    if (context->file.input_fd < 0)
    {
        print_verbose(context, "Error opening input file: %s\n", context->file.input_file_path);
        return ERR_FILE_OPEN;
    }
    print_verbose(context, "Input file FD: %d\n", context->file.input_fd);

    context->file.output_fd = open_file(
        context->file.output_file_path,
        O_RDWR | O_CREAT | O_TRUNC,
        0755);
    if (context->file.output_fd < 0)
    {
        print_verbose(context, "Error opening output file: %s\n", context->file.output_file_path);
        return ERR_FILE_OPEN;
    }
    print_verbose(context, "Output file FD: %d\n", context->file.output_fd);

    return SUCCESS;
}

static int write_to_file(int fd, void *data, size_t data_size)
{
    size_t n_bytes;
    if ((n_bytes = write(fd, data, data_size)) != data_size)
        return -1;
    offset += n_bytes;

    return 1;
}

static void add_zero_padding(int fd, size_t end_offset)
{
    char c = 0;
    while (offset < end_offset)
    {
        write_to_file(fd, &c, sizeof(c));
    }
}

int write_elf(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        print_verbose(context, "Writing 64-bit ELF\n");
        write_to_file(context->file.output_fd, context->elf.elf64.ehdr, sizeof(Elf64_Ehdr));
        add_zero_padding(context->file.output_fd, context->elf.elf64.ehdr->e_phoff);

        print_verbose(context, "Writing 64-bit ELF Program Headers\n");
        write_to_file(context->file.output_fd, context->elf.elf64.phdr, context->elf.elf64.ehdr->e_phnum * sizeof(Elf64_Phdr));

        print_verbose(context, "Writing 64-bit ELF Section Data\n");
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            if (context->elf.elf64.shdr[i].sh_type != SHT_NOBITS)
            {
                add_zero_padding(context->file.output_fd, context->elf.elf64.shdr[i].sh_offset);
                if (i == (size_t)context->elf.elf64.cave_index)
                {
                    write_to_file(context->file.output_fd, context->elf.elf64.section_data[i], context->elf.elf64.shdr[i].sh_size + INJECTION_PAYLOAD_SIZE);
                }
                else
                {
                    write_to_file(context->file.output_fd, context->elf.elf64.section_data[i], context->elf.elf64.shdr[i].sh_size);
                }
            }
        }
        add_zero_padding(context->file.output_fd, context->elf.elf64.ehdr->e_shoff);

        print_verbose(context, "Writing 64-bit ELF Section Headers\n");
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            write_to_file(context->file.output_fd, context->elf.elf64.shdr + i, sizeof(Elf64_Shdr));
        }
    }

    return SUCCESS;
}

int import_context_data(t_woody_context *context)
{
    t_error_code ret;

    if ((ret = open_files(context) != SUCCESS))
        return ret;
    if ((ret = load_files_to_memory(context) != SUCCESS))
        return ret;

    return SUCCESS;
}
