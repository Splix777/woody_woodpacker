#include "woody.h"

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
        0644);
    if (context->file.output_fd < 0)
    {
        print_verbose(context, "Error opening output file: %s\n", context->file.output_file_path);
        return ERR_FILE_OPEN;
    }
    print_verbose(context, "Output file FD: %d\n", context->file.output_fd);

    return SUCCESS;
}

int write_output_file(t_woody_context *context)
{
    // We will write the output file from our struct.
    // First we will write the ELF header, then the program header table, then the section header table, and finally the section data.

    // Write the ELF header
    size_t written = write(context->file.output_fd, context->elf.elf64.ehdr, sizeof(Elf64_Ehdr));
    if (written != sizeof(Elf64_Ehdr))
    {
        print_verbose(context, "Failed to write ELF header\n");
        return ERR_FILE_WRITE;
    }

    // Write the program header table
    written = write(context->file.output_fd, context->elf.elf64.phdr, sizeof(Elf64_Phdr) * context->elf.elf64.ehdr->e_phnum);
    if (written != sizeof(Elf64_Phdr) * context->elf.elf64.ehdr->e_phnum)
    {
        print_verbose(context, "Failed to write program header table\n");
        return ERR_FILE_WRITE;
    }

    // Write the section data
    for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
    {
        if (context->elf.elf64.section_data[i] == NULL)
            continue;

        written = write(context->file.output_fd, context->elf.elf64.section_data[i], context->elf.elf64.shdr[i].sh_size);
        if (written != context->elf.elf64.shdr[i].sh_size)
        {
            print_verbose(context, "Failed to write section data for section %ld\n", i);
            return ERR_FILE_WRITE;
        }
    }

    // Write the section header table
    written = write(context->file.output_fd, context->elf.elf64.shdr, sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum);
    if (written != sizeof(Elf64_Shdr) * context->elf.elf64.ehdr->e_shnum)
    {
        print_verbose(context, "Failed to write section header table\n");
        return ERR_FILE_WRITE;
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
