#include "woody.h"

/*
 * File IO helpers:
 *  - Open input/output
 *  - mmap() input into memory for validation / parsing
 *  - Serialize the modified ELF back to disk with correct padding
 *
 * write_elf() writes a "fresh" ELF from the in-memory structures rather than
 * patching the original file in-place. It emits:
 *  [ELF header] -> [zero padding to e_phoff] -> [program headers]
 *  -> [each section's data at sh_offset (with zero padding between)]
 *  -> [zero padding to e_shoff] -> [section headers]
 *
 * The padding matters because injection can push section data/headers forward,
 * and (by design) this implementation may materialize gaps (e.g. BSS-sized
 * regions) as explicit zeros in the output file.
 */
static int open_file(const char* file_path, int flags, int mode) {
    int fd = open(file_path, flags, mode);
    if (fd < 0)
        return -1;

    return fd;
}

static off_t get_file_size(int fd) {
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0)
        return 0;

    if ((size_t)file_size > SIZE_MAX)
        return 0;

    if (lseek(fd, 0, SEEK_SET) == -1)
        return 0;

    return file_size;
}

static uint8_t* map_file_to_memory(int fd, size_t file_size, bool shared) {
    uint8_t* file_buffer = mmap(NULL, // Let the system choose address
        file_size, // File size
        PROT_READ | PROT_WRITE, // Read and write permissions
        (shared ? MAP_SHARED : MAP_PRIVATE), // Shared or private mapping
        fd, // File descriptor
        0 // Offset
    );

    if (file_buffer == MAP_FAILED)
        return NULL;

    return file_buffer;
}

static int load_files_to_memory(t_woody_context* context) {
    context->file.file_size = get_file_size(context->file.input_fd);
    if (context->file.file_size == 0) {
        print_verbose(context, "Error getting FD %d file size\n",
            context->file.input_fd);
        return ERR_INVALID_BINARY;
    }
    print_verbose(
        context, "Input file size (bytes): %ld\n", context->file.file_size);

    context->file.file_buff = map_file_to_memory(
        context->file.input_fd, context->file.file_size, false);
    if (!context->file.file_buff) {
        print_verbose(context, "Error mapping file %s to memory\n",
            context->file.input_file_path);
        return ERR_INVALID_BINARY;
    }
    print_verbose(context, "File %s mapped to memory at %p\n",
        context->file.input_file_path, context->file.file_buff);

    return SUCCESS;
}

static int open_files(t_woody_context* context) {
    context->file.input_fd
        = open_file(context->file.input_file_path, O_RDONLY, 0644);
    if (context->file.input_fd < 0) {
        print_verbose(context, "Error opening input file: %s\n",
            context->file.input_file_path);
        return ERR_FILE_OPEN;
    }
    print_verbose(context, "%s Input file: %s - FD(%d)\n", BOXED_ARROW_RIGHT,
        context->file.input_file_path, context->file.input_fd);

    context->file.output_fd = open_file(
        context->file.output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (context->file.output_fd < 0) {
        print_verbose(context, "Error opening output file: %s\n",
            context->file.output_file_path);
        close(context->file.input_fd);
        context->file.input_fd = -1;
        return ERR_FILE_OPEN;
    }
    print_verbose(context, "%s Output file: %s - FD(%d)\n", BOXED_ARROW_LEFT,
        context->file.output_file_path, context->file.output_fd);

    return SUCCESS;
}

static int write_to_file(
    int fd, const void* data, size_t data_size, size_t* offset) {
    const uint8_t* ptr       = (const uint8_t*)data;
    size_t         total_out = 0;

    /* write(2) may write fewer bytes than requested; loop until complete. */
    while (total_out < data_size) {
        ssize_t n_bytes = write(fd, ptr + total_out, data_size - total_out);
        if (n_bytes <= 0)
            return -1;
        total_out += (size_t)n_bytes;
    }

    *offset += total_out;
    return 0;
}

static int add_zero_padding(int fd, size_t end_offset, size_t* offset) {
    char c = 0;
    while (*offset < end_offset) {
        if (write_to_file(fd, &c, sizeof(c), offset) != 0)
            return -1;
    }
    return 0;
}

int write_elf(t_woody_context* context) {
    // Static offset to track progress
    static size_t offset = 0;
    offset               = 0;

    if (context->elf.is_64bit) {
        print_verbose(context, "Writing 64-bit ELF\n");
        if (write_to_file(context->file.output_fd, context->elf.elf64.ehdr,
                sizeof(Elf64_Ehdr), &offset)
            != 0)
            return ERR_FILE_WRITE;
        if (add_zero_padding(context->file.output_fd,
                context->elf.elf64.ehdr->e_phoff, &offset)
            != 0)
            return ERR_FILE_WRITE;

        print_verbose(context, "Writing 64-bit ELF Program Headers\n");
        if (write_to_file(context->file.output_fd, context->elf.elf64.phdr,
                sizeof(Elf64_Phdr) * context->elf.elf64.ehdr->e_phnum, &offset)
            != 0)
            return ERR_FILE_WRITE;

        print_verbose(context, "Writing 64-bit ELF Section Data\n");
        for (int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++) {
            if (context->elf.elf64.shdr[i].sh_type != SHT_NOBITS) {
                if (add_zero_padding(context->file.output_fd,
                        context->elf.elf64.shdr[i].sh_offset, &offset)
                    != 0)
                    return ERR_FILE_WRITE;
                if (i == context->elf.elf64.payload_section_index
                    && context->elf.elf64.cave) {
                    if (write_to_file(context->file.output_fd,
                            context->elf.elf64.section_data[i],
                            context->elf.elf64.shdr[i].sh_size
                                + INJECTION_PAYLOAD_64_SIZE,
                            &offset)
                        != 0)
                        return ERR_FILE_WRITE;
                } else {
                    if (write_to_file(context->file.output_fd,
                            context->elf.elf64.section_data[i],
                            context->elf.elf64.shdr[i].sh_size, &offset)
                        != 0)
                        return ERR_FILE_WRITE;
                }
            }
        }
        if (add_zero_padding(context->file.output_fd,
                context->elf.elf64.ehdr->e_shoff, &offset)
            != 0)
            return ERR_FILE_WRITE;

        print_verbose(context, "Writing 64-bit ELF Section Headers\n");
        for (int i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
            if (write_to_file(context->file.output_fd,
                    &context->elf.elf64.shdr[i], sizeof(Elf64_Shdr), &offset)
                != 0)
                return ERR_FILE_WRITE;
    } else {
        return ERR_INVALID_ELF;
    }

    return SUCCESS;
}

int import_context_data(t_woody_context* context) {
    t_error_code ret;

    if ((ret = open_files(context)) != SUCCESS)
        return ret;
    if ((ret = load_files_to_memory(context)) != SUCCESS)
        return ret;

    return SUCCESS;
}
