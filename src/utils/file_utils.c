// src/utils/file_utils.c

#include "woody.h"    // t_woody_context, ERR_FILE_OPEN
#include <fcntl.h>    // open, O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC
#include <unistd.h>   // close, lseek, SEEK_END, SEEK_SET, SEEK_CUR
#include <sys/mman.h> // mmap
#include <errno.h>    // errno

bool load_file_to_memory(t_woody_context *context)
{
    if (!context)
    {
        fprintf(stderr, "Error: context is NULL\n");
        return false;
    }

    // Open input file
    context->input_fd = open(context->input_file_path, O_RDONLY);
    if (context->input_fd < 0)
    {
        perror("Error opening input file");
        context->error_code = ERR_FILE_OPEN;
        return false;
    }

    // We use off_t for file size to handle large files
    off_t file_size = lseek(context->input_fd, 0, SEEK_END);
    if (file_size < 0)
    {
        perror("Error getting file size");
        close(context->input_fd);
        context->error_code = ERR_FILE_OPEN;
        return false;
    }

    // Check if file size fits into size_t
    if (file_size < 0 || (size_t)file_size > SIZE_MAX)
    {
        fprintf(stderr, "Error: File size exceeds maximum size_t value\n");
        close(context->input_fd);
        context->error_code = ERR_OVERFLOW;
        return false;
    }
    // Cast file size to size_t for buffer allocation
    context->file_size = (size_t)file_size;

    // Reset file position to start
    if (lseek(context->input_fd, 0, SEEK_SET) == -1)
    {
        perror("Error resetting file position");
        close(context->input_fd);
        context->error_code = ERR_FILE_OPEN;
        return false;
    }

    // Load input file into buffer using mmap
    context->file_buffer = mmap(
        NULL, // Allow auto memory mapping
        context->file_size,
        PROT_READ | PROT_WRITE, // Read | Write permissions
        MAP_PRIVATE,            // Private since we wont be modifying original file
        context->input_fd,
        0);
    if (context->file_buffer == MAP_FAILED)
    {
        perror("Error mapping file");
        close(context->input_fd);
        context->error_code = (errno == EOVERFLOW) ? ERR_OVERFLOW : ERR_FILE_OPEN;
        return false;
    }

    // Open output file
    context->output_fd = open(context->output_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (context->output_fd < 0)
    {
        perror("Error opening output file");
        munmap(context->file_buffer, context->file_size);
        close(context->input_fd);
        context->error_code = ERR_FILE_OPEN;
        return false;
    }

    return true;
}