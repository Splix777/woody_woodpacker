#ifndef WOODY_H
#define WOODY_H

#include <stdint.h>    // uint8_t for byte manipulation
#include <stdio.h>     // FILE, fopen, fclose, fread, fwrite
#include <stdbool.h>   // bool, true, false
#include <unistd.h>    // for file operations
#include <sys/types.h> // for off_t
#include <string.h>    // for string manipulation
#include <stdlib.h>    // for dynamic memory allocation
#include <fcntl.h>     // for file operations
#include <sys/mman.h>  // mmap
#include <elf.h>       // ELF header structures
#include <errno.h>     // errno
#include <ctype.h>     // isalnum
#include <time.h>      // time
#include <stdarg.h>    // va_list, va_start, va_end
#include "error_codes.h"
#include "payload.h"
#include "colors.h"

// Standard Output File Name
#define OUTPUT_FILE_NAME "woody"

typedef struct s_elf64
{
    Elf64_Ehdr *ehdr;    // ELF Header
    Elf64_Phdr *phdr;    // Program Header
    Elf64_Shdr *shdr;    // Section Header
    char **section_data; // Section data (Actual data in the sections)

    int payload_section_index; // Code cave index
    bool cave;                 // Flag to indicate code cave
    uint64_t text_size;        // Size of the .text section
    uint64_t text_entry;       // Entry point of the .text section
    uint64_t text_offset;      // Offset of the .text section
} t_elf64;

typedef struct s_elf32
{
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    char **section_data;

    int payload_section_index;
    bool cave;
    uint32_t text_size;
    uint32_t text_entry;
    uint32_t text_offset;
} t_elf32;

typedef struct s_woody_context
{
    // File handling
    struct
    {
        const char *input_file_path;  // Path to the input ELF file
        const char *output_file_path; // Path to the output "woody" file
        int input_fd;                 // Input file descriptor
        int output_fd;                // Output file descriptor
        uint8_t *file_buff;           // Buffer for the ELF file
        size_t file_size;             // Size of the input file
    } file;

    // ELF-specific data
    struct
    {
        bool is_64bit; // Flag to indicate 64-bit ELF
        t_elf64 elf64; // ELF64 data
        t_elf32 elf32; // ELF32 data
    } elf;

    // Encryption
    struct
    {
        uint64_t key64;
        uint32_t key32;
    } encryption;

    // State and metadata
    t_error_code error_code; // Error code for context state
    bool verbose;            // Flag to enable verbose output
} t_woody_context;

// Context utility
int argument_parse(int argc, char **argv, t_woody_context *context);
int initialize_struct(t_woody_context *context);

// File utility
int write_elf(t_woody_context *context);
int import_context_data(t_woody_context *context);

// Header validation
int validate_headers(t_woody_context *context);

// ELF Injection
int inject_elf(t_woody_context *context);
int find_code_cave(t_woody_context *context);
int insert_new_section(t_woody_context *context);

// ELF Utility
int find_elf_segment_index_by_section(t_woody_context *context, int section_index);
char *find_elf_section_name(t_woody_context *context, int index);
int find_elf_section_index(t_woody_context *context, char *name);
int find_text_section_index(t_woody_context *context);
void set_elf_segment_permission(t_woody_context *context, int index, int flags);
int find_last_segment_by_type(t_woody_context *context, unsigned int type);
int find_last_section_in_segment(t_woody_context *context, int segment_index);
Elf64_Shdr *initialized_section_header_64(void);
Elf32_Shdr *initialized_section_header_32(void);

// Payload
char *prepare_payload(t_woody_context *context);

// Error
void print_error(t_error_code code);
const char *get_error_message(t_error_code code);
t_error_code handle_error(t_woody_context *context, t_error_code err_code);

// Cleanup
void cleanup_context(t_woody_context *context);

// Debugging
void print_woody_context(t_woody_context *context);
void print_verbose(t_woody_context *context, const char *format, ...);

// Encryption
int encrypt_64(char *data, size_t data_size, uint64_t key);
int encrypt_32(char *data, size_t data_size, uint32_t key);
int encrypt_text_section(t_woody_context *context);

#endif // WOODY_H
