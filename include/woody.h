#ifndef WOODY_H
#define WOODY_H

#include <stdint.h>  // uint8_t for byte manipulation
#include <stdio.h>   // FILE, fopen, fclose, fread, fwrite
#include <stdbool.h> // bool, true, false
#include <elf.h>     // ELF header structures

// Error codes
typedef enum e_error_code
{
    ERR_NONE = 0,
    ERR_INVALID_ARGS,
    ERR_FILE_OPEN,
    ERR_FILE_PARSE,
    ERR_KEY_GEN,
    ERR_ENCRYPTION,
    ERR_INJECTION,
    ERR_OUTPUT,
    ERR_OVERFLOW,
    ERR_INVALID_CONTEXT,
    ERR_INVALID_ELF,
    // ...
} t_error_code;

// Context structure
typedef struct s_woody_context
{
    // File handling
    const char *input_file_path;  // Path to the input ELF file
    const char *output_file_path; // Path to the output "woody" file
    int input_fd;                 // Input file descriptor
    int output_fd;                // Output file descriptor
    uint8_t *file_buffer;         // Buffer for the ELF file
    size_t file_size;             // Size of the input file

    // ELF-specific data
    Elf64_Ehdr *elf_header;      // Pointer to ELF header
    Elf64_Phdr *program_headers; // Pointer to program headers
    Elf64_Shdr *section_headers; // Pointer to section headers
    size_t text_section_offset;  // Offset for .text section (to be encrypted)
    size_t text_section_size;    // Size of .text section

    // Encryption
    uint8_t *encryption_key; // AES key
    size_t key_size;         // Size of the key (e.g., 128, 192, 256 bits)
    bool encryption_done;    // Flag to indicate encryption success

    // State and metadata
    t_error_code error_code; // Error code for context state
    bool initialized;        // Flag to indicate successful initialization

    // Cleanup pointers
    void *dynamic_allocations[10]; // Array to track dynamically allocated memory
    size_t allocation_count;       // Count of allocations for cleanup
} t_woody_context;

// Context utility function prototypes
bool init_woody_context(
    t_woody_context *context,
    const char *input_file,
    const char *output_file);
bool load_file_to_memory(t_woody_context *context);
void cleanup_context(t_woody_context *context);
int handle_error(t_woody_context *context, t_error_code error_code);
void print_woody_context(t_woody_context *context);

// ELF parsing function prototypes
bool parse_input_file(t_woody_context *context);
bool validate_elf_header(t_woody_context *context);

#endif // WOODY_H
