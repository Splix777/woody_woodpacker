#include "elf_parser.h"
#include "elf_validator.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>

// Open ELF file, parse headers, and store data in context
bool parse_input_file(t_woody_context *context)
{
    if (!context)
        return false;

    if (!validate_elf_header(context))
        return false;
    print_woody_context(context);

    // // Read the ELF header
    // Elf64_Ehdr elf_header;
    // if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, file) != 1)
    // {
    //     perror("Failed to read ELF header");
    //     context->error_code = ERR_FILE_PARSE;
    //     fclose(file);
    //     return false;
    // }

    // // Validate the magic number using the new function
    // int magic_result = validate_magic_number(context, &elf_header);
    // if (magic_result != 0)
    // {
    //     context->error_code = ERR_FILE_PARSE;
    //     fclose(file);
    //     return false;
    // }

    // // Allocate memory for the ELF header in context and copy the data
    // context->elf_header = malloc(sizeof(Elf64_Ehdr));
    // if (context->elf_header == NULL)
    // {
    //     perror("Memory allocation failed for ELF header");
    //     context->error_code = ERR_FILE_PARSE;
    //     fclose(file);
    //     return false;
    // }
    // memcpy(context->elf_header, &elf_header, sizeof(Elf64_Ehdr));

    // // Continue parsing other headers (program headers, section headers, etc.)
    // if (!parse_section_headers(file, context))
    // {
    //     context->error_code = ERR_FILE_PARSE;
    //     fclose(file);
    //     return false;
    // }

    // // Close the file after parsing
    // fclose(file);

    return true;
}
