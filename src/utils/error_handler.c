// src/utils/error_handler.c

#include "woody.h"  // t_woody_context, t_error_code
#include <stdio.h>  // fprintf
#include <stdlib.h> // exit

// Error messages corresponding to error codes
static const char *error_messages[] = {
    "No error",
    "Invalid arguments",
    "File open error",
    "File parse error",
    "Key generation error",
    "Encryption error",
    "Code injection error",
    "Output creation error",
    "Overflow error",
    "Invalid context error",
    "Invalid ELF error",
    // ...
};

// Handle error: Cleanup and exit with appropriate code
int handle_error(t_woody_context *context, t_error_code error_code)
{
    // Log error message
    if (error_code >= 0 && error_code < (sizeof(error_messages) / sizeof(error_messages[0])))
        fprintf(stderr, "Error: %s\n", error_messages[error_code]);
    else
        fprintf(stderr, "Error: Unknown error code %d\n", error_code);

    // Set the error code in the context for tracking
    if (context)
    {
        context->error_code = error_code;
        cleanup_context(context);
    }

    // Exit with error code
    exit(error_code);
}
