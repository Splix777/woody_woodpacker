#include "woody.h"

// Main function for Woody Woodpacker
int main(int argc, char **argv)
{
    // Master context to shuttle data across all steps
    t_woody_context context;

    // Step 1: Validate command-line arguments
    // Check if the required number of arguments is provided
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return handle_error(NULL, ERR_INVALID_ARGS);
    }

    // Step 2: Initialize context
    // Setup the master context with input and output file paths
    if (!init_woody_context(&context, argv[1], "woody"))
    {
        return handle_error(&context, ERR_FILE_OPEN);
    }

    // --- Roadmap Steps ---
    // Step 3: Parse and validate input file
    if (!parse_input_file(&context))
        return handle_error(&context, ERR_FILE_PARSE);

    // Step 4: Generate encryption key
    // if (!generate_key(&context))
    //     return handle_error(&context, ERR_KEY_GEN);

    // Step 5: Prepare code injection
    // if (!prepare_code_injection(&context))
    //     return handle_error(&context, ERR_INJECTION);

    // Step 6: Encrypt necessary sections
    // if (!encrypt_sections(&context))
    //     return handle_error(&context, ERR_ENCRYPTION);

    // Step 7: Create woody output
    // if (!create_woody_output(&context))
    //     return handle_error(&context, ERR_OUTPUT);

    // Cleanup resources and exit successfully
    cleanup_context(&context);
    return ERR_NONE;
}
