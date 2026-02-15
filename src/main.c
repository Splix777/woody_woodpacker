#include "woody.h"

/*
 * Entry point.
 *
 * Keep this file simple: main() wires the stages together and all real work
 * lives in the dedicated modules (parser/, encryption/, injector/, utils/).
 *
 * Quick test (inside Docker):
 *   docker compose exec -T woody_woodpacker bash -lc 'make clean && make && ./woody_woodpacker -f resources/sample && ./woody'
 */
int main(int argc, char** argv) {
    t_error_code    ret;
    t_woody_context context;
    memset(&context, 0, sizeof(t_woody_context));
    context.file.input_fd  = -1;
    context.file.output_fd = -1;

    if ((ret = argument_parse(argc, argv, &context)) != SUCCESS)
        return handle_error(&context, ret);

    if ((ret = import_context_data(&context)) != SUCCESS)
        return handle_error(&context, ret);

    if ((ret = validate_headers(&context)) != SUCCESS)
        return handle_error(&context, ret);

    /*
     * Analysis-only mode: scan for "code caves" (padding gaps) and exit.
     * This does not modify files or perform injection.
     */
    if (context.scan_caves) {
        if ((ret = initialize_struct(&context)) != SUCCESS)
            return handle_error(&context, ret);
        scan_code_caves(&context);
        cleanup_context(&context);
        return SUCCESS;
    }

    if ((ret = inject_elf(&context)) != SUCCESS)
        return handle_error(&context, ret);

    // print_woody_context(&context);
    cleanup_context(&context);
    return ret;
}
