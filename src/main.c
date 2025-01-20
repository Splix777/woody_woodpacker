#include "woody.h"

int main(int argc, char **argv)
{
    t_error_code ret;
    t_woody_context context;
    memset(&context, 0, sizeof(t_woody_context));

    if ((ret = argument_parse(argc, argv, &context) != SUCCESS))
        return handle_error(&context, ret);

    if ((ret = import_context_data(&context)) != SUCCESS)
        return handle_error(&context, ret);

    if ((ret = validate_headers(&context)) != SUCCESS)
        return handle_error(&context, ret);

    if ((ret = inject_elf(&context)) != SUCCESS)
        return handle_error(&context, ret);

    // print_woody_context(&context);
    cleanup_context(&context);
    return ret;
}
