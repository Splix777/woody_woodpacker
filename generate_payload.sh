#!/bin/bash

# generate_payload.sh
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input_object_file> <output_c_file>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

# Make sure the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file $INPUT_FILE does not exist"
    exit 1
fi

# Generate the C file
echo "#include \"payload.h\"" > "$OUTPUT_FILE"
echo -n "unsigned char INJECTION_PAYLOAD[] = {" >> "$OUTPUT_FILE"
hexdump -v -e '",0x" 1/1 "%02x"' "$INPUT_FILE" | sed 's/^,//' >> "$OUTPUT_FILE"
echo "};" >> "$OUTPUT_FILE"
echo "const size_t INJECTION_PAYLOAD_SIZE = sizeof(INJECTION_PAYLOAD);" >> "$OUTPUT_FILE"

echo "Generated payload.c from $INPUT_FILE"