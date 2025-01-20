#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_object_file> <output_c_file> <payload_name>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
PAYLOAD_NAME="$3"

# Make sure the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file $INPUT_FILE does not exist"
    exit 1
fi

# Generate the C file
echo "#include \"payload.h\"" > "$OUTPUT_FILE"
echo -n "unsigned char $PAYLOAD_NAME[] = {" >> "$OUTPUT_FILE"
hexdump -v -e '",0x" 1/1 "%02x"' "$INPUT_FILE" | sed 's/^,//' >> "$OUTPUT_FILE"
echo "};" >> "$OUTPUT_FILE"
echo "const size_t ${PAYLOAD_NAME}_SIZE = sizeof($PAYLOAD_NAME);" >> "$OUTPUT_FILE"

echo "Generated $OUTPUT_FILE from $INPUT_FILE"
