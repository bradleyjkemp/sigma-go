#!/bin/bash

ZIP_URL="https://github.com/SigmaHQ/sigma/releases/download/r2024-02-26/sigma_all_rules.zip"
TEMP_DIR=$(mktemp -d)

curl -L "$ZIP_URL" --output "$TEMP_DIR/sigma_all_rules.zip"

unzip "$TEMP_DIR/sigma_all_rules.zip" -d "$TEMP_DIR"

find "$TEMP_DIR" -type f -name "*.yml" | while read -r file; do
	condition=$(yq e '.detection.condition' "$file" | sed 's/"/\\"/g')
	if [ ! -z "$condition" ]; then
		condition_hash=$(echo -n "$condition" | sha256sum | cut -d' ' -f1)

		cp "$file" "./UniqueCondition_$condition_hash.yml"
		echo "Copied to './UniqueCondition_$condition_hash.rule..yml'"
	fi
done

echo "Processing complete."

rm -rf "$TEMP_DIR"
