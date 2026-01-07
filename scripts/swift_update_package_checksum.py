import argparse
import json
import os
import re
import sys


def run(new_checksum: str = None, new_tag: str = None):
    if new_checksum is None and new_tag is None:
        print("At least one of --checksum or --tag arguments must be provided.", file=sys.stderr)
        sys.exit(1)

    if new_checksum is not None:
        if not new_checksum.isalnum():
            print("Checksum must be alphanumeric.", file=sys.stderr)
            sys.exit(1)

        if not new_checksum.islower():
            print("Checksum must be lowercase.", file=sys.stderr)
            sys.exit(1)

        try:
            int(new_checksum, 16)
        except ValueError:
            print("Checksum must be hexadecimal.", file=sys.stderr)
            sys.exit(1)

    if new_tag is not None:
        if new_tag.strip() != new_tag:
            print("Tag must not contain any whitespace.", file=sys.stderr)
            sys.exit(1)

        tag_regex = re.compile(r"^v?\d+[.]\d+[.]\d+$")
        tag_match = tag_regex.match(new_tag)
        if tag_match is None:
            print("Tag must adhere to vX.Y.Z or X.Y.Z format.", file=sys.stderr)
            sys.exit(1)

    settings = [
        {"variable_name": "checksum", "value": new_checksum},
        {"variable_name": "tag", "value": new_tag},
    ]

    package_file_path = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "../Package.swift")
    )

    try:
        with open(package_file_path, "r") as package_file_handle:
            package_file = package_file_handle.read()
    except OSError:
        print("Failed to read Package.swift file.", file=sys.stderr)
        sys.exit(1)

    updated_package_file = package_file
    for current_setting in settings:
        current_variable_name = current_setting["variable_name"]
        new_value = current_setting["value"]
        if new_value is None:
            continue

        print(f"setting {current_variable_name} (JSON-serialization):")
        print(json.dumps(new_value))

        regex = re.compile(rf"(let\s+{current_variable_name}\s*=\s*)(.*)")
        match = regex.search(updated_package_file)
        if match is None:
            print(
                f"Failed to find {current_variable_name} in Package.swift.",
                file=sys.stderr,
            )
            sys.exit(1)

        previous_value = match.group(2)
        updated_package_file = updated_package_file.replace(previous_value, f'"{new_value}"')

    with open(package_file_path, "w") as package_file_handle:
        package_file_handle.write(updated_package_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Update Swift package checksum and tag."
    )
    parser.add_argument(
        "--checksum",
        type=str,
        help="new checksum of cktapFFI.xcframework.zip",
        required=False,
        default=None,
    )
    parser.add_argument(
        "--tag",
        type=str,
        help="new release tag (vX.Y.Z or X.Y.Z)",
        required=False,
        default=None,
    )
    args = parser.parse_args()
    run(new_checksum=args.checksum, new_tag=args.tag)
