from pathlib import Path
from ghidra_retypd_provider.type_inference import infer_types, serialize_types
from loguru import logger
import argparse
import sys


def main():
    logger.enable("ghidra_retypd_provider")
    logger.add(
        sys.stdout,
        format="{time} {level} {message}",
        filter="ghidra_retypd_provider",
        level="INFO",
    )

    parser = argparse.ArgumentParser(
        description="Infer types from p-code file using Retypd",
    )

    parser.add_argument(
        "--json-in", type=Path, help="The json file to analyze"
    )
    parser.add_argument(
        "--function",
        type=str,
        help="The function to analyze, "
        "if not specified the whole program is analyzed",
    )
    args = parser.parse_args()
    types = infer_types(args.json_in, args.function)
    output_path = args.json_in.with_name(args.json_in.name + ".types.json")
    serialize_types(types, output_path)


if __name__ == "__main__":
    main()
