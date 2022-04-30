from dataclasses import dataclass
import json
from ghidra_retypd_provider.type_serialization import (
    CTypeJsonEncoder,
    collect_all_non_primitive_types,
)
from loguru import logger

from typing import Optional, Tuple, Dict, List, Iterable
from retypd import ConstraintSet, Program, Solver
from retypd.clattice import CLattice, CLatticeCTypes

from retypd.c_type_generator import CTypeGenerator
from retypd.c_types import CType, FunctionType
from retypd.parser import SchemaParser
from pathlib import Path
from retypd.loggable import LogLevel


class RetypdGhidraError(Exception):
    pass


@dataclass
class FunctionPrototype:
    """
    A class to represent simple function prototypes.
    The types of the return variable and the arguments
    are strings or None.
    """

    ret: Optional[str]
    params: List[Optional[str]]


def recover_original_names(
    types: Iterable[CType], modified_names: Dict[str, str]
) -> List[CType]:
    """
    Rename the function types based in the dictionary that maps
    the modified procedure names to the original procedure names.
    """
    final_types = []
    for ctype in types:
        assert isinstance(ctype, FunctionType)
        if ctype.name in modified_names:
            ctype.name = modified_names[ctype.name]
        final_types.append(ctype)
    return final_types


def get_int_and_pointer_size(language: str):
    """
    Get the size of integers and pointer for each
    Ghidra language.
    """
    if language.startswith("ARM") and "32" in language:
        return 4, 4
    if language.startswith("x86"):
        if "64" in language:
            return (4, 8)
        else:
            return (4, 4)

    raise RetypdGhidraError(f"Unknown ISA {language}")


def constraints_from_json(path: Path) -> Tuple[str, Program, Dict[str, str]]:
    """
    Load constraints from a JSON encoded file
    :returns: Language of original assembly, loaded type Program, and name map
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    language: str = data["language"]
    constraints: Dict[str, List[str]] = data["constraints"]
    callgraph: Dict[str, List[str]] = data["callgraph"]
    nameMap: Dict[str, str] = data["nameMap"]

    parsed_constraints = {}

    for (func, constrs) in constraints.items():
        parsed = set()

        for constr in constrs:
            try:
                parsed.add(SchemaParser.parse_constraint(constr))
            except ValueError as e:
                logger.error(f"Failed to parse constraint {constr}")
                raise e

        parsed_constraints[func] = ConstraintSet(parsed)

    program = Program(
        CLattice(),
        {},
        parsed_constraints,
        callgraph,
    )

    return language, program, nameMap


def infer_types(json_in: Path, function: Optional[str] = None) -> List[CType]:
    """
    Infer C types for the P-code functions in the `json_in` json file.
    :param json_in: Path to the JSON-encoded constraints
    :param function: If function is specified,
    the type inference only considers the given function.

    """
    language, program, modified_names = constraints_from_json(json_in)
    solver = Solver(program, verbose=LogLevel.DEBUG)
    _, sketches = solver()
    for f, sk in sketches.items():
        logger.debug("Sketches: ", f, sk)

    int_size, pointer_size = get_int_and_pointer_size(language)
    gen = CTypeGenerator(
        sketches,
        CLattice(),
        CLatticeCTypes(),
        int_size,
        pointer_size,
    )
    return recover_original_names(gen().values(), modified_names)


def serialize_types(types: List[CType], dest: Path) -> None:
    all_types = list(collect_all_non_primitive_types(types))
    logger.debug(f"all types {all_types}")
    with open(dest, "w") as f:
        json.dump(all_types, f, cls=CTypeJsonEncoder, indent=2)
