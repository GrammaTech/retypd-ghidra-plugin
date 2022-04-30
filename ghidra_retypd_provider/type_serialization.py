from json import JSONEncoder

from retypd.c_types import PointerType, CType, FunctionType, CompoundType
from typing import Iterable, Set, List


def is_non_primitive(ctype: CType) -> bool:
    return isinstance(ctype, (FunctionType, CompoundType, PointerType))


def collect_all_non_primitive_types(
    function_types: Iterable[CType],
) -> Set[CType]:
    def get_subtypes(ctype: CType) -> List[CType]:
        if isinstance(ctype, FunctionType):
            return [ctype.return_type] + list(ctype.params)
        elif isinstance(ctype, PointerType):
            return [ctype.target_type]
        elif isinstance(ctype, CompoundType):
            return [field.ctype for field in ctype.fields]
        else:
            raise Exception(f"Cannot get subtypes of {type(ctype)}")

    worklist = list(function_types)
    collected_types = set()
    while len(worklist) > 0:
        ctype = worklist.pop()
        if ctype not in collected_types and is_non_primitive(ctype):
            if not isinstance(ctype, PointerType):
                collected_types.add(ctype)
            worklist.extend(get_subtypes(ctype))
    return collected_types


class CTypeJsonEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, CompoundType):
            fields = []
            for index, field in enumerate(obj.fields):
                fields.append(
                    {
                        "name": field.name
                        if field.name != ""
                        else f"field_{index}",
                        "type": str(field.ctype),
                        "offset": field.offset,
                    }
                )
            return {
                "type": obj.compound_type,
                "name": obj.name,
                "fields": fields,
            }
        elif isinstance(obj, FunctionType):
            params = []
            for i, param in enumerate(obj.params):
                if param is not None:
                    params.append({"index": i, "type": str(param)})
            return {
                "type": "function",
                "name": obj.name,
                "params": params,
                "ret": str(obj.return_type)
                if obj.return_type is not None
                else "None",
            }
        else:
            return super().default(obj)
