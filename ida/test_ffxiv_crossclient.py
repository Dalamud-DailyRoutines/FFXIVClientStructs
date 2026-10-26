from __future__ import annotations

import copy
import hashlib
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import capstone

from ffxiv_crossclient import (
    Function,
    Mapping,
    describe_code,
    find_masked,
    recover_declared,
    relocate_data,
    resolve_symbols,
    validate_declared,
)
from ffxiv_crossclient_ida import (
    configure_native,
    import_expansion,
    load_script,
    rebase_data,
)
from ffxiv_crossclient_ida import run as import_generated


class MemoryImage:
    def __init__(self, code, base=0x140000000):
        self.base = base
        self.size = 0x2000
        self.sha256 = hashlib.sha256(code).hexdigest()
        self.sections = [
            SimpleNamespace(
                VirtualAddress=0x100,
                SizeOfRawData=len(code),
                Characteristics=0x20000000,
                Name=b".text",
            )
        ]
        self.contents = {0x100: code}
        self.functions = {}

    def read(self, rva, length):
        offset = rva - 0x100
        if offset < 0:
            return b""
        return self.contents[0x100][offset : offset + length]

    def section(self, rva):
        return next(
            (
                section
                for section in self.sections
                if section.VirtualAddress
                <= rva
                < section.VirtualAddress + section.SizeOfRawData
            ),
            None,
        )

    def executable(self, rva):
        return self.section(rva) is not None

    def function(self, rva):
        return next(
            (
                function
                for function in self.functions.values()
                if function.start <= rva < function.end
            ),
            None,
        )


class MatchingTests(unittest.TestCase):
    def test_masked_search_handles_regex_bytes_and_newline(self):
        image = MemoryImage(b"\x2e\x28\x5b\x0a\x29\xc3")
        self.assertEqual(
            find_masked(
                image, b"\x2e\x28\x5b\x00\x29\xc3", b"\xff\xff\xff\x00\xff\xff"
            ),
            [0x100],
        )

    def test_masked_search_rejects_ambiguity(self):
        image = MemoryImage(b"\x48\x8b\x05\x01\x02\x03\x04\xc3" * 2)
        matches = find_masked(
            image,
            b"\x48\x8b\x05\x00\x00\x00\x00\xc3",
            b"\xff\xff\xff\x00\x00\x00\x00\xff",
        )
        self.assertEqual(matches, [0x100, 0x108])

    def test_masked_search_rejects_section_boundary(self):
        image = MemoryImage(b"\x48\x8b\x05")
        self.assertEqual(
            find_masked(image, b"\x00\x48\x8b\x05", b"\x00\xff\xff\xff"), []
        )

    def test_normalization_preserves_constants(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        left = MemoryImage(b"\xb8\x01\x00\x00\x00\xc3")
        right = MemoryImage(b"\xb8\x02\x00\x00\x00\xc3")
        self.assertNotEqual(
            describe_code(left, decoder, 0x100, left.read(0x100, 6), 0x106)[0],
            describe_code(right, decoder, 0x100, right.read(0x100, 6), 0x106)[0],
        )

    def test_normalization_follows_signed_rip(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        image = MemoryImage(b"\x48\x8b\x05" + struct.pack("<i", -0x20) + b"\xc3")
        normalized, references, regions, consumed = describe_code(
            image, decoder, 0x100, image.read(0x100, 8), 0x108
        )
        self.assertEqual(normalized, b"\x48\x8b\x05\x00\x00\x00\x00\xc3")
        self.assertEqual(references, ((0, 0xE7),))
        self.assertEqual(regions, [(3, 4)])
        self.assertEqual(consumed, 8)

    def test_conflict_invalidates_interior_addresses(self):
        source = MemoryImage(bytes(64))
        target = MemoryImage(bytes(64))
        source.functions[0x100] = Function(0x100, 0x120)
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x100, "test")
        mapping.spans[0x100] = (0x100, 0x20)
        self.assertEqual(mapping.resolve(0x108), 0x108)
        mapping.add(0x100, 0x110, "conflict")
        self.assertIsNone(mapping.resolve(0x108))

    def test_cached_spans_preserve_interior_addresses(self):
        source = MemoryImage(bytes(64))
        target = MemoryImage(bytes(64))
        source.functions[0x100] = Function(0x100, 0x120)
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x108, "test")
        mapping.spans[0x100] = (0x108, 0x20)
        loaded = Mapping(source, target)
        loaded.load(mapping.payload())
        self.assertEqual(loaded.resolve(0x118), 0x120)
        invalid = mapping.payload()
        invalid["target_sha256"] = "invalid"
        with self.assertRaises(ValueError):
            loaded.load(invalid)

    def test_unresolved_addresses_never_survive_relocation(self):
        image = MemoryImage(bytes(64))
        mapping = Mapping(image, image)
        mapping.add(0x100, 0x110, "test")
        data = {
            "globals": {image.base + 0x100: "Known", image.base + 0x200: "Missing"},
            "classes": {
                "Example": {
                    "vtbls": [{"ea": 0, "base": "Parent"}],
                    "vfuncs": {3: "Update"},
                }
            },
        }
        original = copy.deepcopy(data)
        result, report = relocate_data(data, mapping)
        self.assertEqual(result["globals"], {image.base + 0x110: "Known"})
        self.assertEqual(result["classes"]["Example"]["vfuncs"], {3: "Update"})
        self.assertEqual(result["classes"]["Example"]["vtbls"][0]["ea"], 0)
        self.assertEqual(report["unresolved_count"], 1)
        self.assertEqual(data, original)

    def test_native_signatures_follow_calls(self):
        image = MemoryImage(b"\xe8\x03\x00\x00\x00\x90\x91\x92\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [
                    {"name": "Run", "signature": "E8 ?? ?? ?? ?? 90 91 92"}
                ],
            }
        ]
        result = resolve_symbols(structures, image)
        self.assertEqual(
            result["data"]["classes"]["Example"]["funcs"], {image.base + 0x108: "Run"}
        )
        self.assertEqual(result["unresolved"], [])

    def test_native_static_offsets_remain_signed(self):
        image = MemoryImage(
            b"\x90" * 16 + b"\x48\x8d\x05" + struct.pack("<i", -0x17) + b"\xc3"
        )
        structures = [
            {
                "type": "Example",
                "static_members": [
                    {
                        "name": "Instance",
                        "signature": "48 8D 05 ?? ?? ?? ?? C3",
                        "relative_follow_offsets": [3],
                        "is_pointer": False,
                    }
                ],
            }
        ]
        result = resolve_symbols(structures, image)
        self.assertEqual(
            result["data"]["classes"]["Example"]["instances"][0]["ea"],
            image.base + 0x100,
        )

    def test_native_function_rejects_interior_signature(self):
        image = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3")
        image.functions[0x100] = Function(0x100, 0x107)
        result = resolve_symbols(
            [
                {
                    "type": "Example",
                    "member_functions": [
                        {"name": "Run", "signature": "B8 01 02 03 04 C3"}
                    ],
                }
            ],
            image,
        )
        self.assertFalse(next(iter(result["resolved_signatures"].values()))["function"])
        self.assertNotIn("Example", result["data"]["classes"])
        self.assertEqual(len(result["unresolved"]), 1)

    def test_declared_recovery_requires_reference_address(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        data = {"classes": {"Example": {"funcs": {source.base + 0x107: "Run"}}}}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.addresses, {})
        data["classes"]["Example"]["funcs"] = {source.base + 0x100: "Run"}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.resolve(0x100), 0x101)

    def test_declared_recovery_preserves_confirmed_mapping(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x107, "confirmed")
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        data = {"classes": {"Example": {"funcs": {source.base + 0x100: "Run"}}}}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.resolve(0x100), 0x107)
        self.assertEqual(mapping.conflicts, set())

    def test_independent_signature_disagreement_is_quarantined(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x107, "confirmed")
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        validate_declared(mapping, structures)
        self.assertIsNone(mapping.resolve(0x100))
        self.assertEqual(mapping.conflicts, {0x100})
        self.assertEqual(mapping.symbols["data"]["classes"]["Example"]["funcs"], {})
        self.assertFalse(
            next(iter(mapping.symbols["resolved_signatures"].values()))["function"]
        )
        self.assertEqual(len(mapping.symbols["mapping_disagreements"]), 1)
        before = copy.deepcopy(mapping.payload())
        validate_declared(mapping, structures)
        self.assertEqual(mapping.payload(), before)


class ImportTests(unittest.TestCase):
    def test_expansion_preserves_dependency_graph_and_existing_layout(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                calls = []
                directory = Path(__file__).resolve().parent
                payload = {
                    "expansion_types": ["Child"],
                    "generated_types": [],
                    "expansion_enums": [],
                    "structs": [
                        {"type": name, "fields": []} for name in ("Parent", "Child")
                    ],
                    "enums": [],
                }
                api = SimpleNamespace(
                    srclang_importer=True, clean_struct_name=lambda name: name
                )
                methods = (
                    "delete_struct",
                    "create_struct",
                    "create_struct_members",
                    "finalise_struct",
                    "create_vtable",
                    "create_union",
                    "update_member_func",
                    "update_static_member",
                    "update_virt_func",
                    "delete_enum",
                    "create_enum_struct",
                )
                for name in methods:
                    setattr(
                        api,
                        name,
                        lambda *arguments, name=name, calls=calls: calls.append(
                            (name, arguments[-1].type)
                        ),
                    )

                def load(path, documents, directory=directory, fail=fail, api=api):
                    definitions = documents[directory / "ffxiv_structs.yml"]["structs"]

                    def run():
                        self.assertEqual(
                            [item["type"] for item in definitions], ["Parent", "Child"]
                        )
                        for name in (
                            "delete_struct",
                            "create_struct",
                            "create_struct_members",
                            "finalise_struct",
                        ):
                            for item in definitions:
                                if fail and name == "create_struct_members":
                                    raise RuntimeError("中止导入")
                                getattr(api, name)(SimpleNamespace(type=item["type"]))

                    return {"api": api, "run": run}

                type_api = SimpleNamespace(
                    tinfo_t=lambda: SimpleNamespace(
                        get_named_type=lambda library, name: True,
                        get_udt_details=lambda members: False,
                    ),
                    udt_type_data_t=list,
                )
                with (
                    patch.dict("sys.modules", {"ida_typeinf": type_api}),
                    patch("ffxiv_crossclient_ida.load_script", side_effect=load),
                    patch("ffxiv_crossclient_ida.configure_native"),
                ):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "中止导入"):
                            import_expansion(payload, {}, directory, 0x140000000)
                    else:
                        import_expansion(payload, {}, directory, 0x140000000)
                self.assertNotIn(("delete_struct", "Parent"), calls)
                self.assertNotIn(("create_struct_members", "Parent"), calls)
                self.assertIn(("create_struct", "Parent"), calls)
                self.assertEqual(calls.count(("finalise_struct", "Parent")), 1)

    def test_entry_applies_database_base_only_once(self):
        data = {
            "_crossclient": {"image_base": 0x1000, "target_sha256": "test"},
            "classes": {"Example": {"funcs": {0x1100: "Run"}}},
        }
        imported = []
        class_type = SimpleNamespace(STANDARD_IMAGE_BASE=0x140000000)
        rename = {"FfxivClass": class_type, "load_data": lambda: None}
        importer = {"api": SimpleNamespace(can_run=lambda: True), "run": lambda: None}

        def load(path, documents):
            imported.append(next(iter(documents.values())))
            return rename if path.name == "ffxiv_idarename.py" else importer

        with (
            patch.dict(
                "sys.modules",
                {
                    "ida_auto": SimpleNamespace(auto_wait=lambda: None),
                    "ida_idaapi": SimpleNamespace(BADADDR=-1),
                    "ida_kernwin": SimpleNamespace(),
                    "ida_nalt": SimpleNamespace(get_imagebase=lambda: 0x2000),
                    "ida_name": SimpleNamespace(),
                },
            ),
            patch.object(Path, "read_text", return_value=json.dumps(data)),
            patch("ffxiv_crossclient_ida.verify_target"),
            patch("ffxiv_crossclient_ida.configure_native"),
            patch("ffxiv_crossclient_ida.load_script", side_effect=load),
            patch("builtins.print"),
        ):
            import_generated(data_path="generated.yml")
        self.assertEqual(class_type.STANDARD_IMAGE_BASE, 0x2000)
        self.assertEqual(len(imported), 2)
        for document in imported:
            self.assertEqual(document["classes"]["Example"]["funcs"], {0x2100: "Run"})

    def test_native_types_use_validated_address(self):
        class FunctionData(list):
            push_back = list.append

        applied = []
        type_api = SimpleNamespace(
            func_type_data_t=FunctionData,
            funcarg_t=SimpleNamespace,
            tinfo_t=lambda: SimpleNamespace(create_func=lambda function: True),
            CM_CC_FASTCALL=1,
            TINFO_DEFINITE=1,
            apply_tinfo=lambda address, info, flags: applied.append(address) is None,
        )
        field = SimpleNamespace(type="__int64", return_type="void", parameters=[])
        api = SimpleNamespace(
            get_tinfo_from_type=lambda value: value,
            get_vft_from_data=lambda name: {"ea": 0x2300},
            get_yaml=lambda: SimpleNamespace(structs=[SimpleNamespace(fields=[field])]),
        )
        manifest = {
            "image_base": 0x1000,
            "resolved_signatures": {
                "valid": {"address": 0x1100, "function": True},
                "interior": {"address": 0x1200, "function": False},
            },
            "resolved_statics": {},
        }
        with patch.dict(
            "sys.modules",
            {
                "ida_idaapi": SimpleNamespace(BADADDR=-1),
                "ida_typeinf": type_api,
                "ida_funcs": SimpleNamespace(get_func_name=lambda address: "Run"),
                "ida_bytes": SimpleNamespace(get_qword=lambda address: address + 0x100),
            },
        ):
            configure_native(api, manifest, 0x2000)
            self.assertEqual(api.get_yaml().structs[0].fields[0].type, "__fastcall")
            for signature in ("valid", "interior", "missing"):
                api.update_member_func(
                    SimpleNamespace(
                        signature=signature,
                        name="Run",
                        return_type="void",
                        parameters=[],
                    ),
                    SimpleNamespace(type="Example"),
                )
            api.update_virt_func(
                SimpleNamespace(
                    name="Run", offset=16, return_type="void", parameters=[]
                ),
                SimpleNamespace(type="Example"),
            )
        self.assertEqual(applied, [0x2100, 0x2410])

    def test_rebase_accepts_json_keys_and_preserves_zero(self):
        data = {
            "_crossclient": {
                "image_base": 0x1000,
                "resolved_signatures": {"test": {"match": 0x1010, "address": 0x1020}},
                "resolved_statics": {"test": 0x1030},
            },
            "globals": {"4112": "Global"},
            "functions": {},
            "classes": {
                "Example": {
                    "funcs": {"4128": "Run"},
                    "vtbls": [{"ea": 0}, {"ea": 0x1040}],
                }
            },
        }
        original = copy.deepcopy(data)
        result = rebase_data(data, 0x2000)
        self.assertEqual(result["globals"], {0x2010: "Global"})
        self.assertEqual(result["classes"]["Example"]["funcs"], {0x2020: "Run"})
        self.assertEqual(
            result["classes"]["Example"]["vtbls"], [{"ea": 0}, {"ea": 0x2040}]
        )
        self.assertEqual(
            result["_crossclient"]["resolved_signatures"]["test"]["address"], 0x2020
        )
        self.assertEqual(result["_crossclient"]["resolved_statics"]["test"], 0x2030)
        self.assertEqual(data, original)

    def test_existing_script_receives_generated_data_without_file_edits(self):
        path = Path(__file__).with_name("ffxiv_idarename.py").resolve()
        data = path.with_name("data.yml")
        source = "calls = []\ndef load_data():\n    calls.append(open(__file__.replace('ffxiv_idarename.py', 'data.yml')).read())\nload_data()\n"
        with patch.object(Path, "read_text", return_value=source):
            module = load_script(path, {data: {"generated": True}})
        self.assertEqual(module["calls"], [])
        module["load_data"]()
        self.assertIn("generated: true", module["calls"][0])
        self.assertEqual(len(module["calls"]), 1)

    def test_function_pointer_declaration_preserves_spacing_and_names(self):
        path = Path(__file__).with_name("ffxiv_structimporter.py").resolve()
        source = "class Api:\n    def get_srclang_type_name(self, value):\n        return value\n    def create_srclang_decl(self):\n        field_decl = 'void (*Callback)('\n        for name in ['first', 'second']:\n            field_decl = field_decl + self.get_srclang_type_name('int') + ''\n            field_decl = field_decl + name + ','\n        return field_decl[:-2] + ')'\n"
        with patch.object(Path, "read_text", return_value=source):
            module = load_script(path, {})
        self.assertEqual(
            module["Api"]().create_srclang_decl(),
            "void (*Callback)(int first,int second);",
        )


if __name__ == "__main__":
    unittest.main()
