"""Static regression checks for the 17-module Android tool menu/bridge contract."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MENUS = ROOT / "app/src/main/java/com/alvsia/pro/tool/SubMenus.kt"
BRIDGE = ROOT / "app/src/main/python/alvsia_bridge.py"
BRIDGE_IMPL = ROOT / "app/src/main/python/alvsia_bridge_impl.py"
CATALOG = ROOT / "app/src/main/java/com/alvsia/pro/tool/ToolCatalog.kt"
ENGINE = ROOT / "app/src/main/java/com/alvsia/pro/tool/ToolEngine.kt"


def test_menu_ids_are_unique_and_reachable():
    menus = MENUS.read_text(encoding="utf-8")
    bridge = BRIDGE.read_text(encoding="utf-8") + "\n" + BRIDGE_IMPL.read_text(encoding="utf-8")
    ids = re.findall(r'SubTool\(\s*"([a-zA-Z0-9_]+)"', menus)
    assert ids, "No SubTool IDs found; menu parsing may have drifted"
    duplicates = sorted({sid for sid in ids if ids.count(sid) > 1})
    assert not duplicates, f"Duplicate sub-tool IDs: {duplicates}"

    generic = {
        "pak_delete_entry": '"delete" in sid',
        "pak_inject": 'sid in ("pak_repack_full","pak_inject","pak_encrypt","pak_decrypt_restore")',
        "pak_full_unpack": 'sid.startswith("pak_full")',
        "lua_patch_byte": 'mid == 16 or sid.startswith("lua_patch_")',
        "lua_mod_repack": 'sid.startswith("lua_patch_") or sid in ("lua_inject_hook","lua_mod_repack")',
    }
    direct_engine_routes = {"android_permission_dump": 'subId == "android_permission_dump"'}
    engine = ENGINE.read_text(encoding="utf-8")
    missing = []
    for sid in ids:
        if sid in direct_engine_routes and direct_engine_routes[sid] in engine:
            continue
        if f'"{sid}"' in bridge:
            continue
        route = generic.get(sid)
        if not route or route not in bridge:
            missing.append(sid)
    assert not missing, f"Menu IDs without bridge routes: {missing}"


def test_catalog_contains_all_seventeen_modules():
    catalog = CATALOG.read_text(encoding="utf-8")
    ids = [int(x) for x in re.findall(r'ToolItem\((\d+),', catalog)]
    assert ids == list(range(1, 18)), f"Expected module IDs 1..17 in order, got {ids}"


def test_engine_surfaces_bridge_failures():
    engine = ENGINE.read_text(encoding="utf-8")
    bridge = BRIDGE.read_text(encoding="utf-8") + "\n" + BRIDGE_IMPL.read_text(encoding="utf-8")
    assert "X OUT -> operation failed" in engine
    assert "'ok': False" in engine
    assert 'startsWith("X ")' in engine
    assert "target filename(s) are not present in this PAK index" in bridge
    assert "Lua filenames sample ->" in bridge


if __name__ == "__main__":
    tests = (
        test_menu_ids_are_unique_and_reachable,
        test_catalog_contains_all_seventeen_modules,
        test_engine_surfaces_bridge_failures,
    )
    for test in tests:
        test()
        print("PASS", test.__name__)
    print("TOOL DISPATCH TEST: PASS (3/3)")
