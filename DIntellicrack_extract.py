import json

with open("audit/_workplan.json") as f:
    wp = json.load(f)
fbf = wp.get("findingsByFile", {})
files = [
    "test_x64dbg_events.py",
    "test_lexer.py",
    "test_realcov_11_model_loader.py",
    "test_app_integration.py",
    "test_realcov_14b_script_manager.py",
]
for k in fbf:
    nk = k.replace(chr(92), "/")
    for f in files:
        if nk.endswith(f):
            print("=== KEY:", k)
            print(json.dumps(fbf[k], indent=2))
            print()
