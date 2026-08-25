"""Make project root importable for tests."""
import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# LLM_MODEL has no built-in default (digest._check_env enforces it at run
# start), so the suite supplies its own. setdefault, not a bare assignment, so
# running against a real model id from the environment still works.
os.environ.setdefault("LLM_MODEL", "test-model")
