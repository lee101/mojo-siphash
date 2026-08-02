import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR = os.path.join(ROOT, "python")

saved_path = sys.path[:]
sys.path = [
    path
    for path in sys.path
    if os.path.realpath(path or os.getcwd()) != os.path.realpath(PYTHON_DIR)
]
import siphash as upstream_siphash

del sys.modules["siphash"]
sys.path = saved_path
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
