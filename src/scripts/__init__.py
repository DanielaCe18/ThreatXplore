# scripts/__init__.py

from pathlib import Path
import importlib.util

# Get the path to the current directory
current_dir = Path(__file__).resolve().parent

# Iterate through all Python files in the directory
for path in current_dir.glob('*.py'):
    if path.stem != '__init__':
        module_name = path.stem
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Add the imported module to the current module's globals
        globals()[module_name] = module

# Optionally define __all__ to specify what gets imported with `from scripts import *`
__all__ = [module.stem for module in current_dir.glob('*.py') if module.stem != '__init__']
