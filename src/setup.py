# setup.py

from setuptools import setup, find_packages
from pathlib import Path

setup(
    name='scripts',
    version='0.1',
    packages=find_packages(),  # Automatically find and include all packages
    py_modules=[f.stem for f in Path('scripts').glob('*.py')],  # Include all Python files in scripts directory
)
