# Publishing to PyPI

This guide explains how to build and publish AFL Overseer to PyPI.

## Prerequisites

1. Install build tools:
```bash
pip install --upgrade build twine
```

2. Set up PyPI credentials:
   - Create an account at https://pypi.org/
   - Generate an API token at https://pypi.org/manage/account/token/
   - Create `~/.pypirc`:
```ini
[pypi]
username = __token__
password = pypi-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Building the Package

1. Clean previous builds:
```bash
rm -rf dist/ build/ *.egg-info src/*.egg-info
```

2. Build the package:
```bash
python -m build
```

This creates:
- `dist/afl-overseer-X.Y.Z.tar.gz` (source distribution)
- `dist/afl_overseer-X.Y.Z-py3-none-any.whl` (wheel)

## Testing the Build

1. Test installation in a virtual environment:
```bash
python3 -m venv test_env
source test_env/bin/activate
pip install dist/afl_overseer-*.whl
afl-overseer --version
deactivate
rm -rf test_env
```

2. Upload to TestPyPI first:
```bash
python -m twine upload --repository testpypi dist/*
```

3. Test installation from TestPyPI:
```bash
python3 -m venv test_env
source test_env/bin/activate
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ afl-overseer
afl-overseer --version
deactivate
rm -rf test_env
```

## Publishing to PyPI

1. Upload to PyPI:
```bash
python -m twine upload dist/*
```

2. Verify the upload:
   - Visit https://pypi.org/project/afl-overseer/
   - Check the package page displays correctly

3. Test installation:
```bash
pip install afl-overseer
```

## Version Management

Before each release:

1. Update version in `src/__init__.py`:
```python
__version__ = "X.Y.Z"
```

2. Update version in `pyproject.toml`:
```toml
version = "X.Y.Z"
```

3. Create a git tag:
```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

## Versioning Scheme

Follow Semantic Versioning (https://semver.org/):
- `MAJOR.MINOR.PATCH`
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

## Checklist

Before publishing:
- [ ] Update version in `src/__init__.py`
- [ ] Update version in `pyproject.toml`
- [ ] Update CHANGELOG.md (if exists)
- [ ] Run tests: `pytest` (if tests exist)
- [ ] Clean build: `rm -rf dist/ build/ *.egg-info`
- [ ] Build package: `python -m build`
- [ ] Test locally: Install from wheel and verify
- [ ] Upload to TestPyPI and verify
- [ ] Create git tag
- [ ] Upload to PyPI
- [ ] Verify on PyPI website
- [ ] Test installation: `pip install afl-overseer`

## Troubleshooting

### Build Errors
- Ensure `setuptools` and `wheel` are up to date: `pip install --upgrade setuptools wheel`
- Check `pyproject.toml` for syntax errors

### Upload Errors
- Verify PyPI credentials in `~/.pypirc`
- Check if version already exists (you cannot re-upload the same version)
- Ensure package name is available (not taken by another project)

### Import Errors After Installation
- Check package structure in built wheel: `unzip -l dist/*.whl`
- Verify entry points in `pyproject.toml`
- Test in a clean virtual environment

## Resources

- PyPI Help: https://pypi.org/help/
- Python Packaging Guide: https://packaging.python.org/
- Setuptools Documentation: https://setuptools.pypa.io/
- Build Documentation: https://pypa-build.readthedocs.io/
- Twine Documentation: https://twine.readthedocs.io/
