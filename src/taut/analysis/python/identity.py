"""Stable identity shared by Python analysis results and cache contracts."""

from taut.analysis.contracts import AdapterIdentity

PYTHON_AST_IDENTITY = AdapterIdentity(name="python-ast", version="9")
