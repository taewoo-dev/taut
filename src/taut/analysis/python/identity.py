"""Stable identity shared by Python analysis results and cache contracts."""

from taut.analysis.contracts import AdapterIdentity

# Version 13 separates returned values from callees and joins inferred types by flow.
PYTHON_AST_IDENTITY = AdapterIdentity(name="python-ast", version="13")
