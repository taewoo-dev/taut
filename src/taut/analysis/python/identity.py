"""Stable identity shared by Python analysis results and cache contracts."""

from taut.analysis.contracts import AdapterIdentity

# Version 12 invalidates cached analysis reasons from before English diagnostics.
PYTHON_AST_IDENTITY = AdapterIdentity(name="python-ast", version="12")
