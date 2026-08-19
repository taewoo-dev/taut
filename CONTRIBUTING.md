# Contributing to taut

Bug reports and rule proposals are welcome through GitHub Issues. A rule must describe a condition
that can be determined reliably from code, rather than a subjective preference.

Run the full verification suite before submitting a change:

```bash
bash scripts/test.sh
```

A new rule needs tests that demonstrate:

- a violation is detected;
- compliant code passes;
- unrelated code zones remain unaffected; and
- invalid configuration fails with a clear error.
