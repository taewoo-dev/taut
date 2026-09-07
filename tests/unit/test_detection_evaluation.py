from __future__ import annotations

import pytest
from scripts.evaluate_detection import Case, Corpus, evaluate


def test_quality_metrics_do_not_count_uncertainty_as_detection() -> None:
    corpus = Corpus(
        1,
        "synthetic",
        "repository regression review",
        (
            Case(
                "direct",
                "ASYNC001",
                "import time\nasync def f():\n    time.sleep(1)",
                True,
                "synchronous sleep blocks the event loop",
            ),
            Case(
                "callback",
                "ASYNC001",
                "import time\ndef run(fn, enabled):\n    if enabled:\n        fn(1)\n"
                "async def f():\n    run(time.sleep, True)",
                True,
                "callback executes sleep synchronously",
            ),
            Case(
                "safe", "ASYNC001", "async def f():\n    return 1", False, "no blocking operation"
            ),
        ),
    )
    result = evaluate(corpus)
    assert result["metrics"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 1,
        "true_negative": 1,
        "indeterminate_positive": 1,
        "indeterminate_negative": 0,
        "precision": 1.0,
        "recall": 0.5,
        "positive_flag_rate": 1.0,
    }


@pytest.mark.parametrize(
    "corpus",
    [
        Corpus(2, "synthetic", "reviewer", ()),
        Corpus(1, "synthetic", "", ()),
        Corpus(
            1,
            "synthetic",
            "reviewer",
            (Case("unknown", "UNKNOWN001", "value = 1", False, "unknown rule"),),
        ),
        Corpus(
            1,
            "synthetic",
            "reviewer",
            (Case("broken", "ASYNC001", "def broken(:", False, "invalid source"),),
        ),
    ],
)
def test_invalid_corpus_cannot_produce_a_quality_score(corpus: Corpus) -> None:
    with pytest.raises(ValueError):
        evaluate(corpus)
