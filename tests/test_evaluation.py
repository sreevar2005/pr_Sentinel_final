from pathlib import Path

import pytest

from prscreen.cli import main
from prscreen.diff import parse_diff
from prscreen.evaluation import (
    PLACEHOLDERS,
    CorpusError,
    Expectation,
    build_diff,
    evaluate,
    evaluate_case,
    load_case,
)

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "corpus"


@pytest.fixture(scope="module")
def report():
    return evaluate(CORPUS)


def test_corpus_behaves_as_labeled(report):
    failing = [c.case_id for c in report.cases if not c.gate_ok]
    assert failing == [], "a case no longer behaves as labeled; run: prscreen eval"


def test_corpus_has_both_kinds_and_real_prs(report):
    kinds = {c.kind for c in report.cases}
    assert kinds == {"risky", "benign"}
    assert len(report.cases) >= 50
    assert len(report.real) >= 50


def test_docs_evaluation_md_is_up_to_date(capsys):
    assert main(["eval", "--corpus", str(CORPUS), "--format", "markdown"]) == 0
    expected = capsys.readouterr().out
    docs = (ROOT / "docs" / "evaluation.md").read_text(encoding="utf-8")
    assert docs == expected, "regenerate: prscreen eval --format markdown > docs/evaluation.md"


def test_corpus_files_contain_no_raw_secrets_or_invisible_characters():
    for path in sorted((CORPUS / "cases").glob("*.toml")):
        text = path.read_text(encoding="utf-8")
        for value in PLACEHOLDERS.values():
            if len(value) > 1:  # single characters are covered by the next check
                assert value not in text, f"{path.name} contains a raw value; use its placeholder"
        assert all(ch.isprintable() or ch in "\n" for ch in text), f"{path.name} has invisible characters"


def test_expectation_parsing():
    assert Expectation.parse("CI002 .github/workflows/a.yml:10") == Expectation(
        "CI002", ".github/workflows/a.yml", 10
    )
    assert Expectation.parse("PATH001 a b.yml") == Expectation("PATH001", "a b.yml", None)
    with pytest.raises(CorpusError):
        Expectation.parse("CI002")


def test_build_diff_round_trips_through_the_parser():
    text = build_diff(
        [
            {"path": "a.py", "removed": ["x = 1"], "added": ["x = 2", "y = 3"]},
            {"path": "new.sh", "status": "added", "added": ["echo hi"]},
            {"path": "gone.txt", "status": "deleted", "removed": ["bye"]},
            {"path": "img.png", "status": "added", "binary": True},
        ]
    )
    a, new, gone, img = parse_diff(text).files
    assert [line.text for line in a.added] == ["x = 2", "y = 3"]
    assert (new.kind, gone.kind, img.binary) == ("added", "deleted", True)


def test_case_validation(tmp_path):
    bad = tmp_path / "x.toml"
    bad.write_text('kind = "risky"\n')
    with pytest.raises(CorpusError, match="at least one"):
        load_case(bad)
    bad.write_text('kind = "benign"\nexpect = ["OBF001 a.py"]\n')
    with pytest.raises(CorpusError, match="use allow"):
        load_case(bad)


def test_known_noise_counts_as_false_positive_but_passes_the_gate():
    case = {
        "kind": "benign",
        "known_noise": ["NET003 app.py:1"],
        "file": [{"path": "app.py", "added": ['URL = "https://api.weather-data.io"']}],
    }
    result = evaluate_case("x", case)
    assert len(result.unexpected) == 1 and result.gate_ok and not result.passed


def test_a_new_false_positive_fails_the_gate():
    case = {"kind": "benign", "file": [{"path": "app.py", "added": ["eval(x)"]}]}
    assert not evaluate_case("x", case).gate_ok


def test_eval_cli_text_and_json(capsys):
    assert main(["eval", "--corpus", str(CORPUS)]) == 0
    assert "gate: PASS" in capsys.readouterr().out
    assert main(["eval", "--corpus", str(CORPUS), "--format", "json"]) == 0
    assert '"gate_passed": true' in capsys.readouterr().out
    assert main(["eval", "--corpus", "does-not-exist"]) == 2
