"""The claim "every rejection code has a test", stated as a test.

docs/errors.md is the reference a caller reads, and nothing checked that it had not grown
past the suite: a code could be documented, relied on by an operator, and never executed by
anything. This module parses the document, collects every code in its first column (the
column a reader scans), and fails if a code is neither exercised by a test nor listed in
UNREACHABLE with a reason.

Coverage is decided by the literal code string appearing in a test source, not by importing
anything: a test that asserts on a reason field names the code, and that is the same string
an operator greps for.

Reachable through the public API is the bar. A code that a test can only reach by deleting
its own arithmetic does not count; it goes in UNREACHABLE with one sentence saying why.
"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ERRORS_MD = HERE.parent / 'docs' / 'errors.md'
SELF = Path(__file__).resolve().name

# code -> why no test can trigger it. Empty today: all 57 documented codes are exercised.
# An entry here is a claim about the code, not a TODO; it is the only way to add a refusal
# without a test. test_the_checker_reports_an_explained_code proves the table is consulted.
UNREACHABLE = {}

# A code is matched as a whole token: MISSING must not be satisfied by MISSING_TICKET, and
# SUPERSEDED must not be satisfied by ALREADY_SUPERSEDED.
_WORD = r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])'


def documented_codes(path=ERRORS_MD):
    """Every code in the first column of every table row, in document order."""
    codes = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped.startswith('|'):
            continue
        first_cell = stripped.strip('|').split('|')[0]
        for code in re.findall(r'`([A-Z][A-Z0-9_]{2,})`', first_cell):
            if code not in codes:
                codes.append(code)
    return codes


def _test_sources():
    """Test sources searched for a code, this module excluded: it names every documented code,
    so searching it would make every code look covered."""
    return {p.name: p.read_text(encoding='utf-8')
            for p in sorted(HERE.glob('*.py')) if p.name != SELF}


def is_covered(code, sources):
    pattern = _WORD % re.escape(code)
    return any(re.search(pattern, text) for text in sources.values())


def uncovered(documented, sources, exceptions):
    """Codes with neither a test nor a reason. Empty is the only acceptable answer."""
    return sorted(c for c in documented
                  if not is_covered(c, sources) and c not in exceptions)


# -- the document is parsed, not assumed --------------------------------------------------

def test_the_document_is_parsed_as_a_table_of_codes():
    codes = documented_codes()
    # A parser that silently returns nothing would make every other assertion here vacuous.
    assert len(codes) >= 50, codes
    assert 'MISSING_TICKET' in codes and 'MISSING' in codes, codes
    assert codes == [c for i, c in enumerate(codes) if c not in codes[:i]], 'duplicates'


def test_every_documented_code_is_exercised_or_explained():
    documented = documented_codes()
    missing = uncovered(documented, _test_sources(), UNREACHABLE)
    assert missing == [], (
        'documented in docs/errors.md but no test exercises them and no reason is given in '
        'tests/test_error_coverage.py UNREACHABLE: %s' % missing)


def test_the_exception_table_names_only_documented_codes():
    """A stale entry (a code renamed or dropped) must not sit there explaining nothing."""
    assert sorted(set(UNREACHABLE) - set(documented_codes())) == []


def test_the_checker_reports_a_code_that_is_neither_tested_nor_explained():
    """The mechanism itself: without this, an empty result proves only that nothing ran."""
    not_a_code = 'NEVER_DOCUMENTED_CODE'
    assert uncovered([not_a_code], {}, {}) == [not_a_code]
    assert uncovered([not_a_code], {}, {not_a_code: 'unreachable by construction'}) == []
    assert uncovered([not_a_code], {'x.py': "assert r['error'] == 'NEVER_DOCUMENTED_CODE'"}, {}) == []
