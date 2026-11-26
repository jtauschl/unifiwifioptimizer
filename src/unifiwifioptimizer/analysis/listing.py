"""Names inside a finding sentence."""

from collections.abc import Sequence

# The largest count for which every sentence that lists names stays below the report's sentence bound: with
# names of the parser's longest length, five fit the longest such sentence and six do not.
MAX_LISTED_NAMES = 5


def listed(names: Sequence[str]) -> str:
    """The first `MAX_LISTED_NAMES` of `names` joined by commas, then ` and N more` for the rest. A sentence
    that lists names has a length of its own that way, whatever the site holds, and its advice is never the
    part a bound cuts."""
    shown = ", ".join(names[:MAX_LISTED_NAMES])
    rest = len(names) - MAX_LISTED_NAMES
    return f"{shown} and {rest} more" if rest > 0 else shown
