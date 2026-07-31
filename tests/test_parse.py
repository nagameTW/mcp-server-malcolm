"""Pins parse_int_list against str.isdigit()'s false positives.

Was: `if not token.isdigit(): raise ToolInputError(...)`. str.isdigit() is
True for two different kinds of Unicode digit, and int() only agrees with it
for one of them:

  * "No" category (e.g. "①" CIRCLED DIGIT ONE): isdigit() is True, int()
    raises ValueError. Because the old check let it through, that ValueError
    escaped straight out of parse_int_list uncaught -- a raw ValueError
    instead of the crafted ToolInputError the docstring promises.
  * "Nd" category (e.g. "٣" ARABIC-INDIC THREE, "１" FULLWIDTH ONE): isdigit()
    is True AND int() happily converts it (int("٣") == 3) -- so the old check
    silently accepted a non-ASCII digit as though it were an ordinary one.

Fixed to `_DIGITS.fullmatch(token)`, ASCII digits only, so both kinds are
rejected with the same named-token message before int() ever sees them.
"""

from __future__ import annotations

import pytest

from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools._parse import parse_int_list


def test_a_no_category_unicode_digit_raises_tool_input_error_not_value_error():
    """ "①".isdigit() is True but int("①") raises -- this is the crash the fix
    exists to prevent, not just a stricter validation choice."""
    with pytest.raises(ToolInputError) as err:
        parse_int_list("①,2", "severity", '"1,2" (1=high, 2=medium, 3=low)')
    assert "①" in str(err.value)


@pytest.mark.parametrize("digit", ["٣", "１"])
def test_other_unicode_decimal_digits_are_also_rejected(digit: str):
    """These convert cleanly under int() (int("٣") == 3), so the old code
    silently accepted them; the fix's ASCII-only rule rejects them too."""
    with pytest.raises(ToolInputError) as err:
        parse_int_list(f"{digit},2", "severity", '"1,2"')
    assert digit in str(err.value)


def test_ordinary_ascii_values_still_parse():
    assert parse_int_list("1, 2,3", "severity", '"1,2"') == [1, 2, 3]
