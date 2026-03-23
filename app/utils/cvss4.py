# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
CVSS 4.0 score computation.

Implements the CVSS 4.0 scoring algorithm per FIRST specification:
https://www.first.org/cvss/v4.0/specification-document

Base metrics:
  AV (Attack Vector), AC (Attack Complexity), AT (Attack Requirements)
  PR (Privileges Required), UI (User Interaction)
  VC, VI, VA (Vulnerable System Confidentiality/Integrity/Availability)
  SC, SI, SA (Subsequent System Confidentiality/Integrity/Availability)

Threat metrics:
  E (Exploit Maturity)

Environmental metrics:
  CR, IR, AR (Confidentiality/Integrity/Availability Requirements)
  + Modified base metrics (MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA)

Supplemental metrics (informational, don't affect score):
  S, AU, R, V, RE, U
"""

import math
import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# CVSS 4.0 metric values
# ---------------------------------------------------------------------------

# Base metrics
AV_VALUES = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
AC_VALUES = {"L": "Low", "H": "High"}
AT_VALUES = {"N": "None", "P": "Present"}
PR_VALUES = {"N": "None", "L": "Low", "H": "High"}
UI_VALUES = {"N": "None", "P": "Passive", "A": "Active"}
VC_VALUES = {"H": "High", "L": "Low", "N": "None"}
VI_VALUES = {"H": "High", "L": "Low", "N": "None"}
VA_VALUES = {"H": "High", "L": "Low", "N": "None"}
SC_VALUES = {"H": "High", "L": "Low", "N": "None"}
SI_VALUES = {"S": "Safety", "H": "High", "L": "Low", "N": "None"}
SA_VALUES = {"S": "Safety", "H": "High", "L": "Low", "N": "None"}

# Threat metrics
E_VALUES = {"X": "Not Defined", "A": "Attacked", "P": "POC", "U": "Unreported"}

# Environmental requirement metrics
CR_VALUES = {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}
IR_VALUES = {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}
AR_VALUES = {"X": "Not Defined", "H": "High", "M": "Medium", "L": "Low"}

# Severity thresholds per CVSS 4.0 spec
SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "NONE"),
]

# CVSS 4.0 eq lookup tables (simplified — full eq lookup tables per spec appendix)
# Score lookup by EQ combination (EQ1, EQ2, EQ3, EQ4, EQ5, EQ6)
# This is a simplified implementation; full tables are in the FIRST spec

EQ1_LEVELS = {
    0: {"AV": "N", "PR": "N", "UI": "N"},
    1: {"AV": ["N", "A"], "PR": "N", "UI": "N"},
    2: {},  # Catch-all
}


@dataclass
class CVSSVector:
    """Parsed CVSS 4.0 vector components."""
    # Base metrics
    AV: str = "N"
    AC: str = "L"
    AT: str = "N"
    PR: str = "N"
    UI: str = "N"
    VC: str = "H"
    VI: str = "H"
    VA: str = "H"
    SC: str = "H"
    SI: str = "H"
    SA: str = "H"
    # Threat
    E: str = "X"
    # Environmental requirements
    CR: str = "X"
    IR: str = "X"
    AR: str = "X"
    # Modified base
    MAV: str = "X"
    MAC: str = "X"
    MAT: str = "X"
    MPR: str = "X"
    MUI: str = "X"
    MVC: str = "X"
    MVI: str = "X"
    MVA: str = "X"
    MSC: str = "X"
    MSI: str = "X"
    MSA: str = "X"
    # Supplemental (informational only)
    S: str = "X"
    AU: str = "X"
    R: str = "X"
    V: str = "X"
    RE: str = "X"
    U: str = "X"


def parse_vector(vector_string: str) -> Optional[CVSSVector]:
    """
    Parse a CVSS 4.0 vector string into a CVSSVector object.

    Args:
        vector_string: CVSS 4.0 vector string, e.g.:
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

    Returns:
        CVSSVector object, or None if parsing fails.
    """
    if not vector_string:
        return None

    # Normalize: strip whitespace, handle both "CVSS:4.0/" prefix and raw metrics
    vector = vector_string.strip()
    if vector.startswith("CVSS:4.0/"):
        vector = vector[len("CVSS:4.0/"):]

    # Parse key:value pairs
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key.strip().upper()] = value.strip().upper()

    if not metrics:
        return None

    # Build CVSSVector from parsed metrics
    cv = CVSSVector()
    for field in CVSSVector.__dataclass_fields__:
        if field in metrics:
            setattr(cv, field, metrics[field])

    return cv


def compute_score(vector: CVSSVector) -> float:
    """
    Compute the CVSS 4.0 score from a parsed vector.

    This is a simplified implementation of the CVSS 4.0 scoring algorithm.
    The full algorithm uses lookup tables (EQ levels) per the FIRST specification.
    For production use, consider using the official cvss4 Python library.

    Args:
        vector: Parsed CVSSVector object.

    Returns:
        CVSS 4.0 score (0.0 to 10.0), rounded to 1 decimal place.
    """
    # Determine effective values (modified metrics override base if set)
    eff_av = vector.MAV if vector.MAV != "X" else vector.AV
    eff_ac = vector.MAC if vector.MAC != "X" else vector.AC
    eff_at = vector.MAT if vector.MAT != "X" else vector.AT
    eff_pr = vector.MPR if vector.MPR != "X" else vector.PR
    eff_ui = vector.MUI if vector.MUI != "X" else vector.UI
    eff_vc = vector.MVC if vector.MVC != "X" else vector.VC
    eff_vi = vector.MVI if vector.MVI != "X" else vector.VI
    eff_va = vector.MVA if vector.MVA != "X" else vector.VA
    eff_sc = vector.MSC if vector.MSC != "X" else vector.SC
    eff_si = vector.MSI if vector.MSI != "X" else vector.SI
    eff_sa = vector.MSA if vector.MSA != "X" else vector.SA

    # EQ1: Exploitability metrics
    eq1 = _compute_eq1(eff_av, eff_pr, eff_ui)

    # EQ2: Complexity metrics
    eq2 = _compute_eq2(eff_ac, eff_at)

    # EQ3: Vulnerable system impact
    eq3 = _compute_eq3(eff_vc, eff_vi, eff_va)

    # EQ4: Subsequent system impact
    eq4 = _compute_eq4(eff_sc, eff_si, eff_sa)

    # EQ5: Threat metric
    eq5 = _compute_eq5(vector.E)

    # EQ6: Environmental requirements
    eq6 = _compute_eq6(vector.CR, vector.IR, vector.AR, eff_vc, eff_vi, eff_va)

    # Look up base score from EQ combination
    score = _lookup_score(eq1, eq2, eq3, eq4, eq5, eq6)

    return round(max(0.0, min(10.0, score)), 1)


def score_from_vector_string(vector_string: str) -> Optional[float]:
    """
    Parse a vector string and return the CVSS 4.0 score.

    Args:
        vector_string: CVSS 4.0 vector string.

    Returns:
        Score (0.0–10.0) or None if parsing fails.
    """
    vector = parse_vector(vector_string)
    if vector is None:
        return None
    return compute_score(vector)


def severity_from_score(score: float) -> str:
    """
    Return the severity label for a CVSS 4.0 score.

    Args:
        score: CVSS 4.0 numeric score.

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
    """
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "NONE"


def severity_from_vector(vector_string: str) -> Optional[str]:
    """
    Compute severity directly from a vector string.

    Args:
        vector_string: CVSS 4.0 vector string.

    Returns:
        Severity string or None if parsing fails.
    """
    score = score_from_vector_string(vector_string)
    if score is None:
        return None
    return severity_from_score(score)


# ---------------------------------------------------------------------------
# EQ level computation helpers
# ---------------------------------------------------------------------------

def _compute_eq1(av: str, pr: str, ui: str) -> int:
    """EQ1 level (0-2): exploitability."""
    if av == "N" and pr == "N" and ui == "N":
        return 0
    if (av == "N" or pr == "N" or ui == "N") and not (av == "P"):
        return 1
    return 2


def _compute_eq2(ac: str, at: str) -> int:
    """EQ2 level (0-1): attack complexity."""
    if ac == "L" and at == "N":
        return 0
    return 1


def _compute_eq3(vc: str, vi: str, va: str) -> int:
    """EQ3 level (0-2): vulnerable system impact."""
    if vc == "H" or vi == "H" or va == "H":
        return 0
    if vc == "L" or vi == "L" or va == "L":
        return 1
    return 2


def _compute_eq4(sc: str, si: str, sa: str) -> int:
    """EQ4 level (0-2): subsequent system impact."""
    if si == "S" or sa == "S":
        return 0
    if sc == "H" or si == "H" or sa == "H":
        return 1
    return 2


def _compute_eq5(e: str) -> int:
    """EQ5 level (0-2): threat maturity."""
    if e == "X" or e == "A":
        return 0
    if e == "P":
        return 1
    return 2  # U = Unreported


def _compute_eq6(cr: str, ir: str, ar: str, vc: str, vi: str, va: str) -> int:
    """EQ6 level (0-2): environmental requirements."""
    # High requirements + high impact
    if ((cr == "H" or cr == "X") and vc == "H") or \
       ((ir == "H" or ir == "X") and vi == "H") or \
       ((ar == "H" or ar == "X") and va == "H"):
        return 0
    if ((cr == "H" or cr == "X") and vc != "N") or \
       ((ir == "H" or ir == "X") and vi != "N") or \
       ((ar == "H" or ar == "X") and va != "N"):
        return 1
    return 2


# Simplified lookup table (EQ1+EQ2, EQ3+EQ4, EQ5, EQ6) → base score
# Full 6-dimensional table per FIRST spec appendix
_SCORE_TABLE: dict[tuple, float] = {
    # (eq1, eq2, eq3, eq4, eq5, eq6) -> score
    (0, 0, 0, 0, 0, 0): 10.0,
    (0, 0, 0, 0, 0, 1): 9.9,
    (0, 0, 0, 0, 0, 2): 9.8,
    (0, 0, 0, 0, 1, 0): 9.5,
    (0, 0, 0, 0, 1, 1): 9.5,
    (0, 0, 0, 0, 1, 2): 9.4,
    (0, 0, 0, 0, 2, 0): 9.0,
    (0, 0, 0, 1, 0, 0): 9.4,
    (0, 0, 0, 1, 0, 1): 9.3,
    (0, 0, 0, 1, 0, 2): 9.2,
    (0, 0, 0, 1, 1, 0): 9.0,
    (0, 0, 0, 1, 1, 1): 8.9,
    (0, 0, 0, 1, 1, 2): 8.8,
    (0, 0, 0, 2, 0, 0): 9.0,
    (0, 0, 0, 2, 0, 1): 8.9,
    (0, 0, 1, 0, 0, 0): 9.4,
    (0, 0, 1, 0, 0, 1): 9.3,
    (0, 0, 1, 1, 0, 0): 8.9,
    (0, 0, 2, 0, 0, 0): 8.3,
    (0, 1, 0, 0, 0, 0): 9.0,
    (0, 1, 0, 0, 0, 1): 8.9,
    (0, 1, 0, 1, 0, 0): 8.5,
    (0, 1, 1, 0, 0, 0): 8.5,
    (0, 1, 2, 0, 0, 0): 7.7,
    (1, 0, 0, 0, 0, 0): 8.9,
    (1, 0, 0, 0, 0, 1): 8.8,
    (1, 0, 0, 1, 0, 0): 8.5,
    (1, 0, 1, 0, 0, 0): 8.5,
    (1, 0, 2, 0, 0, 0): 7.7,
    (1, 1, 0, 0, 0, 0): 8.4,
    (1, 1, 0, 1, 0, 0): 7.9,
    (1, 1, 1, 0, 0, 0): 7.9,
    (1, 1, 2, 0, 0, 0): 6.9,
    (2, 0, 0, 0, 0, 0): 8.1,
    (2, 0, 0, 1, 0, 0): 7.6,
    (2, 0, 1, 0, 0, 0): 7.6,
    (2, 0, 2, 0, 0, 0): 6.5,
    (2, 1, 0, 0, 0, 0): 7.0,
    (2, 1, 0, 1, 0, 0): 6.5,
    (2, 1, 1, 0, 0, 0): 6.5,
    (2, 1, 2, 0, 0, 0): 5.4,
}


def _lookup_score(eq1: int, eq2: int, eq3: int, eq4: int, eq5: int, eq6: int) -> float:
    """Look up score from EQ combination."""
    key = (eq1, eq2, eq3, eq4, eq5, eq6)
    if key in _SCORE_TABLE:
        return _SCORE_TABLE[key]

    # Interpolate for missing combinations
    # Simplified: use closest lower EQ combination
    best_score = 0.0
    for stored_key, score in _SCORE_TABLE.items():
        if all(stored_key[i] <= key[i] for i in range(6)):
            best_score = max(best_score, score)

    # Reduce by EQ5 and EQ6 contributions if not found
    base = best_score
    if eq5 > 0:
        base = max(0.0, base - eq5 * 0.5)
    if eq6 > 0:
        base = max(0.0, base - eq6 * 0.2)

    return base


def build_vector_string(vector: CVSSVector) -> str:
    """
    Build a CVSS 4.0 vector string from a CVSSVector object.

    Args:
        vector: CVSSVector object.

    Returns:
        CVSS 4.0 vector string.
    """
    parts = [
        "CVSS:4.0",
        f"AV:{vector.AV}",
        f"AC:{vector.AC}",
        f"AT:{vector.AT}",
        f"PR:{vector.PR}",
        f"UI:{vector.UI}",
        f"VC:{vector.VC}",
        f"VI:{vector.VI}",
        f"VA:{vector.VA}",
        f"SC:{vector.SC}",
        f"SI:{vector.SI}",
        f"SA:{vector.SA}",
    ]

    # Add non-default threat/environmental/supplemental metrics
    if vector.E != "X":
        parts.append(f"E:{vector.E}")
    if vector.CR != "X":
        parts.append(f"CR:{vector.CR}")
    if vector.IR != "X":
        parts.append(f"IR:{vector.IR}")
    if vector.AR != "X":
        parts.append(f"AR:{vector.AR}")

    return "/".join(parts)
