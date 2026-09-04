"""Content-policy categories that organisations can block (e.g. gambling).

Rows in `known_threats` backed by these categories are enforced only when the
category is enabled in the org content policy. Uncategorized rows are treated
as malware regardless of the policy.
"""
from __future__ import annotations

# Canonical categories. Admins store a subset of these in the content policy
# setting; a categorized site is blocked only when its category is active.
CONTENT_CATEGORIES: tuple[str, ...] = (
    "GAMBLING",
    "ADULT",
    "SOCIAL_MEDIA",
    "OTHER",
)

CATEGORY_LABELS: dict[str, str] = {
    "GAMBLING": "Gambling / betting",
    "ADULT": "Adult content",
    "SOCIAL_MEDIA": "Social media",
    "OTHER": "Other blocked content",
}