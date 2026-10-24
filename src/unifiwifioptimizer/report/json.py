"""The report as one JSON document for every site of the run.

The models walk through the domain's plain projection (secrets refused). `ensure_ascii` keeps every
non-ASCII code point escaped, so a bidirectional override in an access point name stays visible as
`\\u202e` instead of reordering the viewer's terminal. No secret type is reachable from a `SiteReport`;
the renderer still refuses one.
"""

import json
from collections.abc import Sequence
from typing import Any

from unifiwifioptimizer.domain.plain import SecretPolicy
from unifiwifioptimizer.domain.plain import plain as to_plain
from unifiwifioptimizer.domain.report import SiteReport

SCHEMA_VERSION = 1


def plain(value: object) -> Any:
    return to_plain(value, SecretPolicy.REFUSE)


def site_document(report: SiteReport) -> dict[str, Any]:
    """The nested model plus the derived views the text renderer prints, so both outputs say the same."""
    document: dict[str, Any] = plain(report)
    if report.extended_channel_plan is None:
        document.pop("extended_channel_plan")
    if report.rf.client_tx_dbm_5g_upper is None:
        document["rf"].pop("client_tx_dbm_5g_upper")
        for ap in document["aps"]:
            for band in ap["bands"]:
                band.pop("assumed_client_tx_dbm")
        for wlan in document["roaming"]:
            for detail in wlan["per_ap"]:
                detail.pop("assumed_client_tx_dbm")
    document["derived"] = {
        "pending_tx_changes": report.pending_tx_changes,
        "waiting_items": report.waiting_items,
        "has_changes": report.has_changes,
        "partial": report.partial,
        "recommendations": plain(report.recommendations),
        "findings": plain(report.findings),
        "checks": plain(report.checks),
    }
    pruned: dict[str, Any] = _without_unset(document, "deferred_by")
    return pruned


def _without_unset(node: Any, key: str) -> Any:
    """Optional keys are omitted while unset, so a report without them keeps its schema-1 shape."""
    if isinstance(node, dict):
        return {k: _without_unset(v, key) for k, v in node.items() if not (k == key and v is None)}
    if isinstance(node, list):
        return [_without_unset(item, key) for item in node]
    return node


def render_json(reports: Sequence[SiteReport]) -> str:
    document = {"schema_version": SCHEMA_VERSION, "sites": [site_document(r) for r in reports]}
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
