"""Plain-text renderers for the read-only subcommands."""

from unifiwifioptimizer.app.use_cases import SiteOverview, SitesOverview
from unifiwifioptimizer.domain.models import FieldProblem
from unifiwifioptimizer.report.safe_text import safe_text


def render_sites(overview: SitesOverview) -> str:
    lines = ["", f"  {'Site ID':<20}  {'Site Name':<24}  Access Points"]
    for summary in overview.sites:
        count = str(summary.access_point_count)
        if summary.unparsable_count:
            count += f" (+{summary.unparsable_count} unparsable)"
        lines.append(f"  {safe_text(summary.site.id, 20):<20}  {safe_text(summary.site.description, 24):<24}  {count}")
    if not overview.sites:
        lines.append("  No UniFi sites were returned by the controller.")
    lines.append("")
    return "\n".join(lines) + "\n" + render_problems(overview.problems)


def render_site(overview: SiteOverview) -> str:
    lines = [
        "",
        f"  Site ID:   {safe_text(overview.site.id)}",
        f"  Site Name: {safe_text(overview.site.description)}",
        "",
    ]
    lines.append("  WLANs:")
    wlans = sorted(overview.wlans, key=lambda w: w.name)
    lines += [f"    {safe_text(w.name)} ({'enabled' if w.enabled else 'disabled'})" for w in wlans] or ["    none"]
    lines += ["", "  Access Points:"]
    aps = sorted(overview.access_points, key=lambda ap: ap.name)
    for ap in aps:
        radios = ", ".join(
            f"{r.band.label} ch {r.channel if r.channel is not None else 'auto'}/{r.width_mhz} MHz" for r in ap.radios
        )
        model = safe_text(ap.model) if ap.model is not None else "unknown model"
        lines.append(f"    {safe_text(ap.name)} ({model}, {ap.mac}) {radios}")
    for device in overview.unparsable_devices:
        label = safe_text(device.name) if device.name is not None else (device.mac or "unknown device")
        lines.append(f"    {label}: not usable ({safe_text(device.reason, 120)})")
    if not aps and not overview.unparsable_devices:
        lines.append("    none")
    lines.append("")
    return "\n".join(lines) + "\n" + render_problems(overview.problems)


def render_problems(problems: tuple[FieldProblem, ...]) -> str:
    if not problems:
        return ""
    lines = [f"  Note: {len(problems)} controller field(s) could not be used:"]
    lines += [f"    {safe_text(p.path, 100)}: {safe_text(p.message, 80)}" for p in problems[:20]]
    if len(problems) > 20:
        lines.append(f"    ... and {len(problems) - 20} more")
    return "\n".join(lines) + "\n\n"
