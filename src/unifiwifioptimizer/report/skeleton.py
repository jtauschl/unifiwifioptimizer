"""A `config.yaml` skeleton for one site, prefilled from what the controller reports."""

import unicodedata
from collections import Counter

from unifiwifioptimizer.app.use_cases import SiteOverview
from unifiwifioptimizer.config.schema import SshAuth
from unifiwifioptimizer.report.safe_text import UNSAFE_CATEGORIES


def yaml_scalar(value: str) -> str:
    """One double-quoted YAML scalar the strict loader reads back unchanged, whatever the text looks like
    (`off`, `12`, `a: b`), with every control, format, separator, surrogate, private-use and unassigned
    character written as an escape so the skeleton is safe to print and stays valid YAML."""
    out: list[str] = []
    for char in value:
        if char in '"\\':
            out.append("\\" + char)
        elif unicodedata.category(char) in UNSAFE_CATEGORIES:
            code = ord(char)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def render_skeleton(overview: SiteOverview) -> str:
    ap_names = Counter(ap.name for ap in overview.access_points)
    lines = [
        f"  {yaml_scalar(overview.site.id)}:",
        "    ssh:",
        f"      # {SshAuth.CONTROLLER}: use the SSH credentials the controller manages for its access points;",
        f"      # {SshAuth.KEY}: your own key (set user, optionally key_file); {SshAuth.PASSWORD}: user + password.",
        f"      auth: {SshAuth.CONTROLLER}",
        "",
        "    # Open, Residential, Office, Obstructed, or a custom path-loss exponent",
        "    environment: Residential",
        "",
        "    # Round-robin scan passes per run; readings are aggregated as the median,",
        "    # so 3 or more passes outvote a single outlier.",
        "    scan_passes: 3",
        "",
        "    # Standard, Compat, IoT, or Hotspot (docs/PROFILES.md says which fits which device)",
        "    wlans:",
    ]
    wlans = sorted({w.name for w in overview.wlans})
    lines += [f"      {yaml_scalar(name)}: Standard" for name in wlans] or ["      # no WLANs reported"]
    lines += [
        "",
        "    # Which access points can hear each other: fill in the neighbours of every access point;",
        "    # the tool cannot know your floor plan. Scans run between the listed pairs only.",
        "    neighbors:",
    ]
    for name in sorted(ap_names):
        lines.append(f"      {yaml_scalar(name)}: []")
        if ap_names[name] > 1:
            lines.append(f"      # {ap_names[name]} access points share this name; rename them to tell them apart")
    if not ap_names:
        lines.append("      # no access points reported")
    if overview.mgmt is not None and overview.mgmt.ssh_enabled is False:
        lines += ["", "    # SSH is disabled on this controller; `auth: controller` cannot work until it is enabled."]
    return "\n".join(lines) + "\n"
