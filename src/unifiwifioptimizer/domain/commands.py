"""The commands the tool prints for a person to paste.

Every printed command starts with the program name and repeats the options of the invocation that select the files it
reads: `--config-file` (a global option, so it sits before the subcommand) on every command, `--known-hosts` on the
command that takes it. The option texts arrive finished (quoted, sanitised and bounded by the CLI, which owns the
quoting); this module owns where each option sits and nothing else.
"""

from dataclasses import dataclass

PROGRAM = "unifiwifioptimizer"
CONFIG_FILE_OPTION = "--config-file"
KNOWN_HOSTS_OPTION = "--known-hosts"


@dataclass(frozen=True, slots=True, kw_only=True)
class PrintedCommands:
    """`config_option` and `store_option` are `""` or an option with its leading blank, for example
    ` --config-file=/etc/uwo/home.yaml`. `withheld` names the options the run was given whose value could not be printed
    as typed: the option is then printed with an empty value, which every shell hands on unchanged and the parser
    refuses before it reads a file, and a note after the command says to fill it in. Each method returns the command
    in backticks, with that note after it where one applies."""

    config_option: str
    store_option: str
    withheld: tuple[str, ...]

    def _span(self, words: str, *, takes_store: bool = False) -> str:
        names = [n for n in self.withheld if takes_store or n != KNOWN_HOSTS_OPTION]
        note = ""
        if names:
            many = len(names) > 1
            values, options = ("values", "options") if many else ("value", "option")
            note = (
                f" (the {values} of {' and '.join(names)} in this run cannot be printed as typed; "
                f"fill in the empty {options})"
            )
        return f"`{PROGRAM}{self.config_option} {words}`{note}"

    def trust_host_keys(self, site_id: str) -> str:
        return self._span(f"trust-host-keys --site {site_id}{self.store_option}", takes_store=True)

    def site(self, site_id: str) -> str:
        return self._span(f"site {site_id}")

    def config(self, site_id: str) -> str:
        return self._span(f"config {site_id}")

    def controller_fingerprint(self) -> str:
        return self._span("controller-fingerprint")

    def init(self) -> str:
        return self._span("init")


def controller_fingerprint_for(url: str) -> str:
    """The command that prints the fingerprint of a URL typed a moment ago, valid as `parse_controller_url` takes it
    (so it needs no quoting). With `--url` it reads no file, so it repeats no option of the run."""
    return f"`{PROGRAM} controller-fingerprint --url={url}`"
