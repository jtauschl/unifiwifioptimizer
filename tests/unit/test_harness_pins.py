"""Every package a harness image installs carries an exact version.

A digest-pinned base image still serves whatever package versions its index holds on build day, so two builds
weeks apart could run the tests against different dropbear or OpenSSH releases. A pinned version that leaves
the index fails the build loudly; that is the point. The check reads `apk add`, `apt-get install` and
`apt install`, refuses the commands that move already installed packages (`upgrade`) or install around the
package manager, and reports the exec and heredoc forms of `RUN`, which it cannot read, instead of skipping them.
"""

import re
import shlex
from collections.abc import Iterator
from pathlib import Path

import pytest

DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"

_TOOLS = frozenset({"apk", "apt-get", "apt"})
_INSTALL_SUBCOMMANDS = frozenset({"add", "install"})
_UPGRADE_SUBCOMMANDS = frozenset({"upgrade", "dist-upgrade", "full-upgrade"})
_OUTSIDE_THE_PACKAGE_MANAGER = frozenset({"dpkg", "aptitude", "pip", "pip3"})
_FLAGS = frozenset({"-y", "--yes", "--no-cache", "--no-install-recommends", "-q", "-qq", "--quiet", "-U", "--update"})
_FLAGS_WITH_VALUE = frozenset({"-o", "-c", "-t", "-X", "--repository"})
_REDIRECTS = frozenset({">", ">>", "<", ">&", "&>", ">|", "<>", "<&"})
_SEPARATORS = frozenset({"&&", "||", ";", ";;", "|", "&", "(", ")"})
_FD_REDIRECT = re.compile(r"(?<![^\s;&|()])\d+(?=[<>])")
_EXACT_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*=[A-Za-z0-9][^\s=$<>*?\[\]]*")


def _instructions(dockerfile: str) -> Iterator[str]:
    # Docker drops a comment line inside a continued instruction before the shell sees it.
    # Docker also skips an empty line inside a continued instruction (it only warns).
    kept = "\n".join(line for line in dockerfile.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    joined = re.sub(r"\\[ \t]*\n", " ", kept)
    for line in joined.splitlines():
        match = re.match(r"\s*RUN\s+(.*)", line, flags=re.IGNORECASE)
        if match:
            yield match.group(1).strip()


def _readable(instruction: str) -> bool:
    command = re.sub(r"""^(?:--(?:[^\s"']|"[^"]*"|'[^']*')*\s+)*""", "", instruction)
    return not command.startswith("[") and "<<" not in command


def _tokens(instruction: str) -> list[str]:
    lexer = shlex.shlex(_FD_REDIRECT.sub("", instruction), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    # The shell starts a comment only at the start of a word; a `#` inside one (`sed s#a#b#`) must not cut the rest off.
    lexer.commenters = ""
    return list(lexer)


def _command_arguments(tokens: list[str], start: int) -> list[str]:
    arguments: list[str] = []
    index = start
    while index < len(tokens) and tokens[index] not in _SEPARATORS:
        if tokens[index] in _REDIRECTS:
            index += 2
        else:
            arguments.append(tokens[index])
            index += 1
    return arguments


def _split_call(arguments: list[str]) -> tuple[str | None, list[str], list[str]]:
    """The subcommand of a package-manager call, the problems of its options, and its operands."""
    subcommand: str | None = None
    problems: list[str] = []
    operands: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _FLAGS_WITH_VALUE:
            index += 1
        elif argument.startswith("-"):
            if argument not in _FLAGS:
                problems.append(f"unrecognised flag {argument}")
        elif subcommand is None:
            subcommand = argument
        else:
            operands.append(argument)
        index += 1
    return subcommand, problems, operands


def _calls(tokens: list[str]) -> Iterator[tuple[str, str | None, list[str], list[str]]]:
    for index, token in enumerate(tokens):
        tool = Path(token).name
        if tool in _TOOLS:
            yield (tool, *_split_call(_command_arguments(tokens, index + 1)))


def installation_problems(dockerfile: str) -> list[str]:
    """Everything in the `RUN` instructions that lets an installed package float."""
    problems: list[str] = []
    for instruction in _instructions(dockerfile):
        if not _readable(instruction):
            problems.append(f"RUN form the check cannot read: {instruction[:40]}")
            continue
        tokens = _tokens(instruction)
        problems.extend(
            f"installs around apk/apt: {token}" for token in tokens if Path(token).name in _OUTSIDE_THE_PACKAGE_MANAGER
        )
        for tool, subcommand, option_problems, operands in _calls(tokens):
            if subcommand in _UPGRADE_SUBCOMMANDS:
                problems.append(f"{tool} {subcommand} moves installed packages")
            if subcommand not in _INSTALL_SUBCOMMANDS:
                continue
            problems.extend(option_problems)
            if not operands:
                problems.append(f"{tool} {subcommand} names no package")
            problems.extend(
                f"not an exact version: {operand}" for operand in operands if not _EXACT_PACKAGE.fullmatch(operand)
            )
    return problems


def _installed_packages(dockerfile: str) -> list[str]:
    return [
        operand
        for instruction in filter(_readable, _instructions(dockerfile))
        for _, subcommand, _, operands in _calls(_tokens(instruction))
        if subcommand in _INSTALL_SUBCOMMANDS
        for operand in operands
    ]


def _dockerfiles() -> list[Path]:
    return sorted(DOCKER_DIR.glob("*/Dockerfile"))


@pytest.mark.parametrize("dockerfile", _dockerfiles(), ids=lambda path: path.parent.name)
def test_every_installed_harness_package_has_an_exact_version(dockerfile: Path) -> None:
    text = dockerfile.read_text()
    assert _installed_packages(text), f"{dockerfile.parent.name}: no package installation found, the check is blind"
    assert installation_problems(text) == []


def test_the_harness_has_images_to_check() -> None:
    assert {path.parent.name for path in _dockerfiles()} == {"ap", "ssh84"}


@pytest.mark.parametrize(
    "line",
    [
        "RUN apk add --no-cache dropbear=2025.88-r1 openssh-server=10.0_p1-r11",
        "RUN apt-get install -y --no-install-recommends openssh-client=1:8.4p1-5+deb11u7",
        "RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y curl=7.74.0-1.3+deb11u14",
        "RUN apt-get -o Acquire::Check-Valid-Until=false install -y foo=1.2-1~bpo11+1 bar=1:2.0~rc1-1",
        "RUN apk add --no-cache \\\n    dropbear=2025.88-r1 \\\n    netcat-openbsd=1.229.1-r0 \\\n  && adduser -D x",
        "RUN apk add --no-cache dropbear=2025.88-r1 \\   \n    netcat-openbsd=1.229.1-r0",
        "RUN apk add --no-cache dropbear=2025.88-r1 2>&1 | tee /log",
        "RUN apk add --no-cache dropbear=2025.88-r1 2>/dev/null",
        "RUN apk add --no-cache dropbear=2025.88-r1 &>/dev/null",
        "RUN apk add --no-cache dropbear=2025.88-r1 >/dev/null openssh-server=10.0_p1-r11",
        "RUN apk add --no-cache dropbear=2025.88-r1 2>&1 openssh-server=10.0_p1-r11",
        "RUN apk add dropbear=2025.88-r1 2>/dev/null \\\n    openssh-server=10.0_p1-r11",
        "RUN apk add dropbear=2025.88-r1 \\\n\n    openssh-server=10.0_p1-r11",
        "RUN apk add dropbear=2025.88-r1 \\\n   \n    openssh-server=10.0_p1-r11",
        "RUN apt-get install -y -t bullseye foo=1-1",
        "RUN apt-get install -y -o Dpkg::Options::=--force-confold foo=1-1",
        "RUN /sbin/apk add dropbear=2025.88-r1",
        "RUN apk add dropbear=2025.88-r1 >/dev/null && apk info",
        "RUN --mount=type=cache,target=/var/cache/apk apk add dropbear=2025.88-r1",
        "RUN sed -i s#a#b#g /etc/x && apk add dropbear=2025.88-r1",
        "RUN apk add dropbear=2025.88-r1 >|/log openssh-server=10.0_p1-r11",
        "RUN apk add dropbear=2025.88-r1 <>/log openssh-server=10.0_p1-r11",
        "RUN apk add dropbear=2025.88-r1 <&3 openssh-server=10.0_p1-r11",
        "RUN apk update && rm -rf /var/cache/apk/*",
        "RUN printf 'apk add unpinned && more' >/etc/note && true",
        "RUN\tapk add dropbear=2025.88-r1",
        "# apk add unpinned\nRUN echo hello",
        "RUN echo hello",
    ],
)
def test_pinned_or_unrelated_instructions_pass(line: str) -> None:
    assert installation_problems(line) == []


@pytest.mark.parametrize(
    ("line", "fragment"),
    [
        ("RUN apk add --no-cache dropbear", "not an exact version: dropbear"),
        ("RUN apk add --no-cache dropbear=2025.88-r1 openssh-server", "not an exact version: openssh-server"),
        ("RUN apt-get install -y --no-install-recommends openssh-client", "not an exact version: openssh-client"),
        ("RUN apk add dropbear>=2025", "not an exact version"),
        ("RUN apk add 'dropbear~=2025'", "not an exact version"),
        ("RUN apk add dropbear=", "not an exact version"),
        ("RUN apk add $PACKAGES", "not an exact version: $PACKAGES"),
        ("RUN apk add dropbear=$VERSION", "not an exact version"),
        ("RUN apt-get install -y 'openssh-client=1:8.4*'", "not an exact version"),
        ("RUN apt-get install -y 'openssh-client=1:8.4p1-?'", "not an exact version"),
        ("RUN apk add --virtual build-deps gcc=14.2.0-r6", "unrecognised flag --virtual"),
        ("RUN apt install -y curl", "not an exact version: curl"),
        ("RUN true && apk add --no-cache dropbear", "not an exact version: dropbear"),
        ("RUN apk --no-cache add dropbear", "not an exact version: dropbear"),
        ("RUN apk -U add dropbear", "not an exact version: dropbear"),
        ("RUN apt-get -y install openssh-client", "not an exact version: openssh-client"),
        ("RUN apt-get -qq install openssh-client", "not an exact version: openssh-client"),
        ("RUN apt-get -o Acquire::Check-Valid-Until=false install -y openssh-client", "openssh-client"),
        ("RUN apt-get -o Dpkg::Options::=--force-confold install -y openssh-client", "openssh-client"),
        ("RUN apk --frobnicate add dropbear=2025.88-r1", "unrecognised flag --frobnicate"),
        (
            "RUN apk add --no-cache dropbear=2025.88-r1 >/dev/null openssh-server",
            "not an exact version: openssh-server",
        ),
        ("RUN apk add --no-cache dropbear=2025.88-r1 2>&1 openssh-server", "not an exact version: openssh-server"),
        ("RUN apk add dropbear=2025.88-r1 1>/dev/null openssh-server", "not an exact version: openssh-server"),
        ("RUN apk add dropbear=2025.88-r1 2>/dev/null \\\n    openssh-server", "not an exact version: openssh-server"),
        ("RUN apk add dropbear=2025.88-r1 \\\n\n    openssh-server", "not an exact version: openssh-server"),
        ("RUN apk add dropbear=2025.88-r1 \\\n   \n    openssh-server", "not an exact version: openssh-server"),
        ("RUN apt-get install -y -t bullseye foo", "not an exact version: foo"),
        ("RUN xargs apk add < /pkgs", "apk add names no package"),
        ("RUN apt-get install -y", "apt-get install names no package"),
        ("RUN /sbin/apk add dropbear", "not an exact version: dropbear"),
        ("RUN apk upgrade", "apk upgrade moves installed packages"),
        ("RUN apt-get update && apt-get dist-upgrade -y", "moves installed packages"),
        ("RUN dpkg -i /tmp/x.deb", "installs around apk/apt: dpkg"),
        ("RUN pip install requests==2.0", "installs around apk/apt: pip"),
        ('RUN ["apk", "add", "dropbear"]', "RUN form the check cannot read"),
        ("RUN <<EOT\napk add dropbear\nEOT", "RUN form the check cannot read"),
        (
            "RUN apk add --no-cache \\\n    dropbear=2025.88-r1 \\\n    netcat-openbsd",
            "not an exact version: netcat-openbsd",
        ),
        (
            "RUN apk add --no-cache dropbear=2025.88-r1 \\\n# the second server\n    openssh-server \\\n  && true",
            "not an exact version: openssh-server",
        ),
        ("RUN apk add --no-cache dropbear=2025.88-r1 \\   \n    openssh-server", "openssh-server"),
        ("RUN sed -i s#a#b#g /etc/x && apk add openssh", "not an exact version: openssh"),
        ("RUN echo a#b; apk add bar", "not an exact version: bar"),
        ("RUN apk add foo=1-r0 --repository http://x/#y bar", "not an exact version: bar"),
        ("RUN apk add foo=1-r0 >|/log bar", "not an exact version: bar"),
        ("RUN apk add foo=1-r0 <>/log bar", "not an exact version: bar"),
        ("RUN apk add foo=1-r0 <&3 bar", "not an exact version: bar"),
        ('RUN --mount="type=bind,target=/a b" ["apk","add","foo"]', "RUN form the check cannot read"),
        ("RUN /usr/bin/pip install x", "installs around apk/apt: /usr/bin/pip"),
        ("RUN /usr/bin/dpkg -i x.deb", "installs around apk/apt: /usr/bin/dpkg"),
        ("RUN --mount=type=cache,target=/var/cache/apk <<EOT\napk add foo\nEOT", "RUN form the check cannot read"),
        ("RUN --network=none <<EOT\napk add foo\nEOT", "RUN form the check cannot read"),
        ('RUN --network=none ["apk","add","foo"]', "RUN form the check cannot read"),
        ("RUN apk add foo=1-r0 && sh <<EOT\napk add bar\nEOT", "RUN form the check cannot read"),
        ("RUN\tapk add dropbear", "not an exact version: dropbear"),
        ("run apk add dropbear", "not an exact version: dropbear"),
    ],
)
def test_an_unpinned_installation_is_reported(line: str, fragment: str) -> None:
    assert any(fragment in problem for problem in installation_problems(line)), installation_problems(line)
