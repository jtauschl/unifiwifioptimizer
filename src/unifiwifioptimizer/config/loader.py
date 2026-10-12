"""Strict YAML loading of the configuration file.

The file holds the API key and possibly an SSH password, so it is read through a descriptor chain that
refuses symlinks, non-regular files, foreign owners and group/world-readable modes, under a size cap and
a parse deadline. The YAML dialect is deliberately narrower than PyYAML's default: YAML 1.2 core scalars
only (`true`/`false`, decimal/`0x`/`0o` integers, finite floats, no timestamps), scalar keys, no
duplicate keys, no deep nesting, no alias storms. Values such as `off` or `no` therefore stay strings —
the controller uses them as modes. Non-finite floats are refused while constructing, not by walking the
finished tree, because an alias-expanded tree can be far larger than the document (billion laughs).
"""

import math
import os
import re
import signal
import stat
import threading
import time
from collections.abc import Callable, Hashable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import Node

from unifiwifioptimizer.domain.errors import ConfigError, ConfigTimeoutError

MAX_FILE_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_NODES = 10_000
MAX_ALIASES = 50
# Longer digit strings are never a configuration value; int() itself gives up at 4300 digits.
MAX_NUMBER_CHARS = 32
PARSE_DEADLINE_S = 5.0
# YAML 1.2 core schema; PyYAML's defaults would turn `off`, `yes`, `1:30` or `1_000` into non-strings.
# PyYAML applies resolvers with `match`, so every pattern is anchored at both ends.
_BOOL_RE = re.compile(r"^(true|false)$")
_INT_RE = re.compile(r"^([-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
_FLOAT_RE = re.compile(r"^([-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?|[-+]?\.(inf|Inf|INF)|\.(nan|NaN|NAN))$")
_NULL_RE = re.compile(r"^(~|null|Null|NULL|)$")


class StrictLoader(yaml.SafeLoader):
    """`SafeLoader` with resource caps, duplicate-key rejection and the YAML 1.2 core scalar schema."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0
        self._aliases = 0

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        if self.check_event(AliasEvent):
            self._aliases += 1
            if self._aliases > MAX_ALIASES:
                raise ConfigError("$", f"more than {MAX_ALIASES} aliases")
        self._nodes += 1
        if self._nodes > MAX_NODES:
            raise ConfigError("$", f"more than {MAX_NODES} nodes")
        self._depth += 1
        try:
            if self._depth > MAX_DEPTH:
                raise ConfigError("$", f"nesting deeper than {MAX_DEPTH}")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        # An explicit `!!map` tag reaches this with any node kind.
        if not isinstance(node, yaml.MappingNode):
            raise ConfigError(_line(node), "expected a mapping")
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                raise ConfigError(f"line {key_node.start_mark.line + 1}", "a key must be a scalar")
            if key in seen:
                raise ConfigError(f"line {key_node.start_mark.line + 1}", "duplicate key")
            seen.add(key)
        return super().construct_mapping(node, deep)

    def construct_yaml_int(self, node: yaml.ScalarNode) -> int:
        # YAML 1.2 core: a leading zero is still decimal (`010` → 10); PyYAML's own constructor reads
        # YAML 1.1 octal there and crashes on `09`. An explicit `!!int` tag reaches this with any text.
        text = _number_text(self.construct_scalar(node), node)
        try:
            return int(text, 0) if text.startswith(("0x", "0o")) else int(text, 10)
        except ValueError:
            raise ConfigError(_line(node), "expected an integer") from None

    def construct_yaml_float(self, node: yaml.ScalarNode) -> float:
        text = _number_text(self.construct_scalar(node), node).lower()
        if text.endswith(("inf", "nan")):
            raise ConfigError(_line(node), "expected a finite number")
        try:
            value = float(text)
        except ValueError:
            raise ConfigError(_line(node), "expected a number") from None
        if not math.isfinite(value):
            raise ConfigError(_line(node), "expected a finite number")
        return value

    def construct_yaml_bool(self, node: yaml.ScalarNode) -> bool:
        text = self.construct_scalar(node)
        if _BOOL_RE.match(text) is None:
            raise ConfigError(_line(node), "expected true or false")
        return text == "true"


def _line(node: Node) -> str:
    return f"line {node.start_mark.line + 1}"


def _number_text(scalar: str, node: yaml.ScalarNode) -> str:
    text = scalar.replace("_", "")
    if len(text) > MAX_NUMBER_CHARS:
        raise ConfigError(_line(node), f"a number has at most {MAX_NUMBER_CHARS} characters")
    return text


# `merge` (`<<`), `value` (`=`) and `yaml` are YAML 1.1 and would turn a hand-typed password `=` into an error.
_REPLACED_TAGS = ("bool", "int", "float", "null", "timestamp", "merge", "value", "yaml")
# The YAML 1.2 core schema has no other tags; `!!binary`, `!!set`, `!!omap`, `!!pairs` and `!!timestamp`
# reach the schema as types it never expects, and their constructors crash on crafted text. The `None`
# entry is PyYAML's "undefined tag" constructor, which raises; without it an unknown tag silently falls
# back to a plain scalar.
_CORE_TAGS = frozenset(
    [None, *(f"tag:yaml.org,2002:{name}" for name in ("str", "int", "float", "bool", "null", "seq", "map"))]
)


def _install_core_schema(loader: type[yaml.SafeLoader]) -> None:
    loader.yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers if not tag.endswith(_REPLACED_TAGS)]
        for first, resolvers in loader.yaml_implicit_resolvers.items()
    }
    loader.add_implicit_resolver("tag:yaml.org,2002:bool", _BOOL_RE, list("tf"))
    loader.add_implicit_resolver("tag:yaml.org,2002:int", _INT_RE, list("-+0123456789"))
    loader.add_implicit_resolver("tag:yaml.org,2002:float", _FLOAT_RE, list("-+0123456789."))
    loader.add_implicit_resolver("tag:yaml.org,2002:null", _NULL_RE, ["~", "n", "N", ""])
    loader.yaml_constructors = {
        tag: constructor for tag, constructor in loader.yaml_constructors.items() if tag in _CORE_TAGS
    }
    loader.add_constructor("tag:yaml.org,2002:int", StrictLoader.construct_yaml_int)
    loader.add_constructor("tag:yaml.org,2002:float", StrictLoader.construct_yaml_float)
    loader.add_constructor("tag:yaml.org,2002:bool", StrictLoader.construct_yaml_bool)


_install_core_schema(StrictLoader)


@contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    # setitimer needs the main thread; elsewhere the caps on size, nodes and depth bound the work alone.
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def expire(_signum: int, _frame: object) -> None:
        raise ConfigTimeoutError("$", f"parsing exceeded {seconds:g} s")

    previous = signal.signal(signal.SIGALRM, expire)
    started = time.monotonic()
    # setitimer replaces whatever timer the caller had armed; it is given back with the elapsed time
    # deducted, and a timer that should have fired meanwhile fires right away.
    remaining, interval = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if remaining:
            signal.setitimer(signal.ITIMER_REAL, max(remaining - (time.monotonic() - started), 1e-6), interval)


def parse_yaml(text: str, source: str = "$") -> object:
    """The document as plain Python values, or `ConfigError` naming the source."""
    try:
        with _deadline(PARSE_DEADLINE_S):
            # StrictLoader derives from SafeLoader; `yaml.load` is the only way to pass a Loader subclass.
            document = yaml.load(text, Loader=StrictLoader)  # noqa: S506 # nosec B506
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{source}, line {mark.line + 1}" if mark is not None else source
        raise ConfigError(where, "invalid YAML") from None
    return document


def _check_owner(st: os.stat_result, path: str, what: str, forbidden_bits: int) -> None:
    if st.st_uid != os.getuid():
        raise ConfigError(path, f"{what} is not owned by the current user")
    if st.st_mode & forbidden_bits:
        raise ConfigError(path, f"{what} is accessible to other users (fix with chmod)")


def read_private_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """The file's text, after proving that nothing but the owner can read or replace it.

    The parent directory is opened first (no symlink, owned by us, not group/world-writable) and the file
    relative to that descriptor (no symlink, regular, owned by us, mode 0600 or stricter), so a swap
    between check and read cannot redirect the read.
    """
    directory = path.parent
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ConfigError(str(directory), f"cannot open directory ({exc.strerror})") from None
    try:
        _check_owner(os.fstat(dir_fd), str(directory), "directory", stat.S_IWGRP | stat.S_IWOTH)
        try:
            # O_NONBLOCK: opening a FIFO would otherwise wait for a writer; a regular file ignores the flag.
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
        except FileNotFoundError:
            raise ConfigError(str(path), "not found") from None
        except OSError as exc:
            raise ConfigError(str(path), f"cannot open ({exc.strerror})") from None
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(str(path), "not a regular file")
        _check_owner(st, str(path), "file", stat.S_IRWXG | stat.S_IRWXO)
        if st.st_size > max_bytes:
            raise ConfigError(str(path), f"larger than {max_bytes} bytes")
    except ConfigError:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ConfigError(str(path), f"larger than {max_bytes} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(str(path), "not UTF-8") from None


def read_text_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """A non-secret file's text: a regular file (symlinks followed — dotfile managers link such files),
    bounded in size. No ownership or mode demands — the profiles file is meant to be shared and copied."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise ConfigError(str(path), "not found") from None
    except OSError as exc:
        raise ConfigError(str(path), f"cannot open ({exc.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(str(path), "not a regular file")
        if st.st_size > max_bytes:
            raise ConfigError(str(path), f"larger than {max_bytes} bytes")
    except ConfigError:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ConfigError(str(path), f"larger than {max_bytes} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(str(path), "not UTF-8") from None


def write_new_private_file(path: Path, text: str) -> None:
    """Create `path` with mode 0600 (its directory 0700 if new); an existing file is never overwritten."""
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise ConfigError(str(path), "already exists; remove it first or edit it in place") from None
    except OSError as exc:
        raise ConfigError(str(path), f"cannot create ({exc.strerror})") from None
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


Reader = Callable[[Path], str]
