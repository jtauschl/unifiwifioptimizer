# Controller fixtures

Anonymized projections of a UniFi Network Application 10.6.106 site (UDM-SE, 2× U6 Lite, 2× U7 Lite,
country 276), produced by `tests/tools/anonymize_fixtures.py` from live dumps that are never committed.

Only keys the anonymizer's specs name survive; every identifier is synthetic (`02:00:00:00:xx:yy` MACs,
`192.0.2.x` addresses, zero-prefixed object ids, `SSID-n`, `AP-n`, `Group-n`, `site-n`), every other text
matches a closed vocabulary or format rule of its key, and the only credential present is the fixture SSH
user/password pair under `rest_setting.json` → `mgmt`. `sites.json` is
hand-written because `self/sites` had no live dump. `tests/unit/test_fixture_anonymity.py` enforces the
contract on every file in this directory.

Regenerate with:

```sh
uv run python -m tests.tools.anonymize_fixtures --source <dir with live_*.json> --dest tests/fixtures
```
