# Synthetic fixture area

Only synthetic, deliberately authored datasets belong here. Use example domains and reserved documentation addresses; never copy production access logs or credentials. Runtime `.log` files are ignored; use a clearly named `.txt` fixture or an explicitly reviewed exception if a future test requires another extension.

The reference line and expected normalization are in `docs/log-formats.md`. Create independent expected datasets under `expected/` when implementing parser/analytics tests. `combined/` is reserved for Nginx/Apache variants; `adversarial/` for malformed/oversized/injection inputs. Directory placeholders are not test coverage.

Follow `tests/AGENTS.md` before adding fixtures and keep benchmark generators separate from committed large datasets.
