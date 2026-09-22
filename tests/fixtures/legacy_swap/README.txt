Legacy swap fixtures -- captured from the real v1.7.1 writers.
==============================================================

WHY THIS EXISTS
---------------
`run_with_env(swap=)` is retired in 2.0.0. The RECOVERY half is kept (see
vault_lib/legacy_swap.py) because a user can upgrade to 2.0 while a .env on
their disk still holds real values -- either a 1.6-1.7 server crashed
mid-swap, or one is still running a command right now in another session.

The recovery tests used to build that state by CALLING the swap writers
(`store.swap_target_file`, `store.journal_add`). Those writers are deleted
in 2.0, so any test that sets up through them dies with them -- and the
recovery path would silently lose its coverage exactly when it matters
most.

These files are that state, frozen. They were produced by running the real
1.7.1 writers once (never hand-transcribed), so the on-disk format is
pinned as it actually shipped -- including details a hand-written fixture
would miss, such as the journal's top-level `"version": 1` and the
quoting/escaping `render_swap_value` applied per line.

DO NOT REGENERATE these from a 2.0 checkout. The writers are gone; that is
the whole point. Treat them as immutable golden bytes.

CONTENTS
--------
placeholder.env
    The registered target in its normal, placeholder-only state. Carries a
    comment line, CRLF terminators, an `export ` prefix, a leading-indent
    line with trailing spaces, and an unmanaged line -- byte-exactness
    across those is what the restore has to preserve.

swapped.env
    The same file mid-swap, with real values written in. This is what a
    crashed 1.7.x server leaves behind. Restoring it must reproduce
    placeholder.env byte for byte.

journal_active.json
    swap.journal.json as written by `journal_add` -- state "active".

journal_restore_failed.json
    The same journal after `journal_mark_restore_failed` -- state
    "restore_failed", which recovery must act on regardless of whether the
    owning pid is still alive.

    In both journals the entry's path key is the token `__ENV_PATH__`;
    tests substitute their own temp path. `pid` / `pid_start` / `server_id`
    are the real captured values and are overridden per scenario -- see
    tests/test_legacy_swap_recovery.py.

THE VALUES IN swapped.env ARE NOT SECRETS
-----------------------------------------
They are the test constants from the 1.7.1 swap suite:

    API_TOKEN    tok-abcdefgh-123456
    DB_PASSWORD  p$ss w#rd 'quoted' "dq"     (chosen to exercise quoting)
    PLAIN        justletters123

with vault_index.json {API_TOKEN: 1, DB_PASSWORD: 2, PLAIN: 3}.
