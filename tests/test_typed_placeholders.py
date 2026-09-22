"""
Typed ("shape-preserving") placeholders -- the 2.0 replacement for swap=.

`SMTP_PORT="value 17"` is not an int and `SMTP_USE_SSL="value 38"` is not a
bool, so a placeholder-only .env fails to LOAD in pydantic-settings with the
vault not involved in the run at all. That is mechanism F in
docs/env-consumption-research.md, and the reason a protected project could
not run a test suite that reads .env from a scrubbed child environment.

A typed placeholder preserves the shape and nothing else: `0` for an int,
`false` for a bool, `https://placeholder-17.invalid` for a URL. It discloses
the type -- and a URL's scheme -- never content.

The dangerous part is not the rendering, it is the DETECTION. Seven places
ask "is this line still one of ours?", and each means something different by
it. Two of them (install_migrate's guard and the dialog's) decide whether a
value gets vaulted as a real secret: miss there and the literal string
`false` is stored as SMTP_USE_SSL's password. A third is resync's data-loss
guard, which counts how many managed lines still hold a placeholder -- if
typed ones stop counting, the guard silently stops firing. Those three are
the point of this file.

Runs under pytest or standalone.
"""
import contextlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server  # noqa: E402
import vault_lib.crypto as crypto  # noqa: E402
from vault_lib import gui, store  # noqa: E402
from _vault_workspace import _isolate, _reset_trust, TEST_PASSWORD, _FAST_PARAMS  # noqa: E402

# A settings file of the shape that actually broke: typed fields a loader
# validates at import time.
TYPED_SECRETS = {
    "SMTP_PORT": "2525",
    "SMTP_USE_SSL": "true",
    "DATABASE_URL": "postgres://user:pw@db.internal:5432/app",
    "ADMIN_EMAIL": "ops@example.com",
    "API_TOKEN": "tok-abcdefgh-123456",
}
TYPED_INDEX = {"SMTP_PORT": 1, "SMTP_USE_SSL": 2, "DATABASE_URL": 3,
               "ADMIN_EMAIL": 4, "API_TOKEN": 5}


@contextlib.contextmanager
def typed_workspace(env_text=None, register=True, record=True):
    """A vault whose variables have recorded shapes, and a project .env
    already written with the typed placeholders those shapes render."""
    with tempfile.TemporaryDirectory(prefix="llm_typed_") as tmp:
        tmp_path = Path(tmp).resolve()
        originals = _isolate(tmp_path)
        old_params = crypto.SCRYPT_DEFAULT
        crypto.SCRYPT_DEFAULT = _FAST_PARAMS
        _reset_trust()
        project = tmp_path / "project"
        project.mkdir()
        env_path = project / ".env"
        try:
            store.create_v2_vault(TEST_PASSWORD)
            store.save_secrets(TEST_PASSWORD, dict(TYPED_SECRETS))
            store.save_index(dict(TYPED_INDEX))
            shapes = {n: store.infer_shape(v) for n, v in TYPED_SECRETS.items()}
            if record:
                store.record_shapes(shapes)
            if env_text is None:
                env_text = "".join(
                    f"{n}={store.render_placeholder(TYPED_INDEX[n], shapes[n])}\n"
                    for n in sorted(TYPED_SECRETS))
            env_path.write_text(env_text, encoding="utf-8")
            if register:
                store.add_target(str(env_path), sorted(TYPED_SECRETS))
            yield project, env_path, shapes
        finally:
            _reset_trust()
            crypto.SCRYPT_DEFAULT = old_params
            for name, value in originals.items():
                setattr(store, name, value)


@contextlib.contextmanager
def stub_install_dialog(approve=False):
    original = gui.install_dialog
    seen = {}

    def fake(target, to_migrate, other_owner, also_register=None, sensitive_names=None):
        seen["to_migrate"] = list(to_migrate)
        return {"approved": approve, "partial_failure": None}

    gui.install_dialog = fake
    try:
        yield seen
    finally:
        gui.install_dialog = original


# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

def test_shapes_preserve_type_and_nothing_else() -> None:
    cases = {
        "5432": ("int", "17"),
        "0": ("bit", "0"),
        "1": ("bit", "0"),                       # never the real bit
        "true": ("bool", "false"),               # never the real truthiness
        "FALSE": ("bool", "false"),
        "3.14": ("float", "17.0"),
        "ops@example.com": ("email", "placeholder-17@example.invalid"),
        "postgres://u:p@h/db": ("url:postgres", "postgres://placeholder-17.invalid"),
        "https://api.example.com": ("url:https", "https://placeholder-17.invalid"),
        '[1,2]': ("json:list", "[]"),
        '{"a":1}': ("json:object", "{}"),
        "hunter2": ("str", '"value 17"'),
        "": ("str", '"value 17"'),
    }
    for real, (shape, rendered) in cases.items():
        assert store.infer_shape(real) == shape, real
        assert store.render_placeholder(17, shape) == rendered, real


def test_a_placeholder_never_carries_content() -> None:
    """The one property that makes this safe to ship: whatever the real
    value is, the rendered placeholder depends only on its shape and its
    index number."""
    for a, b in (("1", "0"), ("true", "off"), ("9999", "12"),
                 ("https://a.example.com/secret", "https://b.example.com/other"),
                 ("alice@corp.com", "bob@other.org")):
        assert store.infer_shape(a) == store.infer_shape(b), (a, b)
        sa = store.render_placeholder(7, store.infer_shape(a))
        sb = store.render_placeholder(7, store.infer_shape(b))
        assert sa == sb, (a, b, sa, sb)


def test_unknown_shapes_are_refused_and_fall_back_to_the_legacy_form() -> None:
    """placeholder_shapes.json is agent-writable, and everything a shape
    renders lands on a line in the user's .env."""
    for bad in ("nope", "url:", "url:HTTP", "json:blob", "", None, 7, "str; rm -rf /"):
        assert store.validate_shape(bad) is False, bad
        assert store.render_placeholder(3, bad) == '"value 3"', bad
    for n in (0, -1, True, "4", None):
        try:
            store.render_placeholder(n, "int")
        except ValueError:
            continue
        raise AssertionError(f"accepted a bad placeholder number: {n!r}")


def test_rendered_placeholders_can_never_break_the_line() -> None:
    for real in TYPED_SECRETS.values():
        rendered = store.render_placeholder(9, store.infer_shape(real))
        assert "\n" not in rendered and "\r" not in rendered
        assert store.ENV_LINE_RE.match(f"X={rendered}"), rendered


# ---------------------------------------------------------------------------
# Detection: exact, not pattern-based
# ---------------------------------------------------------------------------

def test_detection_is_exact_so_a_real_value_of_the_same_shape_is_not_a_placeholder() -> None:
    """The whole reason PLACEHOLDER_VALUE_RE is NOT widened: a pattern loose
    enough to match `17` would match a real port too."""
    index, shapes = {"SMTP_PORT": 17}, {"SMTP_PORT": "int"}
    assert store.is_placeholder("SMTP_PORT", "17", index, shapes) is True
    assert store.is_placeholder("SMTP_PORT", '"17"', index, shapes) is True
    for real in ("5432", "18", "0", "-17", "17.0", "hunter2"):
        assert store.is_placeholder("SMTP_PORT", real, index, shapes) is False, real


def test_an_untyped_vault_behaves_exactly_as_before() -> None:
    index, shapes = {"A": 3}, {}
    assert store.is_placeholder("A", '"value 3"', index, shapes) is True
    assert store.is_placeholder("A", "value 3", index, shapes) is True
    assert store.is_placeholder("A", '"value ?"', index, shapes) is True
    assert store.is_placeholder("A", "3", index, shapes) is False


def test_shape_tombstone_survives_removal_from_the_index() -> None:
    """A typed placeholder for a name that has left the vault must still be
    recognisable, or resync's data-loss guard stops counting it. Only the
    self-describing shapes can be: a bare `17` is deliberately read as a
    real value."""
    shapes = {"GONE_URL": "url:https", "GONE_MAIL": "email", "GONE_PORT": "int"}
    assert store.is_placeholder("GONE_URL", "https://placeholder-4.invalid", {}, shapes)
    assert store.is_placeholder("GONE_MAIL", "placeholder-4@example.invalid", {}, shapes)
    assert store.is_placeholder("GONE_PORT", "4", {}, shapes) is False


def test_shapes_file_is_validated_on_read_and_never_pruned() -> None:
    with typed_workspace() as (_project, _env_path, shapes):
        assert store.load_shapes() == shapes
        store.record_shapes({"LATER": "int"})
        assert store.load_shapes()["LATER"] == "int"
        assert store.load_shapes()["SMTP_PORT"] == "int"     # merge, not replace
        store._shapes_path().write_text(json.dumps({
            "GOOD": "bool", "bad name": "int", "EVIL": "url:", "X": 7}), encoding="utf-8")
        assert store.load_shapes() == {"GOOD": "bool"}
        store._shapes_path().write_text("{not json", encoding="utf-8")
        assert store.load_shapes() == {}                      # costs fidelity, not a run


# ---------------------------------------------------------------------------
# The three guards that must not break
# ---------------------------------------------------------------------------

def test_migrate_never_vaults_a_typed_placeholder_as_its_own_value() -> None:
    """The sharpest failure this could cause: storing the literal string
    `false` as SMTP_USE_SSL's real secret, and `17` as SMTP_PORT's."""
    with typed_workspace() as (_project, env_path, _shapes):
        with stub_install_dialog(approve=False) as seen:
            result = mcp_server._install_migrate_impl(str(env_path))
        offered = dict(seen.get("to_migrate", []))
        for name in TYPED_SECRETS:
            assert name not in offered, f"{name}'s placeholder would be vaulted as its value"
        assert result.get("applied") is False


def test_migrate_still_sees_a_real_value_sitting_on_a_typed_line() -> None:
    """The converse: the guard must not swallow a genuine secret that
    happens to live on a managed line."""
    with typed_workspace() as (_project, env_path, shapes):
        text = env_path.read_text(encoding="utf-8").replace(
            f"SMTP_PORT={store.render_placeholder(1, shapes['SMTP_PORT'])}",
            "SMTP_PORT=5432")
        env_path.write_text(text, encoding="utf-8")
        with stub_install_dialog(approve=False) as seen:
            mcp_server._install_migrate_impl(str(env_path))
        offered = dict(seen.get("to_migrate", []))
        assert offered.get("SMTP_PORT") == "5432", offered
        assert "SMTP_USE_SSL" not in offered


def test_resync_data_loss_guard_still_fires_on_a_typed_vault() -> None:
    """Counts managed lines that still hold OUR placeholder. If typed ones
    stopped counting, a vault/index replacement could wipe a file's managed
    lines with no refusal at all."""
    with typed_workspace() as (_project, env_path, _shapes):
        shrunk = {"API_TOKEN": 5}          # four of five names "removed"
        try:
            store.sync_target_file(env_path, shrunk, sorted(TYPED_SECRETS))
        except ValueError as e:
            assert "Refusing to resync" in str(e), e
        else:
            raise AssertionError("the data-loss guard did not fire on a typed vault")


def test_resync_rewrites_a_drifted_typed_line_and_leaves_a_real_value_alone() -> None:
    with typed_workspace() as (_project, env_path, shapes):
        text = env_path.read_text(encoding="utf-8")
        # Misnumbered but self-describing -> unambiguously ours, renumbered.
        text = text.replace("DATABASE_URL=postgres://placeholder-3.invalid",
                            "DATABASE_URL=postgres://placeholder-99.invalid")
        # A genuine secret on a managed line -> must be reported, not clobbered.
        text = text.replace(f"ADMIN_EMAIL={store.render_placeholder(4, shapes['ADMIN_EMAIL'])}",
                            "ADMIN_EMAIL=real.person@corp.com")
        env_path.write_text(text, encoding="utf-8")
        conflicts = store.sync_target_file(env_path, dict(TYPED_INDEX), sorted(TYPED_SECRETS))
        after = env_path.read_text(encoding="utf-8")
        assert "SMTP_PORT=1\n" in after, after
        assert "ADMIN_EMAIL=real.person@corp.com" in after
        assert "ADMIN_EMAIL" in conflicts


def test_resync_is_idempotent_and_the_header_is_written_once() -> None:
    """The first resync of a typed file adds the header; every later one
    must be a byte-for-byte no-op, or a file in git churns on every call."""
    with typed_workspace() as (_project, env_path, _shapes):
        store.sync_target_file(env_path, dict(TYPED_INDEX), sorted(TYPED_SECRETS))
        first = env_path.read_bytes()
        assert first.startswith(store.MANAGED_HEADER.encode("utf-8"))
        for _ in range(3):
            store.sync_target_file(env_path, dict(TYPED_INDEX), sorted(TYPED_SECRETS))
        assert env_path.read_bytes() == first
        assert first.count(store.MANAGED_HEADER_PREFIX.encode("utf-8")) == 1


def test_an_opaque_vault_gets_no_header_so_upgrading_touches_nothing() -> None:
    with typed_workspace(record=False) as (_project, env_path, _shapes):
        store.set_placeholder_style(store.STYLE_OPAQUE)
        env_path.write_bytes(b'A="value 1"\n')
        store.add_target(str(env_path), ["A"])
        store.sync_target_file(env_path, {"A": 1}, ["A"])
        assert env_path.read_bytes() == b'A="value 1"\n'


def test_a_missing_managed_line_is_appended_in_the_right_form() -> None:
    """The eighth rendering site: a managed name with no line at all gets
    one appended. It went through a hardcoded "value N" until 2.0, which on
    a typed vault would have written a line its own loader cannot parse."""
    with typed_workspace() as (_project, env_path, _shapes):
        text = "".join(line + "\n" for line in env_path.read_text(encoding="utf-8").splitlines()
                       if not line.startswith("SMTP_PORT="))
        env_path.write_text(text, encoding="utf-8")
        store.sync_target_file(env_path, dict(TYPED_INDEX), sorted(TYPED_SECRETS))
        after = env_path.read_text(encoding="utf-8")
        assert "SMTP_PORT=1\n" in after, after
        assert '"value 1"' not in after


# ---------------------------------------------------------------------------
# Reporting and recovery agree with the new grammar
# ---------------------------------------------------------------------------

def test_vault_status_reports_a_real_value_on_a_typed_line() -> None:
    with typed_workspace() as (_project, env_path, shapes):
        text = env_path.read_text(encoding="utf-8").replace(
            f"DATABASE_URL={store.render_placeholder(3, shapes['DATABASE_URL'])}",
            "DATABASE_URL=postgres://real:secret@db/app")
        env_path.write_text(text, encoding="utf-8")
        status = mcp_server._vault_status_impl()
        assert status["targets_holding_non_placeholders"] == {str(env_path): ["DATABASE_URL"]}
        assert "secret" not in json.dumps(status)


def test_legacy_recovery_writes_typed_placeholders_not_the_old_form() -> None:
    """A pre-2.0 journal recovered into a vault that has since been retyped
    must put back the line the file's consumers can parse."""
    from vault_lib import legacy_swap
    with typed_workspace() as (_project, env_path, shapes):
        env_path.write_text(
            "SMTP_PORT=2525\nSMTP_USE_SSL=true\nADMIN_EMAIL=ops@example.com\n",
            encoding="utf-8")
        report = legacy_swap.recover_swap_file(
            env_path, ["SMTP_PORT", "SMTP_USE_SSL", "ADMIN_EMAIL"], dict(TYPED_INDEX),
            started=0)
        after = env_path.read_text(encoding="utf-8")
        assert report["restored"] == ["ADMIN_EMAIL", "SMTP_PORT", "SMTP_USE_SSL"]
        assert "SMTP_PORT=1\n" in after and "SMTP_USE_SSL=false\n" in after
        assert "placeholder-4@example.invalid" in after
        assert "2525" not in after and "ops@example.com" not in after


# ---------------------------------------------------------------------------
# Numbering: a freed number is never handed out again
# ---------------------------------------------------------------------------

def test_a_freed_placeholder_number_is_never_reused() -> None:
    """The only way a placeholder already written into a project file can
    come to mean a DIFFERENT variable. For a typed placeholder that drift is
    unrecoverable -- `SMTP_PORT=17` where 17 is now someone else's number
    cannot be told from a real port -- so the number is retired instead."""
    with typed_workspace() as (_project, _env_path, _shapes):
        index = dict(TYPED_INDEX)
        store.save_index(index)
        assert store.next_placeholder(index) == 6
        del index["SMTP_USE_SSL"]          # number 2 is now free
        store.save_index(index)
        assert store.next_placeholder(index) == 6, "a freed number came back"
        index["BRAND_NEW"] = store.next_placeholder(index)
        store.save_index(index)
        assert index["BRAND_NEW"] == 6
        assert store.next_placeholder(index) == 7


def test_the_high_water_mark_survives_emptying_the_vault() -> None:
    with typed_workspace() as (_project, _env_path, _shapes):
        store.save_index(dict(TYPED_INDEX))
        store.save_index({})
        assert store.next_placeholder({}) == 6, "numbering restarted from 1"


def test_a_cancelled_dialog_burns_no_number() -> None:
    """next_placeholder is a question, not a reservation: only save_index
    moves the mark, so a human who cancels leaves no gap behind."""
    with typed_workspace() as (_project, _env_path, _shapes):
        store.save_index(dict(TYPED_INDEX))
        for _ in range(5):
            assert store.next_placeholder(dict(TYPED_INDEX)) == 6


# ---------------------------------------------------------------------------
# Style: an upgrade must not rewrite anybody's .env
# ---------------------------------------------------------------------------

def test_a_new_vault_is_typed_and_records_shapes_as_secrets_are_saved() -> None:
    with typed_workspace(record=False) as (_project, _env_path, _shapes):
        assert store.placeholder_style() == store.STYLE_TYPED
        # typed_workspace's save_secrets already recorded them.
        assert store.load_shapes()["SMTP_PORT"] == "int"
        store.save_secrets(TEST_PASSWORD, dict(TYPED_SECRETS, NEW_FLAG="true"))
        assert store.load_shapes()["NEW_FLAG"] == "bool"


def test_an_opaque_vault_records_nothing_when_secrets_are_saved() -> None:
    """The zero-touch promise: a vault that predates typed placeholders sees
    no change at all until a human asks for one."""
    with typed_workspace(record=False) as (_project, _env_path, _shapes):
        store.set_placeholder_style(store.STYLE_OPAQUE)
        store._save_shape_doc({"shapes": {}, "high_water": 9, "style": store.STYLE_OPAQUE})
        store.save_secrets(TEST_PASSWORD, dict(TYPED_SECRETS))
        assert store.load_shapes() == {}
        assert store.placeholder_for("SMTP_PORT", TYPED_INDEX) == '"value 1"'


def test_the_shape_doc_reads_the_earlier_bare_map_format() -> None:
    """A vault written by the first 2.0 build has a plain {name: shape}
    file with no wrapper. It must still load."""
    with typed_workspace() as (_project, _env_path, _shapes):
        store._shapes_path().write_text(json.dumps({"SMTP_PORT": "int"}), encoding="utf-8")
        assert store.load_shapes() == {"SMTP_PORT": "int"}
        assert store.placeholder_style() == store.STYLE_OPAQUE   # absent -> opaque
        assert store.next_placeholder({}) == 1                   # absent -> 0


# ---------------------------------------------------------------------------
# retype_placeholders
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def stub_retype_dialog(approve=True):
    """Runs the real recording and rewriting the dialog would do, without a
    window -- so the tool's contract is tested, not a mock of it."""
    original = gui.retype_placeholders_dialog
    seen = {}

    def fake(names):
        seen["names"] = list(names)
        if not approve:
            return {"approved": False, "retyped": {}, "conflicts": {}, "partial_failure": None}
        secrets = store.load_secrets(TEST_PASSWORD)
        plan = {n: store.infer_shape(secrets[n]) for n in names if n in secrets}
        store.record_shapes(plan)
        store.set_placeholder_style(store.STYLE_TYPED)
        conflicts = {}
        index_now, shapes_now = store.load_index(), store.load_shapes()
        for path_str, names_for_path in store.load_targets().items():
            got = store.sync_target_file(Path(path_str), index_now, names_for_path,
                                         shapes=shapes_now)
            if got:
                conflicts[path_str] = got
        return {"approved": True, "retyped": plan, "conflicts": conflicts,
                "partial_failure": None}

    gui.retype_placeholders_dialog = fake
    try:
        yield seen
    finally:
        gui.retype_placeholders_dialog = original


def test_retype_turns_an_opaque_vault_into_a_parseable_one() -> None:
    """The whole point, end to end: before, the file cannot be loaded by a
    typed settings library; after, it can, and still holds no real value."""
    with typed_workspace(record=False) as (_project, env_path, _shapes):
        store._save_shape_doc({"shapes": {}, "high_water": 5, "style": store.STYLE_OPAQUE})
        env_path.write_bytes(b"".join(
            f'{n}="value {TYPED_INDEX[n]}"\n'.encode("utf-8") for n in sorted(TYPED_SECRETS)))
        with stub_retype_dialog():
            result = mcp_server._retype_placeholders_impl()
        assert result["applied"] is True
        assert result["retyped"]["SMTP_PORT"] == "int"
        assert result["placeholder_style"] == store.STYLE_TYPED
        after = env_path.read_text(encoding="utf-8")
        assert "SMTP_PORT=1\n" in after and "SMTP_USE_SSL=false\n" in after
        assert "postgres://placeholder-3.invalid" in after
        assert "placeholder-4@example.invalid" in after
        # API_TOKEN is an opaque string: there is no shape to preserve, so it
        # keeps the legacy form. Retyping is not "everything changes".
        assert store.load_shapes()["API_TOKEN"] == store.SHAPE_STR
        assert 'API_TOKEN="value 5"' in after
        assert "API_TOKEN" not in result["retyped"]
        assert result["left_opaque"] == ["API_TOKEN"]
        for real in TYPED_SECRETS.values():
            assert real not in after


def test_retype_can_be_scoped_and_rejects_unknown_names() -> None:
    with typed_workspace(record=False) as (_project, _env_path, _shapes):
        store._save_shape_doc({"shapes": {}, "high_water": 5, "style": store.STYLE_OPAQUE})
        bad = mcp_server._retype_placeholders_impl(["NOPE"])
        assert "not in this vault" in bad["error"]
        with stub_retype_dialog() as seen:
            result = mcp_server._retype_placeholders_impl(["SMTP_PORT"])
        assert seen["names"] == ["SMTP_PORT"]
        assert set(result["retyped"]) == {"SMTP_PORT"}
        assert "SMTP_USE_SSL" not in store.load_shapes()


def test_retype_denied_changes_nothing() -> None:
    with typed_workspace(record=False) as (_project, env_path, _shapes):
        store._save_shape_doc({"shapes": {}, "high_water": 5, "style": store.STYLE_OPAQUE})
        before = env_path.read_bytes()
        with stub_retype_dialog(approve=False):
            result = mcp_server._retype_placeholders_impl()
        assert result["applied"] is False and result["message"] == "Denied by user."
        assert env_path.read_bytes() == before
        assert store.load_shapes() == {}
        assert store.placeholder_style() == store.STYLE_OPAQUE


def test_retype_reports_a_hand_edited_line_instead_of_overwriting_it() -> None:
    with typed_workspace(record=False) as (_project, env_path, _shapes):
        store._save_shape_doc({"shapes": {}, "high_water": 5, "style": store.STYLE_OPAQUE})
        text = "".join(f'{n}="value {TYPED_INDEX[n]}"\n' for n in sorted(TYPED_SECRETS))
        text = text.replace('ADMIN_EMAIL="value 4"', "ADMIN_EMAIL=real.person@corp.com")
        env_path.write_text(text, encoding="utf-8")
        with stub_retype_dialog():
            result = mcp_server._retype_placeholders_impl()
        assert result["applied"] is True
        assert "ADMIN_EMAIL" in result["conflicts"][str(env_path)]
        assert "real.person@corp.com" in env_path.read_text(encoding="utf-8")


def test_vault_status_surfaces_an_untyped_vault() -> None:
    with typed_workspace(record=False) as (_project, _env_path, _shapes):
        store._save_shape_doc({"shapes": {}, "high_water": 5, "style": store.STYLE_OPAQUE})
        status = mcp_server._vault_status_impl()
        assert status["placeholder_style"] == store.STYLE_OPAQUE
        assert set(status["untyped_vars"]) == set(TYPED_SECRETS)
        assert "retype_placeholders" in status["untyped_note"]
        with stub_retype_dialog():
            mcp_server._retype_placeholders_impl()
        status = mcp_server._vault_status_impl()
        assert status["placeholder_style"] == store.STYLE_TYPED
        assert "untyped_vars" not in status


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
