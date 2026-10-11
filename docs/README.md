# Documentation

The user-facing documentation is the root [README](../README.md); this folder holds the background material.

| Folder | What it is |
|---|---|
| [`security/`](security/) | [`security-posture-2.0.0.md`](security/security-posture-2.0.0.md): the current threat model, the invariant and its two remaining exceptions. |
| [`security/archive/`](security/archive/) | Superseded by 2.0.0 and kept as the record of why (`run_with_env(swap=)` was retired): the 1.6.0 posture and the 1.6.1 hardening plan. |
| [`research/`](research/) | [`env-consumption-research.md`](research/env-consumption-research.md): how programs read `.env` values, and which paths the vault covers (its executable half is `tests/test_consumption_matrix.py`). [`study-distribution-and-footprint.md`](research/study-distribution-and-footprint.md): a study (in Portuguese) of installing in any AI editor and keeping the footprint small. |

Release history is in [`CHANGELOG.md`](../CHANGELOG.md). Privacy is in [`PRIVACY.md`](../PRIVACY.md) and support in
[`SUPPORT.md`](../SUPPORT.md).
