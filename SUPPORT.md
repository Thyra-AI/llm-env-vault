# Support

## Getting help

- **Run `/llm-env-vault:doctor` first.** If the tools do not appear, or the server will not start,
  it runs the common checks (a `python` on `PATH`, the virtualenv, the dependency install) and
  reports one diagnosis. The README's Troubleshooting section covers the same ground.
- **Bugs, questions and feature requests:** open an issue at
  <https://github.com/Thyra-AI/llm-env-vault/issues>. Include your OS, Python version, the plugin
  version (`claude plugin list`), and the contents of `${CLAUDE_PLUGIN_DATA}/provision.log` if the
  problem is at startup.

**Never paste a secret value, master password, or recovery key into an issue.** Variable names are
fine; values are not.

## Reporting a security issue

Please do not publish exploit details in a public issue. Open an issue at
<https://github.com/Thyra-AI/llm-env-vault/issues> titled "Security: <one-line summary>" with no
reproduction details, and the maintainer will arrange a private channel to receive them. The
README's Security notes and `docs/security-posture-2.0.0.md` describe the threat model and known
limitations, so you can tell a known limit from a new finding.

## Platform support

Windows is the tested and supported platform. macOS and Linux need a `python` (not only `python3`)
on `PATH` and are untested.
