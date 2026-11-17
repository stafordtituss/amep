# Publishing the AMEP packages

| Package | Registry | Install | Source |
|---|---|---|---|
| `amep-protocol` | PyPI | `pip install amep-protocol` | `packages/python` |
| `@stafordtituss/amep` | npm | `npm install @stafordtituss/amep` | `packages/js` |

npm refused the unscoped name `amep` as too similar to existing packages, so the npm package is scoped under the author's npm account.

Both ship the `amep-protocol` command-line tool, and both carry `LICENSE` and `NOTICE`. CI checks that those copies match the repository root.

Publish only after the repository is public and the name search is done. Once a version is on PyPI or npm it cannot be replaced, only superseded.

## One-time setup

**PyPI (no token needed: trusted publishing)**

1. Create an account at pypi.org and turn on two-factor authentication.
2. Go to *Your account → Publishing → Add a new pending publisher*, and enter: PyPI project name `amep-protocol`, owner `stafordtituss`, repository `amep`, workflow `release.yml`, environment `pypi`.
3. In the GitHub repository, create an environment named `pypi` (*Settings → Environments*). Optionally require your approval for each deployment.

**npm**

1. Create an account at npmjs.com and turn on two-factor authentication.
2. Create a *granular access token* with read and write access to packages, with **"Bypass two-factor authentication"** enabled. Without that, npm refuses automated publishes from accounts with 2FA on.
3. Store it in the GitHub repository as the secret `NPM_TOKEN` (*Settings → Secrets and variables → Actions*).
4. npm provenance (`--provenance`) needs the repository to be public.

## Releasing

1. Bump the version in `packages/python/pyproject.toml`, `packages/python/src/amep_protocol/__init__.py`, `packages/js/package.json` and `packages/js/src/index.mjs`. Python uses PEP 440 (`0.2.0a5`), npm uses SemVer (`0.2.0-alpha.5`).
2. Make sure CI is green on `main`.
3. Tag and push: `git tag v0.2.0a5 && git push --tags`.
4. The `release` workflow builds both packages, publishes to PyPI by trusted publishing, and to npm with provenance.

To rehearse the Python release without publishing for real, point a copy of the workflow at TestPyPI (`repository-url: https://test.pypi.org/legacy/`) and add a matching trusted publisher on test.pypi.org.
