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

## The MCP server (`amep-mcp`)

`packages/mcp` is released separately, with tags `mcp-v*`, because it changes on its own schedule. It is listed in the official MCP Registry as `io.github.stafordtituss/amep-verifier`; the registry stores only metadata and points to the PyPI package.

**Before each release**

1. Rebuild the bundled suites if the vectors changed: `python3 -I packages/mcp/build_suite.py` (`--check` verifies the bundle is current).
2. Bump the version in `packages/mcp/pyproject.toml`, `packages/mcp/src/amep_mcp/__init__.py`, and both `version` fields in `packages/mcp/server.json`.
3. Run the tests: `PYTHONPATH=packages/python/src:packages/mcp/src python -m unittest discover -s packages/mcp/tests`.

**One-time setup: PyPI trusted publisher.** Add a pending publisher for project `amep-mcp`: owner `stafordtituss`, repository `amep`, workflow `release-mcp.yml`, environment `pypi`. Then add `.github/workflows/release-mcp.yml`:

```yaml
name: release-mcp
on:
  push:
    tags: ["mcp-v*"]
permissions:
  contents: read
jobs:
  pypi:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: |
          python -m pip install --quiet build
          python -I packages/mcp/build_suite.py --check
          python -m build packages/mcp --outdir dist
      - uses: pypa/gh-action-pypi-publish@release/v1
```

**Release:** `git tag mcp-v0.1.0a1 && git push --tags`, then wait for the package to appear on PyPI.

**Then list it in the MCP Registry** (the PyPI README carries the `mcp-name: io.github.stafordtituss/amep-verifier` marker the registry checks for ownership):

```
brew install mcp-publisher
cd packages/mcp
mcp-publisher login github
mcp-publisher publish
```

Check it with `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.stafordtituss/amep-verifier"`.
