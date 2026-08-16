# Third-party code

## liblk

- **Upstream:** https://github.com/R0rt1z2/liblk
- **License:** GPL-3.0 (see `vendor/liblk/LICENSE`)
- **Vendored commit:** `75c8f14f16457b6c53d950d18d1ed7d2a665bed6`
  ("Add support for certs", liblk 3.2.0, 2026-06-30)
- **Vendored at:** 2026-08-16

### Why vendored

`liblk` is not published on PyPI and is installed from git only. Pinning a
git `rev` makes the build depend on GitHub availability — the repo can be
deleted, rate-limited, or force-pushed. Since liblk is only ~2.2k lines of
pure Python and its license (GPL-3.0) is compatible with this project's
AGPL-3.0, the sources are vendored under `vendor/liblk/` for fully offline,
reproducible builds (including PyInstaller binary builds on CI).

### Updating

1. Clone upstream and checkout the desired commit.
2. Replace the contents of `vendor/liblk/` (keep `LICENSE`).
3. Update the commit hash and date above.
4. Run `uv lock --refresh` and re-run the test suite.