# Releasing

Release notes are part of every release. A tag without them does not build.

1. Bump `__version__`, move the CHANGELOG "Unreleased" entries under the new version, and rebuild `skills/lattice-scan/scripts/lattice-scan.pyz` (`python3 packaging/build.py`).
2. Write `release-notes/vX.Y.Z.md`: what is new, who can use it and how, what changed, what is known not to work, how to install and verify. Say what is not in the release as plainly as what is.
3. Merge through a reviewed pull request, then tag `vX.Y.Z` on the merge commit.
4. The release workflow refuses a tag with no `release-notes/vX.Y.Z.md`, and uses that file as the body of the draft release.
5. Check the notes and `SHA256SUMS` in the draft, then publish it. Approve the `pypi` environment to upload to PyPI.
6. After publishing, read the release page once. If the body is not the notes file, fix it with `gh release edit vX.Y.Z --notes-file release-notes/vX.Y.Z.md`.

## Releasing from GitHub (no local tagging)

After step 3's pull request is merged to `main` (version bumped, CHANGELOG section `## X.Y.Z` present, `release-notes/vX.Y.Z.md` written):

1. GitHub > Actions > **release** > Run workflow, branch `main`, enter the version (`0.2.2`, no `v`).
2. The workflow refuses unless `main` carries that version, the CHANGELOG has the section and the tag does not exist. It then tags `vX.Y.Z` on the head of `main`, runs the tests, builds, and makes a **draft** release. The body is `release-notes/vX.Y.Z.md`; if that file is missing, it is made from the CHANGELOG section and says so, so edit it before publishing.
3. Publish the draft, and approve the `pypi` environment to upload to PyPI (steps 5 and 6 above are unchanged).

Pushing a `v*` tag by hand still works and still refuses a tag with no notes file.

## The Claude Code plugin

The skill is released with the tool. Bump `.claude-plugin/plugin.json` together with `__version__` (step 1) and rebuild the bundled script; the release refuses a tag where they differ, or where a module in
`skills/lattice-scan/scripts/lattice-scan.pyz` is stale. Every release attaches `dist/lattice-scan-claude-plugin-X.Y.Z.zip` (`packaging/build_claude_plugin.py`, hash in `SHA256SUMS`). People install through the marketplace
in this repository (`source: "./"`), which reads the tagged files, so nothing else publishes it. After publishing the release, move the pin in `namiq-web/.claude-plugin/marketplace.json` to the release commit (a pull request there).

## The OpenAI plugin package

Every release also builds `dist/lattice-scan-openai-plugin-X.Y.Z.zip` (`packaging/build_openai_plugin.py`) and attaches it. The workflow then runs `packaging/check_openai_plugin.py` on it and fails the release on an ERROR. That check is written from OpenAI's published rules (submission guide, plugin guidelines, the plugin-creator spec and the portable schema); it is not OpenAI's own validator, which runs only inside their portal and Codex tooling. A WARN for the bundled `.pyz` is expected: OpenAI's rules do not say whether bundled scripts are allowed. Submitting it is a person's step: platform.openai.com/plugins > Upload new or existing plugin,
as the verified developer identity, then Submit for review (a skills-only plugin needs no MCP review cases or demo video). After approval, choose when to publish. Upload the ZIP from the release, not a local build.

## The apt repository (not part of the release workflow)

The signed apt repository at namiq.io/apt does not update itself: the workflow attaches the `.deb` to the release, and nothing else publishes it. Until it is published, `apt upgrade` stays on the old version
and `man lattice-scan` shows the old manual (a pip or uv install has no manual page). After every release:

1. Collect the `.deb` of the release and of every earlier version you still want served into one folder, and check each against its release `SHA256SUMS`:
   `gh release download vX.Y.Z -p 'lattice-scan_X.Y.Z_all.deb' -p SHA256SUMS`.
2. Build and sign, on the machine that holds the signing key (it asks for the passphrase, and the private key never leaves that machine):
   `python3 packaging/build_apt_repo.py --key C473615441158A3E775C2EC27E6115F40A41061D --dist FOLDER --out repo/` (the fingerprint, without spaces, is also published at namiq.io/lattice/docs).
3. Copy `repo/` over `namiq-web/public/apt/` in a pull request there, check `gpg --verify public/apt/dists/stable/InRelease`, merge, then deploy namiq-web (`npm run build`, restart the service).
4. Check from a clean machine or container: `apt update && apt policy lattice-scan` shows the new version, and `man lattice-scan` is the new manual.
