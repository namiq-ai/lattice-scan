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
