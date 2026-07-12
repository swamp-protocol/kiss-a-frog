# Releasing kiss-a-frog

How to cut a release. Releases are produced by GoReleaser via the GitHub Actions workflow at `.github/workflows/release.yml`, triggered when a `v*` tag is pushed.

## Versioning

kiss-a-frog follows [semver](https://semver.org). Versions are **independent of the Swamp spec version** — kiss-a-frog v0.3.0 doesn't imply Swamp 0.3.0; it tracks kiss-a-frog's own API and behavior changes.

While kiss-a-frog is in 0.x:

- **PATCH** — bug fixes, documentation, internal refactors with no observable change.
- **MINOR** — new features, behavior changes, breaking-shape changes (per semver, anything goes during 0.x).
- **MAJOR** (0.x → 1.0) — the commitment moment for backwards-compatibility.

Pre-release identifiers (`v0.2.0-rc1`, `v0.2.0-alpha`) are valid; goreleaser's `prerelease: auto` marks releases tagged with a hyphen suffix as GitHub pre-releases.

## Steps

1. **Confirm the working tree is clean and on `main`:**
   ```sh
   git status
   git log --oneline origin/main..HEAD   # should be empty
   ```

2. **Pick the version.** Look at commits since the last tag (`git log $(git describe --tags --abbrev=0)..HEAD`) and decide PATCH / MINOR / MAJOR per the semver discipline above. The version is a decision, not mechanical — for an agent doing this on the principal's behalf, confirm the chosen number with the principal before tagging.

3. **(Optional) Smoke-test a snapshot build locally.** Requires goreleaser installed (`brew install goreleaser`):
   ```sh
   goreleaser release --snapshot --clean
   ls dist/
   ```
   Verifies the build works without publishing anything. Output goes to `dist/` (gitignored).

4. **Tag and push:**
   ```sh
   git tag -a v0.X.Y -m "Release v0.X.Y"
   git push origin v0.X.Y
   ```
   The workflow fires automatically on tag push.

5. **Watch the workflow.** Actions tab: <https://github.com/swamp-protocol/kiss-a-frog/actions>. Typical run is ~2 minutes. On failure, the tag persists; delete it (`git tag -d v0.X.Y && git push --delete origin v0.X.Y`) before retrying after a fix.

6. **Verify the release.** Releases page should have:
   - Six archive files: `kiss-a-frog_0.X.Y_{darwin,linux,windows}_{amd64,arm64}.{tar.gz,zip}`
   - `checksums.txt`
   - Auto-generated changelog body

   Download the archive matching the local platform, extract, run `./kiss version`. Confirm it reports `kiss 0.X.Y (commit ..., built ...)`.

## When the Swamp spec version changes

kiss-a-frog tracks the Swamp spec version in two cosmetic places that the canonicalizer doesn't depend on but that read as confusing if they fall behind:

- `internal/sign/sign_test.go` — `buildPost` test fixture's `Swamp-Version:` header and `Content-Type: ... v=` parameter.
- Any example output in this README or RELEASE.md that shows a Swamp post.

When Swamp bumps (e.g. v0.2.0 → v0.3.0), grep the repo for the old version string and update. The tests still pass either way; this is for human reading consistency.

## Notes and caveats

- **No code signing.** Release binaries are unsigned. macOS Gatekeeper will block first run; users can right-click → Open or `xattr -d com.apple.quarantine kiss`. Windows SmartScreen / Defender may flag the binary on first download. Worth adding a one-line note to README the first time a non-developer audience uses it.
- **Changelog filters.** `.goreleaser.yaml` excludes commits prefixed `docs:`, `test:`, `chore:`. If a meaningful change has one of those prefixes, the release notes won't mention it; rewrite the commit before tagging or amend the release notes manually after publish.
- **Tag immutability.** Once pushed and a release is built, treat the tag as immutable. If a release ships broken, prefer cutting v0.X.Y+1 with a fix over force-deleting and re-tagging — downstream users may have already pulled the broken binary.

## For an agent doing this on the principal's behalf

Authority boundary: tagging and pushing a release is a public, hard-to-reverse action. Prepare the tag and confirm the version number with the principal before pushing. Once the principal approves the version, the tag-and-push is fine to run autonomously, and so is watching the workflow and reporting results back.
