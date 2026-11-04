# Maintenance

## Rust version policy

`rust-toolchain.toml` is the single source for the exact development compiler
version. Keep `channel` pinned to a released version, not `stable` or `nightly`.
Local development, IDEs, CI formatting/Clippy/tests, privileged acceptance and
package builds use this pin. The toolchain includes `rust-analyzer` for IDEs and
editors. Rust sources are opt-in; install them locally when needed:

```sh
rustup component add rust-src
```

`workspace.package.rust-version` in `Cargo.toml` is the minimum supported Rust
version (MSRV), currently **1.89**. Both crates inherit it. The MSRV CI job reads
this value, builds every target and runs workspace tests with the first
release of that minor version and the committed lockfile. It does not run
formatting or Clippy on the old compiler.

Clippy reads the inherited MSRV when suggesting APIs. Cargo resolver 3 prefers
MSRV-compatible dependencies during lockfile updates; the actual MSRV build
remains the compatibility check.

## Update the development toolchain

1. Find the current stable release in the [Rust release announcements](https://blog.rust-lang.org/releases/).
   Optionally run `rustup update stable` and `rustc +stable --version` to inspect
   it locally. Do not change the repository to a rolling channel.
2. Set `toolchain.channel` in `rust-toolchain.toml` to that exact version,
   including the patch number. Keep the components and profile. CI and package
   builds read this file, so no Rust version edits in workflows are needed.
3. Install the pin and run the development checks as an unprivileged user:

   ```sh
   rustup toolchain install
   rustc --version
   cargo fmt --all
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked -- --test-threads=1
   git diff --check
   ```

4. Resolve new lint findings while retaining MSRV compatibility. Leave
   `workspace.package.rust-version` unchanged for a development toolchain update.
   Do not update dependencies unless the change requires it.
5. Verify the MSRV separately. For the current MSRV, run:

   ```sh
   rustup toolchain install 1.89.0 --profile minimal
   cargo +1.89.0 build --workspace --all-targets --locked
   cargo +1.89.0 test --workspace --locked -- --test-threads=1
   ```

6. Review the diff and require the CI and Packages workflows to pass, including
   privileged acceptance and distribution package smoke tests. The acceptance
   check manifests and package `build-info.txt` record the actual compiler.

These commands assume no `RUSTUP_TOOLCHAIN` environment override or rustup
directory override. Check `rustup show active-toolchain` if the selected compiler
does not match the repository pin.

## Change the MSRV

Treat an MSRV increase as a separate compatibility decision. Update
`workspace.package.rust-version` in `Cargo.toml`, the documented MSRV and the
manual MSRV commands above together. Keep both crates inheriting the workspace
value. CI derives its compiler version from the manifest automatically.

For dependency updates, retain resolver 3 and verify the resulting lockfile on
both the development compiler and the MSRV. Resolver fallback is a preference;
it cannot guarantee that every selected dependency supports the MSRV.

## Workflow coverage and scheduling

| Checks | Native runner | Rust version |
| --- | --- | --- |
| Build, tests, formatting, Clippy and full privileged acceptance | `ubuntu-24.04` (x86-64) and `ubuntu-24.04-arm` (ARM64) | Development pin |
| MSRV build and tests | `ubuntu-24.04` (x86-64) | Workspace MSRV |
| Distribution package builds and smoke tests | `ubuntu-24.04` (x86-64) | Development pin |

Keep architecture identifiers in build cache keys and acceptance artifact names.
The acceptance jobs run natively with real delegation and identities on both
architectures; cross-compilation alone does not validate these operations.

Both CI and Packages call `.github/workflows/should-run.yml` before their checks.
For branch pushes, it queries open PRs and skips the checks if the head branch
belongs to this repository and matches the pushed branch. Only the small
selection job runs for these duplicate push events. Branches without an open PR,
tag pushes, pull request events (including forks) and manual dispatches run their
normal jobs. Failure to query PRs fails the selection job.

Concurrency groups include the workflow name and either the PR number or branch
ref, with `cancel-in-progress: true`. This keeps at most one current run per
workflow for each branch or PR, including manual branch runs. Keep branch and PR
groups separate: a skipped push must not cancel the corresponding PR run. Keep
CI and Packages groups separate so both workflows can validate the same change.

Lint workflow changes with:

```sh
actionlint .github/workflows/*.yml
```
