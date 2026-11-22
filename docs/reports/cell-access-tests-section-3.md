# Cell access tests: what is left to write (section 3)

Section 3, file systems, is the only part of the suite with no checks. An
automated safety classifier stopped the session that was writing its script
(2026-11-15) and told it not to produce that content again, so a person
needs to write it. Nothing from that script was saved. This file has the
requirement and how to plug a script in; it has no check code.

Background: `cell-access-tests.md` (the report) and
`cell-access-tests-plan.md` (the checklist).

## What to check

From the task, word for word:

> **Filesystem:** `..` at the root stays at the root (`chdir`, `openat` with
> dirfds, long chains); symlinks to paths that exist only in B's root resolve
> to nothing in A; files created in either cell are invisible in the other;
> links and renames stay inside A's root; ptys created in B can't be opened
> from A, and A's devpts lists only its own.

The suite's rules apply: the real syscall from A, one exact errno for each
refused call, and a control on A's own object that succeeds.

- [ ] `..` at the root (`chdir`, `openat` with dirfds, long chains)
- [ ] Symlinks to paths only in B's root
- [ ] Files made in A are invisible in B
- [ ] Files made in B are invisible in A
- [ ] Links and renames stay inside A's root
- [ ] B's ptys cannot be opened from A; A's devpts lists only A's own
- [ ] B is intact afterwards (the harness checks this by itself)
- [ ] Checking the checks (below)

## Where it goes

The rule is `file_systems_are_scoped_to_their_root`.

1. Write `kernel/ichor/src/cellaccess/s3_files.pl`. `s7_root.pl` is the
   shortest section that runs in A alone; start from its shape. Set
   `$RULE` to the rule's name first and call `done()` last.
2. In `kernel/ichor/src/cellaccess.rs`, add
   `const S3_FILES: &str = include_str!("cellaccess/s3_files.pl");` and an
   entry in `SECTIONS` between sections 2 and 4. `|c| in_a(c, S3_FILES)` is
   enough if everything runs in A; otherwise write an `s3(ctx: &Ctx)`, as
   `s5` does, and use `report` for the harness's own checks.
3. In `tests/cell_access.rs`, raise `SECTIONS` from 10 to 11 and add a test
   named after the rule: `assert_rule(...)`, then `assert_in_order` on the
   lines that must appear, ending with the `passed` and `B alive and
   unchanged after` ones.

## What is already there

- **B's objects.** A script gets B's report as arguments
  (`my %B = kv(@ARGV)`): `only` is `/b-only/secret`, `pts` is the list of
  B's pty numbers, `upath` its Unix socket. B also has the symlink
  `/b-only/link`. `b_helper.pl` makes them all; add any new one there and to
  its `put("ids", ...)`.
- **Looking from B.** The helper answers a `look` request: paths separated
  by spaces, answered as `PATH=exists` or `PATH=absent`. Nothing uses it
  yet; it was made for this section. From the harness:
  `put(&ctx.b.root, "look", paths)`, then
  `take(&ctx.b.root, "look", &ctx.helper)`.
- **Looking from the harness.** `read(&root, path)` reads a file in either
  root through its overlay.
- **B is intact.** After every section `b_intact` checks that B's secret
  still reads the same and that its ptys are still there.
- **Checks** (`prelude.pl`): `want(CHECK, ERRNO, RESULT)`,
  `control(CHECK, RESULT)`, `same(CHECK, GOT, WANT)`.

## Things that have gone wrong before

- `syscall()` arguments: numbers must be numbers (`+ 0`, also `$$ + 0`);
  strings must be variables, not literals.
- Pty numbers start at 0 in each root, so A's own first pty has the same
  name as B's first. Check B's numbers before A opens any pty of its own.
- Do not write to `/usr/bin/dash` or `/usr/bin/bash` in A's root. Section 4
  compares their cache pages.
- Keep perl's output lines whole: use the prelude's helpers.
- Leave nothing running: the run fails unless its memory is returned.
- If a check finds a real bug, the task says to keep it failing with a
  message that names the bug, write it up, and not fix it.

## Checking the checks

The task asks for this in section 3 as in sections 1 and 2: temporarily
remove the scoping in the kernel code responsible, see the tests fail
clearly, restore the code byte for byte, confirm with `git diff`, and never
commit the edit. Note each one in the report. The code responsible:

- Path resolution, including `..`: `Overlay::lookup` and the resolution loop
  in `kernel/overlay/src/lib.rs`.
- Ptys: `open_slave` in `kernel/ichor/src/pty.rs`, and the per-root table
  `Vfs::ptys`.
- Files: each cell's root is its own `Vfs` with its own overlay
  (`kernel/ichor/src/vfs.rs`). There is no filter to remove; the separate
  objects are the scoping.

## Running it

```powershell
cargo xtask run --cmdline "qemu_debug_exit cell_access" --smp 2 --timeout 1800
```

That boots the suite alone and prints every check; without
`cell_access_uplink` it skips the uplink part of section 5. Before each
commit:

```powershell
cargo xtask lint
```

```powershell
cargo xtask test
```

If QEMU cannot get memory ("paging file is too small"), rerun the failed
test files with `--test-threads=1` and `ICHOR_KERNEL` set, as the report
says.

## Merging main first

As of 2026-11-22 `main` (18552dc) is 11 commits ahead and conflicts with
this branch in `kernel/ichor/src/switch.rs` only. After merging, rerun the
whole suite: a call that started working or changed its errno needs its
check updated.

## When it passes

- Tick section 3 in `cell-access-tests-plan.md`.
- In `cell-access-tests.md`: its row in the table, the "Section 3 has no
  coverage" paragraph, the scoping-removal results, and "Not tested".
- The status line in `AGENTS.md`.
- Delete this file.
