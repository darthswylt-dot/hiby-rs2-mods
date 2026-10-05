# MOVE checkpoint collector for the legacy RS2 shell

Update 2026-10-02: the first [supervised live capture](folderfollow-move-supervised-run-20261002.md)
passed source/transport/record gates (341,248 bytes) and matches the later
closed log exactly. This validates the observed run, not general crash safety.

2026-10-01. A legacy-safe, read-only collector is prepared locally. The
**byte transport and a closed-file prefix passed on the actual stock RS2**.
This is not a live MOVE capture or validation of the evidence launcher.
Do not infer permission to install, rearm or launch MOVE from this result.

Scripts:

- `scripts/capture_move_legacy_checkpoint.py`: strict source protocol and CLI.
- `scripts/legacy_adb_transport.py`: bounded ASCII envelope and hex decoder.
- `scripts/check_legacy_adb_transport.py`: stock-only compatibility controls.

The original `capture_move_checkpoint.py` keeps its default native protocol;
its common capture/record-validation logic now also accepts the legacy
protocol explicitly. The failed native exec-out/stat route has not become
compatible with RS2. See the [original device check](folderfollow-move-device-compatibility.md).

## Transport and source identity

The legacy shell requires a PTY and changes CR/LF bytes. Therefore only
ASCII hex and nonce-delimited completion/status markers cross that channel.
CR/LF handling is confined to the ASCII envelope; decoded binary bytes are
never newline-normalized. The remote `od -An -v -tx1 -N N` command bounds
the source read. No pipeline hides its status. A zero host ADB exit status
alone is never evidence of a successful remote capture.

The preflight retains raw metadata and checks boot ID, PID/starttime,
expected live MOVE hash `15cf4457...`, exact requested FD9 path, regular-file
inode/size, memory/status and explicit completion. The frozen prefix is
then read through a new read-only FD8. Checks immediately around `od`
compare that held descriptor with both the pathname and the player's FD9,
and check boot/starttime, mount identity and minimum size. The player's
own file-description offset is never read or changed.

This BusyBox has no `stat`, and kernel fdinfo has no `mnt_id`. The fallback
is numeric, colour-free `ls -Lndi`, `test -ef` (device and inode equality),
and matching shell/player mountinfo. Only the direct vfat `/mnt/sd_0`
mount is accepted; ambiguous mounts, bind roots and more-specific mounts
are refused. vfat does not support symlinks. Identity is not guessed from
an inode number alone. The postflight must agree with the initial source
identity and show nondecreasing uptime/size.

These checks remain observations, not an atomic snapshot. They cannot
exclude an in-place rewrite or every change restored between observations.
Read-only collection also consumes CPU, I/O and page-cache memory.

## Bounds and failure evidence

Remote commands are limited to 4000 encoded bytes. Metadata/stderr retain
the existing 256-KiB bounds. The hex stream has a `4*N + 16 KiB` host bound;
decoding keeps at most `N+1` bytes to expose overflow. A new host output
directory is mandatory, with initial free space of six times the configured
binary budget plus 4 MiB. The per-command timeout remains 30 seconds by
default. The original collector's documented host-pipe cleanup limitations
still apply; this is not an unconditional hard-deadline guarantee.

The output additionally retains `raw.hex` (original encoded wire bytes),
`raw.bin` (decoded bytes), and `raw.stderr`. Malformed markers/tokens,
missing completion, explicit nonzero remote status, short/long output,
timeout and source changes fail closed. Partial wire/decoded evidence and
postflight attempts are retained where host storage permits. No retry,
device-side copy, file creation, signal, rearm or reboot is performed.

The existing strict MOVE record decoder still keeps all valid complete
records, including unsettled trailing events. It never trims evidence back
to manufacture success. Transport compatibility does not imply an accepted
live record stream.

## Actual stock compatibility result

Host evidence: `artifacts/legacy_compatibility_20261001/`.
The report records `compatibility_passed=true`,
`stock_state_preserved=true`, and **`live_move_validated=false`**.

- All 256 byte values plus an explicit NUL/CR/LF/FF control: 266 bytes,
  exact match; SHA-256
  `b1272c7842c818c48d29d5c51d2c248bd7ca91f805c1eb71f50f3f136b309825`.
- An explicit remote status 37 was retained and treated as failure even
  though the legacy ADB client returned zero.
- A pinned 65,536-byte prefix of the known closed September log matched
  the previously recovered local file byte-for-byte; SHA-256
  `33a323e815142fd6c24706e28acf2d34933b86793f93090a65cea29f249ba23e`.

Before/after reads retained boot ID
`d20f9fb3-9038-445a-961b-02f1cd17f03b`, stock PID 116/start ticks 349,
stock executable hash `0fedb30f...`, and an absent `RS2_SORTFIX_TEST` flag.
Installed launcher `522f0b1b...`, inactive MOVE candidate `15cf4457...`,
closed-log hash `e181b611...`, inode 142 and size 7,973,184 were unchanged.
The first host diagnostic records an ordinary ADB daemon startup.
No firmware, launcher, flag or log file was written on the device.

Paired stock memory reads: MemTotal 58,308 KiB, MemFree 948/904 KiB,
Cached 16,952/17,000 KiB, player VmRSS 18,712 KiB. These values are not
evidence of the earlier MOVE run's RAM usage or reboot mechanism.

## Local verification

All **161** repository tests pass with no skips: 20 new transport tests,
19 legacy protocol/capture tests, 16 stock-compatibility harness tests, and
the 106 existing tests. Tests use mocked ADB or disposable host shell
fixtures, not the player. The migrated reference ELF is now found under
`artifacts/import-20261001/hiby_player_02fd.bin` (original parent-directory
layout remains a fallback), so the six ELF-dependent checks are not skipped.
Its SHA-256 remains
`02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87`.

The shell fixture executes real held-FD, `test -ef`, numeric `ls`, `awk`
and bounded `od` checks against host-only files. A hardlink plus a mocked
readlink result avoids Windows symlink privileges; this is not device
mount/FD runtime validation. Existing evidence launcher and MOVE firmware
hashes are unchanged. All 62 Python scripts compile, and `git diff --check`
passes. An independent read-only review found no further material issue.

## Remaining gate

The original-stock user test also reproduced missing automatic scrolling:
the offscreen playing row was highlighted after manual scrolling, and
volume worked. See [the stock comparison](folderfollow-scroll-diagnosis.md#unmodified-stock-comparison-2026-10-01).
This does not identify which list-scroll setter or caller needs changing.

The subsequent [launcher preflight](folderfollow-move-launcher-preflight.md)
passed full syntax and read-only startup prerequisites on the device using
hash-verified compressed ASCII within the command limit. Actual launcher
installation, arming and a live run remain a separate stage. The unexplained
prior reboot is not declared fixed, and no auto-scroll firmware fix is claimed.
