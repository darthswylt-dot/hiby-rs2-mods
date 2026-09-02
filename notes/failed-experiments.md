# Discarded and diagnostic experiments

These results are retained so that failed approaches are not accidentally
repeated. None of the entries in this document should be treated as a release
candidate.

## Folder traversal

### `sortfix_nextfix_test` — discard

- Historical SHA-256: `553765d9b57cfb926808481d8eb973f96d59bd10304c08930cc0b31533b5e965`
- Change: replaced the `addiu` at `0x4E39E8` with `nop`.
- Result: the player hung at the end of Album1 and ADB disconnected.
- Cause: the instruction is in a MIPS branch delay slot and advances the child
  index. Removing it created an infinite loop over the same directory.

### `sortfix_navctx_test` — discard

- Historical SHA-256: `101a0fafaeab8b4c9b85c8f424c735706b1cca58fd71a681d16ec4fe03904c5c`
- Change: cleared the current-path field before recursive descent.
- Result: end-of-folder playback wrapped to the first track of the same folder;
  Previous was unchanged.
- Cause: the modified structure stores the active path, not a disposable local
  navigation context.

### `sortfix_equaldepth_force_test` — diagnostic only

- SHA-256: `369e2edaae54db0c2ab33b2edda9103cc5fbaa5f6e2c2e61c2da3a521f337f00`
- Change: forced equal-depth candidates into the recursive branch.
- Purpose: localized the incorrect local-`rowid` comparison.

### `sortfix_bidir_pathorder_test` — discard

- SHA-256: `81db4eb1de816178a1a7eb0e91dc7d1ac429c5688bf1d6e351bde7fdc0bf9872`
- Result: broke working forward traversal and still skipped the nested directory
  during Previous.
- Lesson: forward and reverse traversal have distinct directory-entry branches;
  sharing the first forward fix did not enable reverse descent.

### Navigation stepping stones

The following artifacts were useful during isolation but are superseded by the
verified full-navigation build:

| Artifact | SHA-256 | Role |
| --- | --- | --- |
| `sortfix_next_parentfix_test` | `c85c9950c37d0776602f21719d37c3db857e20c7cf87bf2f3cee03025c0f6120` | Compared parents before local `rowid` values. |
| `sortfix_pathorder_test` | `50536b835bab113846ecc4430a301be688b284b9e6c276335d3e45af7a75dc95` | First verified forward Next/autoplay traversal. |
| `sortfix_prev_direnable_test` | `c9fcb7a3e8962454e43240c2a062e2969b3d8215ee456f792edabfe4d263f624` | Enabled reverse descent but did not yet choose children in reverse order. |
| `sortfix_fullnav_test_v2` | `b450c33e98d39da08e0052678dfe32f81f8f8514a769729ae34a52493519fd02` | Added reverse iteration; entering a previous subtree still selected the first child. |

## Wake refresh

Several reasonable-looking patches had no effect because they targeted a
backlight/resume path that the reproduced short-Power scenario did not use:

| Artifact | SHA-256 | Result |
| --- | --- | --- |
| `fullnav_wakefix_test` | `c0492d90058d0b2ccc20b5763cf77e54a965a144048e87300c5ed1714abd6dba` | One-shot timer from late resume; no fix. |
| `fullnav_pause_refresh_test` | `e1750461390db1cf256d99a1f2ac972f97d22ac57d0cae11bb2cb5db42714b73` | Allowed refresh while paused; no fix. |
| `fullnav_screenon_refresh_test` | `7d82e11b5dfa90fc524a5840fb95490dd52b97904a28047c2c8ec7f134ad2676` | Hooked the wrong screen-on path. |
| `fullnav_nodrop_screenoff_events_test` | `7f8d1eaab3710c91c29ae31d3afd085555d688dc03436c452601d70511b8b785` | Removed a screen-off event guard; no fix. |
| `fullnav_ui_diag` | `1f19c1cf113ba242c9299d1f89e90da56a963716cbc5ab0caa16439bcf8a6aa1` | Proved the assumed `PWR_ON` hook never fired. |
| `fullnav_powerdiag` | `de490a13081610b8d5970adf16e91412d1bfbcbd2fec5857fb9b7473325cece0` | Identified `BKL_5` as off and `BKL_3` as on. |
| `fullnav_bkl3_refresh_test` | `96d62b3db3a19f77f3d74f9ebf30fe2ae21b75470d3ba5998a222e1c6f2ef6b8` | Correct metadata after wake, but progress remained at zero on Pause. |

The superseding build uses the same actual `BKL_3` hook and calls the stock
progress refresh with `force=1`.

## Folder-follow UI

### Screen-on Folder View rebuild — discard

- Expected build SHA-256: `b49c2074eec91fcc3162bcfa940d9b8752c6a449d8abf26a8992fc93d44bc6a1`
- Result: waking showed Folder View rather than Now Playing; swiping produced
  several overlapping explorer panels.
- Cause: `0x4E4640` creates actual explorer-view levels. Calling it on screen-on
  on top of the existing browser stack corrupts the visible UI hierarchy.

One downloaded file named
`hiby_player_1.4_sortfix_fullnav_wake_folderfollow_test` had the unexpected
SHA-256 `7e202a5f1e176138410da8ab7e79c5281e0741a3ef668212de29d07fb33fd23d`.
It was not trusted. A separately named copy matched `b49c...`; this is why every
artifact must be hashed before `adb push`.

### Swipe diagnostics

`fullnav_wake_swipediag`
(`27ef241000b88143ef9b8282739c3b58b97912f3a1ae5941e7e3e810a41f54f6`)
logged a single Now Playing exit swipe as `a2=1, a3=1`. It is diagnostic only
and is superseded by the active swipe-triggered experiment documented in
`status.md`.

## Temporary ADB ordering

An `S90adb` symlink starts before `hiby_player`, but the player subsequently
rewrites the USB gadget configuration and removes ADB. Use the delayed `S99adb`
method in `adb.md` during testing, then delete it.
