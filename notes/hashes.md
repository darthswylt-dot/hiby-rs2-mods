# Artifact hashes

No binary listed here is committed to this repository. This inventory records
the locally retained development artifacts and the hashes used during hardware
testing.

## Important checkpoints

| State | SHA-256 |
| --- | --- |
| Original firmware 1.4 `hiby_player` | `0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e` |
| Firmware 1.4 sorting fix | `91d9e4a5d041512d26724953efbb3903f47c10b1c7a7e970bf160770254a7b8a` |
| Sorting + verified full traversal | `d2849a8c45ce378d3ad2b2b7cf163e6fcb22d5b1670b5c5e528557945519905c` |
| Sorting + traversal + verified wake refresh | `c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e` |
| Failed folder-follow hardware test; path lookup/build confirmed | `c4dc1fe8b3601505dcbf243f2f4dda5f0c5dc0a959008e512e7d7d4927d12e62` |
| Failed rebuild-before-callback folder-follow test; severe UI corruption/reboot | `5faa8c07da3ffaeba0ac1480ae0694319473112862b3b111bd9f4920d4c06eda` |
| Failed preserve-stack retarget test; old folder remained and input stalled | `c637effab37ff202c172a3f32a75f0d7cfbf309eec13ab8c5ecd1a89de1adfcc` |
| Successful dispatcher FD9 telemetry build; not a functional candidate | `6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912` |
| Recovered post-FD9 source-state diagnostic; not hardware-classified | `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87` |
| Successful crash-resistant two-phase pointer diagnostic | `eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01` |
| Successful passive playback-commit timing diagnostic | `d78e7805cf630af004f43317be8ee9ce3fcbcc78eb6fd42a0a7d18179653629e` |
| Successful passive live path-contract diagnostic | `599cc5e2143aae7633da967f3ea819d0683d2b9d5b184fd799930e07d1c9dc01` |
| Safe partial property-11 Folder View rebuild test; root selection only | `4c43e0a4853f94f9b0577b8fffd1d2ca9ae97dca1dc3d1f033c006565e7fddd6` |
| Failed passive active-vs-last Folder View depth diagnostic; unexpected process exit | `d1c3f979dcc78d30d6ba5a76e25c4d11c06a3af3390972ac3a1d2741f20f4adf` |
| Corrected view-depth diagnostic v2; successful passive hardware run | `a943596abe82468142af3a8af00651782a6960e98b62e01b49a18b9c3fb42c42` |

## Local artifact inventory

All listed local files are 7,133,528 bytes except the firmware 1.3 sortfix,
which is 7,109,624 bytes.

| Artifact | SHA-256 |
| --- | --- |
| `hiby_player_1.3_sortfix` | `e541c92292c0f2dfe4311e098332c57036c5fbc6c4d36bc7e841093a52559879` |
| `hiby_player_1.4_sortfix` | `91d9e4a5d041512d26724953efbb3903f47c10b1c7a7e970bf160770254a7b8a` |
| `hiby_player_1.4_sortfix_bidir_pathorder_test` | `81db4eb1de816178a1a7eb0e91dc7d1ac429c5688bf1d6e351bde7fdc0bf9872` |
| `hiby_player_1.4_sortfix_equaldepth_force_test` | `369e2edaae54db0c2ab33b2edda9103cc5fbaa5f6e2c2e61c2da3a521f337f00` |
| `hiby_player_1.4_sortfix_fullnav_bkl3_force_refresh_test` | `c825a72e1078999f74822846d35c99971f9a660addd5f12d42d50a75f0b9b80e` |
| `hiby_player_1.4_sortfix_fullnav_bkl3_refresh_test` | `96d62b3db3a19f77f3d74f9ebf30fe2ae21b75470d3ba5998a222e1c6f2ef6b8` |
| `hiby_player_1.4_sortfix_fullnav_nodrop_screenoff_events_test` | `7f8d1eaab3710c91c29ae31d3afd085555d688dc03436c452601d70511b8b785` |
| `hiby_player_1.4_sortfix_fullnav_pause_refresh_test` | `e1750461390db1cf256d99a1f2ac972f97d22ac57d0cae11bb2cb5db42714b73` |
| `hiby_player_1.4_sortfix_fullnav_powerdiag` | `de490a13081610b8d5970adf16e91412d1bfbcbd2fec5857fb9b7473325cece0` |
| `hiby_player_1.4_sortfix_fullnav_screenon_refresh_test` | `7d82e11b5dfa90fc524a5840fb95490dd52b97904a28047c2c8ec7f134ad2676` |
| `hiby_player_1.4_sortfix_fullnav_test_v2` | `b450c33e98d39da08e0052678dfe32f81f8f8514a769729ae34a52493519fd02` |
| `hiby_player_1.4_sortfix_fullnav_ui_diag` | `1f19c1cf113ba242c9299d1f89e90da56a963716cbc5ab0caa16439bcf8a6aa1` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_swipe_test` | `c4dc1fe8b3601505dcbf243f2f4dda5f0c5dc0a959008e512e7d7d4927d12e62` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_rebuild_before_callback_test` | `5faa8c07da3ffaeba0ac1480ae0694319473112862b3b111bd9f4920d4c06eda` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_preserve_stack_retarget_test` | `c637effab37ff202c172a3f32a75f0d7cfbf309eec13ab8c5ecd1a89de1adfcc` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_dispatch_fd9_diag_test` | `6c274509946c57a642a5ae7f7a42910e6bc8abe28fba8155c973bb6a56c08912` |
| `hiby_player_02fd.bin` | `02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_safe_pointer_diag_test` | `eba4b0c99ae0f0436a038d9db242b62176c9120bc79d64b6da40564288cf3a01` |
| `hiby_player_1.4_sortfix_fullnav_wake_playback_commit_diag_test` | `d78e7805cf630af004f43317be8ee9ce3fcbcc78eb6fd42a0a7d18179653629e` |
| `hiby_player_1.4_sortfix_fullnav_wake_ui_timer_diag_test` | `32c916ee3762568b06fe05279360b8d2b8f7de5e3ae47be37511e1c44baa3e8a` |
| `hiby_player_1.4_sortfix_fullnav_wake_playing_timer_diag_test` | `4927297b4ceebe3b7f8d4bb8854c632e2083d5212aa9f02c9182c9f213acf3fe` |
| `hiby_player_1.4_sortfix_fullnav_wake_playing_path_diag_test` | `599cc5e2143aae7633da967f3ea819d0683d2b9d5b184fd799930e07d1c9dc01` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_saved_path_rebuild_test` | `4c43e0a4853f94f9b0577b8fffd1d2ca9ae97dca1dc3d1f033c006565e7fddd6` |
| `hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_test` | `d1c3f979dcc78d30d6ba5a76e25c4d11c06a3af3390972ac3a1d2741f20f4adf` |
| `hiby_player_1.4_sortfix_fullnav_wake_view_depth_diag_v2_test` | `a943596abe82468142af3a8af00651782a6960e98b62e01b49a18b9c3fb42c42` |
| `hiby_player_1.4_sortfix_fullnav_wake_folderfollow_test` | `7e202a5f1e176138410da8ab7e79c5281e0741a3ef668212de29d07fb33fd23d` |
| `hiby_player_1.4_sortfix_fullnav_wake_swipediag` | `27ef241000b88143ef9b8282739c3b58b97912f3a1ae5941e7e3e810a41f54f6` |
| `hiby_player_1.4_sortfix_fullnav_wakefix_test` | `c0492d90058d0b2ccc20b5763cf77e54a965a144048e87300c5ed1714abd6dba` |
| `hiby_player_1.4_sortfix_next_parentfix_test` | `c85c9950c37d0776602f21719d37c3db857e20c7cf87bf2f3cee03025c0f6120` |
| `hiby_player_1.4_sortfix_pathorder_test` | `50536b835bab113846ecc4430a301be688b284b9e6c276335d3e45af7a75dc95` |
| `hiby_player_1.4_sortfix_prev_direnable_test` | `c9fcb7a3e8962454e43240c2a062e2969b3d8215ee456f792edabfe4d263f624` |
| `hiby_player_1.4_sortfix_prev_lastchild_test` | `d2849a8c45ce378d3ad2b2b7cf163e6fcb22d5b1670b5c5e528557945519905c` |
| `RS2_1.4_SORT_FULLNAV_WAKE_FOLDERFOLLOW_TEST_v2.bin` | `b49c2074eec91fcc3162bcfa940d9b8752c6a449d8abf26a8992fc93d44bc6a1` |

## Diagnostic log hashes

Device logs are not committed. The completed three-record FD9 log was retained
locally as `target_b_full.bin` only for analysis.

| Log | SHA-256 |
| --- | --- |
| `rs2_folderfollow_dispatch_diag.bin` / `target_b_full.bin` | `a76aefceaed2a8100afc066261755032a2137ef71d5ca4f7e125a0ce0d408dc2` |
| `rs2_folderfollow_safe_pointer_diag.bin` / `rs2_safe_complete_roots_slayers_sleep.bin` | `dc4272a9d4778cc447b1e37081ae853a68e6cac7ca09dd88eac392d5c36cff6c` |
| `rs2_playback_commit_diag.bin` / `rs2_playback_commit_diag_complete_roots_evil_antichrist_die.bin` | `6cda1e5bcf835854eeee2ea2fcfd85a132fe7ddf4cf3d5b59f5265560cb8a6da` |
| `rs2_folderfollow_ui_timer_diag.bin` (zero-invocation hardware run) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `rs2_playing_timer_diag_complete_roots_evil.bin` (1912-record snapshot) | `41904b62da9cd6d2f20340e4dea0545daf1a880e4fd7d957124ef6ee04685cb9` |
| `rs2_folderfollow_playing_path_diag_complete.bin` (3177 complete records) | `46da98a2aa21048d0a0920b999ffd56cc242b92a490560d7fdc5dd2ec81daf67` |
| `rs2_folderfollow_playing_path_diag_final.bin` (5484 complete records; closed after stock reboot) | `0a2bb3912b1cd6283b4b909b1325c5e17bbdfdd6b0d2a334194a077330088986` |
| `rs2_folderfollow_view_depth_diag_failed_boot.bin` (315 complete records; unexpected exit) | `efbb68987801cf57e7bde69f4c5eee2855751f66e6a8ea163ba778b86017b3fc` |
| `rs2_folderfollow_playing_path_diag_deep_navigation_final.bin` (2069 complete records; deep navigation and Back, closed after stock reboot) | `ec1383753a0862a3fcd7bc0dbdcf93452d19559a5e85718414f24e0bfbaef18b` |
| `rs2_folderfollow_view_depth_diag_v2_final.bin` (2590 complete records; active-vs-last paths, closed after stock reboot) | `842dcb2c4401f01d05bd70358c56164f964f00381dc9cbe38b1278bb10b51986` |

Historical failed artifacts no longer present locally:

| Artifact | SHA-256 |
| --- | --- |
| `hiby_player_1.4_sortfix_nextfix_test` | `553765d9b57cfb926808481d8eb973f96d59bd10304c08930cc0b31533b5e965` |
| `hiby_player_1.4_sortfix_navctx_test` | `101a0fafaeab8b4c9b85c8f424c735706b1cca58fd71a681d16ec4fe03904c5c` |
