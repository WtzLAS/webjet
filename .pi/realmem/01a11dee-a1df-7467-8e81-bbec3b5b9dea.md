---
id: 01a11dee-a1df-7467-8e81-bbec3b5b9dea
caption: "webjet-app Merkle tab layout: summary is a Column split; head/genesis/keys are Row splits with scrolling panels"
paths:
  - crates/webjet-app/src/ui/merkle.rs
created: 2026-10-08T23:52:20.703Z
updated: 2026-10-08T23:52:20.703Z
---

The Merkle tab (crates/webjet-app/src/ui/merkle.rs) used to have a fixed-height (`flex_shrink_0`) tree summary row with fixed-width Genesis (360) and signing-key (380) panels; in small windows (e.g. 1100×760) it pushed the leaves/details/log splits to 0 px height, so their separators couldn't be grabbed. Now: `MERKLE_SUMMARY` (Column, summary sized first, default 240, min 100, rest_min 200) above `MERKLE_OPS`/`MERKLE_DETAIL`; inside the summary `MERKLE_HEAD` (head | genesis 360) and `MERKLE_KEYS` ((head|genesis) | certs 380). Summary panels are `summary_panel(id)` = scrolling panel. Test `ui::tests::merkle_separators_move` drags all five handles at 1435×852 … 1000×640 (drag direction shrinks the sized pane, since growing does nothing when the window already squeezes the other pane).
