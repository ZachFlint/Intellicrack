# F29 — Splash screen startup stage transition logs

## Fix description

`src/intellicrack/ui/dialogs/splash_screen.py` explicitly models 8 startup stages (Creds → Providers → Tools → Session → Engine → Scripts → Models → UI) via `_STAGE_LABELS` and `_update_stage_states`. Logging each stage's ACTIVE/COMPLETE transition at info would give a structured startup trace — exactly the orchestration-context Intellicrack benefits from per its scope statement in CLAUDE.md.

## Sites to fix

`src/intellicrack/ui/dialogs/splash_screen.py`:

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 494-527 | `set_progress(value, message)` — moves through stages via `_update_stage_states` | Inside `_update_stage_states`, when a stage transitions to ACTIVE: `_logger.info("splash_stage_started", stage_index=..., stage=_STAGE_LABELS[idx])`; when COMPLETE: `_logger.info("splash_stage_completed", stage_index=..., stage=...)` |
| 485-492 | `mark_stage_failed(stage_index)` panic path | `_logger.error("splash_stage_failed", stage_index=stage_index, stage=_STAGE_LABELS[stage_index])` |
| 425-437 | `show_animated()` | `_logger.info("splash_shown")` |
| 439-453 | `finish_animated(window)` | `_logger.info("splash_finishing")` |
| 455-460 | `_on_fade_out_finished` (`self._finish_target.show()` + `self.close()`) | `_logger.debug("splash_fade_finished")` |
| 237-239 | `except FileNotFoundError: _logger.warning("splash_image_not_found")` — missing `splash_path` kwarg | Add `path=str(splash_path)` |

## Acceptance criteria

- [ ] Every startup stage transition emits a structured log
- [ ] Splash show/finish/close lifecycle logged
- [ ] Splash image load failure includes the path that was attempted
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Spot-check: launch the app and verify the log timeline shows 8 distinct stage transitions
