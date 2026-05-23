# F25 — VNC send-side protocol exchange logs

## Fix description

`src/intellicrack/ui/panels/vnc_widget.py` has strong receive-side coverage (`_handle_server_message`, ZRLE/Tight decompress, raw pixel reads all logged with structured kwargs), but every **outbound RFB write** (`self._writer.write(...)`) is silent. Per §2.3 every protocol exchange should be logged.

## Sites to fix

`src/intellicrack/ui/panels/vnc_widget.py`:

| Lines | Method | Fix |
|-------|--------|-----|
| 263-307 | `RFBClient.connect` `asyncio.open_connection` | `_logger.info("vnc_connecting", host=host, port=port, timeout=connect_timeout)` at L278 BEFORE the connect call |
| 309-323 | `_negotiate_version` client write at L322 | `_logger.debug("vnc_client_version_sent", version=_RFB_VERSION.decode().strip())` after the write |
| 325-407 | `_negotiate_security` / `_perform_vnc_auth` writes (L356, L394, L399) | `_logger.debug("vnc_security_selected", security_type=...)`; `_logger.debug("vnc_auth_response_sent")` |
| 409-436 | `_client_init` writes `ClientInit` (L423) and `_PIXEL_FORMAT_32BIT` (L429) | `_logger.debug("vnc_client_init_sent")`; `_logger.debug("vnc_pixel_format_set", format="BGRX-32")` |
| 438-457 | `request_framebuffer_update` protocol write | `_logger.debug("vnc_request_framebuffer_update", incremental=incremental)` |
| 1569-1582 | `send_pointer_event` — per-mouse-move network write | `_logger.debug("vnc_pointer_event", x=x, y=y, button_mask=button_mask)` (consider rate-limiting if too chatty) |
| 1584-1596 | `send_key_event` | `_logger.debug("vnc_key_event", key=key, down=down)` |
| 1598-1608 | `disconnect` lifecycle transition | `_logger.info("vnc_disconnecting")` entry + `_logger.info("vnc_disconnected")` after close |

## Acceptance criteria

- [ ] Every outbound `self._writer.write(...)` has a surrounding debug log
- [ ] `connect`/`disconnect` are info-level lifecycle events
- [ ] Pointer/key events are debug-level (high volume)
- [ ] Pixel-format/security/auth negotiation steps logged
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Optional: ensure send-side logs are rate-limit-friendly (mouse move spam)
