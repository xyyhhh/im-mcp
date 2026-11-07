# Remote chat images and the decrypted file mirror

Message queries keep `[图片]` as the compact text summary. To read the image,
call `get_message_image(message_id=...)` using that message's index ID. By
default the result contains text metadata and a standard MCP `ImageContent`
block, so a remote client does not need access to the server's filesystem.
The default `quality="full"` tries `_h.dat` / `_h_W.dat` high-resolution files
before normal `.dat` / `_W.dat` variants. It never substitutes a thumbnail.
Unreadable high-resolution files can fall back to another readable full-size
variant, with a warning; a readable high-resolution file is not replaced by a
smaller normal variant just to fit a transfer limit.
The client must route MCP images to a vision-capable model or its configured
vision adapter. The server does not perform OCR or call a separate AI service.

`return_image=False` requests metadata only. The older `include_base64=True`
option still includes the encoded bytes in structured metadata; it is usually
unnecessary. Binary data is never duplicated into the text content block.
Only an explicit `quality="thumbnail"` request selects `_t.dat` / `_t_W.dat`.
If only a thumbnail was downloaded, the default request returns
`original_not_downloaded`. The result includes `source_variant`, `quality`, and
dimensions for JPEG, PNG and GIF headers when available.

Full-size payloads up to 20 MiB and 40 million known pixels are returned unchanged,
without resizing or recompression. Larger payloads return `image_too_large` and
metadata, never a silently substituted thumbnail. `return_image=False` permits
metadata inspection; `allow_large=True` explicitly permits larger transfers.
The 64 MiB encrypted-source decoding hard limit still applies. Pixel dimensions
are not currently inspected for WebP, so its byte-size limit still applies.
Failures set MCP `isError` and include a machine-readable `error_code`, such as
`image_not_downloaded`, `image_key_missing`, or `unsupported_image_format`.

## File layout

The default decrypted account mirror is `~/.wechat_mcp/decrypted/`:

```text
decrypted/
  db_storage/
    message/message_0.db
    contact/contact.db
    ...
  msg/attach/<chat-directory>/<month>/Img/<original-stem>.png
```

Database relative paths match the original account's `db_storage` directory.
Image directories and stems match the original account's `msg/attach` tree;
only the encrypted `.dat` extension changes to the decoded format. A thumbnail
keeps its original `_t` or `_t_W` suffix. Unsupported `wxgf` originals are
preserved as `.wxgf`, then other full-size variants are attempted. If none can
be rendered, `unsupported_image_format` is returned. A thumbnail must be
requested explicitly and is marked `is_thumbnail=True`. Do not infer uncertain
names or dates from an unreadable thumbnail. This change does not add a wxgf
decoder: locally available high-resolution JPEG/PNG/GIF/WebP variants are used.

`WECHAT_FILES_ROOT` selects the source account root explicitly and takes
precedence over automatic discovery. Images from other accounts are not used
as a fallback when an account has been configured. `WECHAT_DECRYPTED_DIR`
selects the decoded database directory, even before it exists. Its parent is
the mirror root when its last component is `db_storage`.
`WECHAT_DECRYPTED_FILES_ROOT` can override the mirror root explicitly.

Existing flat `decrypted/message/*.db` installations remain readable. To migrate,
stop the service, move the existing database subdirectories under
`decrypted/db_storage/`, and restart; do not copy ciphertext over decoded files.
Old flat image caches are left untouched and are no longer used for new output.
The query index, keys, generated avatars and other application metadata are not
original account files and remain outside this mirror.

## Writes and permissions

Resident memory sync still does not write decoded database snapshots. The layout
above determines where explicit disk decryption writes them; it does not enable
disk snapshots in memory mode. Images are decoded on demand. Identical decoded
bytes leave the existing output file and its modification time unchanged.
Changed contents at the same source-relative path replace the output atomically
through a temporary file in that directory. An image read does not append to a
shared file or rewrite unrelated images or databases. Cache reads still read
and decode the encrypted source to detect changes.

V2 images require a saved account image key. Initialize it locally with the
necessary Windows permission, rather than running the long-lived server as an
administrator. Missing local images must first be downloaded in WeChat. This
does not add a public download endpoint; images travel through the existing
authenticated MCP transport. Decoding rejects files larger than 64 MiB.
