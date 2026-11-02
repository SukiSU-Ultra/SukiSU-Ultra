# Theme store

The manager reads a token-protected catalog from a theme mirror and applies
`.sukisu` packages. The theme store and source-management screens are Material 3
Expressive only, independent of the manager's global Miuix/Material setting.
Theme package import/export dialogs use the same Material 3 Expressive styling.
The official mirror is an Armbian host behind Caddy/Lucky; the admin console is
not part of the Android build.

## Public endpoints

| Method | Path | Authentication |
| --- | --- | --- |
| `GET` | `/catalog.json` | `X-Sukisu-Theme-Token` |
| `GET` | `/themes/<id>-v<version>.sukisu` | `X-Sukisu-Theme-Token` |
| `GET` | `/previews/...`, `/screenshots/...` | `X-Sukisu-Theme-Token` |
| `GET` | `/health` | public |
| `POST` | `/submit` | `X-Sukisu-Theme-Token` |

## Upload and review flow

1. The manager picks a `.sukisu` package, preview, optional author avatar and up
   to six screenshots.
2. The manager validates the package locally with `ThemePackageStorage`, then
   resizes previews (max 1280 px), avatars (max 256 px) and screenshots (max
   1080 px) and compresses them to WebP before uploading.
3. `POST /submit` sends multipart metadata and files (`avatar` is optional). The
   server checks the token, field limits, image signatures and decrypts the
   package with the embedded theme key to inspect `theme.json` and referenced
   entries. It also normalizes images to WebP as a fallback for web uploads.
4. A valid submission is stored under `/srv/sukisu-themes/pending/<id>/`. It is
   not public and does not appear in `catalog.json`.
5. An administrator reviews the pending queue in the Armbian console. Approval
   moves the files into `themes/`, `previews/`, `avatars/` and `screenshots/`,
   writes metadata under `meta/`, and rebuilds `catalog.json` (each entry may
   expose an `avatarPath` that the manager shows in the author section).
   Rejection deletes the pending submission.
6. The manager can search the published catalog by name, author, tags,
   description, ID or source, and sort by default, newest, name or size.
   Published themes use a compact module-style list with thumbnails; tapping
   one opens a detail page with all screenshots, full Markdown description,
   changelog, metadata and the download/apply action. Both admin lists also
   have search fields.
7. The submit form can either take an existing `.sukisu` package or export the
   current device appearance as a package and upload that. Download-and-apply
   remains the normal way to apply a published theme. Theme import/export uses
   the same `.sukisu` package format and labels.

The server rejects duplicate pending IDs, uploads whose version is not newer
than the published theme, packages larger than 16 MB, source images larger than
2 MB, and submissions beyond the pending/rate/storage limits (200 submissions
per hour per IP, 35 pending submissions). Stored previews and screenshots are
WebP and count against the 1.2 GB application-level quota, which keeps a 300 MB
disk reserve.

## Markdown and site mentions

Theme `description` and `changelog` fields accept inline Markdown: bold, italic,
inline code, links and line breaks. Site mentions such as `@github`, `@gitee`,
`@bilibili`, `@coolapk`, `@telegram`, `@weibo`, `@xiaohongshu`, `@xda`,
`@youtube` and `@afdian` become links to the corresponding site. The upload
forms show mention chips, and the manager/admin cards render the same inline
formatting.

## Package format compatibility

Theme packages and catalog entries carry a `version` / `formatVersion`.
Format v1 remains importable; new exports use v2. The catalog advertises
`formatVersion`, `minFormatVersion` and `supportedFormats`, and the manager
rejects entries newer than its supported format. The upload form also sends
the validated package format and the server rejects a mismatch. v1/v2 labels
are shown in the manager, admin cards and import/export dialogs.

## Author licenses

The manager generates (or accepts) an author ID and sends it with every
submission. The first submission using an author ID is reviewed normally. When
the administrator approves it, the server stores only a SHA-256 hash of that ID
and grants it automatic publishing. Later submissions with the same ID are
validated and published immediately; no pending entry is created. Pasting an
old author ID on another device restores the same license. Administrators can
view authorized fingerprints and revoke a license in the pending/authors
sections of the console. Author IDs are bearer credentials and should be kept
private.

## Admin API

All admin routes are under `https://<mirror>/admin/api` and require Basic Auth:

- `GET /status`
- `GET /themes`
- `GET /pending`
- `POST /approve` with `{"submissionId":"..."}`
- `POST /reject` with `{"submissionId":"..."}`
- `GET /preview?path=pending/...` (also serves published previews)
- `POST /upload-theme` (trusted admin upload, publishes directly)
- `POST /delete-theme` with `{"id":"..."}`
- `POST /sync` (rebuild `catalog.json`)

Uploads from the manager always require approval. Direct uploads from the
admin console are trusted and publish immediately.
