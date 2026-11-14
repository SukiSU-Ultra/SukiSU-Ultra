#!/usr/bin/env bash
# Upload APKs through Telegram's HTTP Bot API without Python/Telethon.
set -euo pipefail

: "${BOT_TOKEN:?BOT_TOKEN is required}"
: "${CHAT_ID:?CHAT_ID is required}"
: "${TITLE:?TITLE is required}"
: "${VERSION:?VERSION is required}"
: "${BRANCH:?BRANCH is required}"
: "${RUN_URL:?RUN_URL is required}"

if (( $# == 0 )); then
  echo "[-] No files to upload" >&2
  exit 1
fi
if (( $# > 10 )); then
  echo "[-] Telegram media groups support at most 10 files" >&2
  exit 1
fi

for file in "$@"; do
  if [[ ! -f "$file" ]]; then
    echo "[-] File does not exist: $file" >&2
    exit 1
  fi
done

html_escape() {
  printf '%s' "$1" | jq -Rsr '@html'
}

# Keep the useful build context while staying comfortably below Telegram's
# 1024-character document-caption limit.
commit_text="$(git log -1 --format='%s by %an' "${GITHUB_SHA:-HEAD}")"
commit_text="${commit_text:0:500}"
title_html="$(html_escape "$TITLE")"
branch_html="$(html_escape "$BRANCH")"
commits_html="$(html_escape "$commit_text")"
run_url_html="$(html_escape "$RUN_URL")"

context_link=""
if [[ -n "${GITHUB_EVENT:-}" ]]; then
  context_url="$(jq -r '.compare // .head_commit.url // empty' <<<"$GITHUB_EVENT")"
  if [[ -n "$context_url" ]]; then
    context_url_html="$(html_escape "$context_url")"
    context_link="<a href=\"${context_url_html}\">Changes</a>"$'\n'
  fi
fi

caption="<b>${title_html}</b>
Branch: ${branch_html}
#ci_${VERSION}
<pre>${commits_html}</pre>
${context_link}<a href=\"${run_url_html}\">Workflow run</a>"

if [[ "$BRANCH" == "dev" ]]; then
  caption+=$'\n⚠️⚠️<b>DEV VERSION, PLEASE BACKUP BEFORE INSTALLATION</b>⚠️⚠️'
  caption+=$'\n⚠️⚠️<b>测试版，安装前请备份</b>⚠️⚠️'
fi

api="https://api.telegram.org/bot${BOT_TOKEN}"
response="$(mktemp)"
trap 'rm -f "$response"' EXIT

# IMPORTANT: do NOT use --retry-all-errors here.
# curl's generic retry re-sends the whole multipart request, but the local
# APK file streams may already be consumed by the first attempt. Telegram
# then receives attach://fileN references without the actual file data and
# replies 400 "media not found". Only retry on connection failures, which
# happen before any request body is sent.
common_args=(
  --silent --show-error --fail-with-body
  --retry 2 --retry-delay 2 --retry-connrefused
  --connect-timeout 30 --max-time 1800
  -H "Expect:"
  -o "$response"
  -F "chat_id=${CHAT_ID}"
)
if [[ -n "${MESSAGE_THREAD_ID:-}" ]]; then
  common_args+=(-F "message_thread_id=${MESSAGE_THREAD_ID}")
fi

# Helper: run curl, and on failure print the Telegram response body so the
# exact "description" shows up in the workflow log instead of only "curl: (22)".
run_curl() {
  if ! curl "${common_args[@]}" "$@"; then
    echo "[-] curl failed, Telegram response:" >&2
    jq . "$response" >&2 2>/dev/null || cat "$response" >&2
    return 1
  fi
}

if (( $# == 1 )); then
  echo "[+] Uploading 1 APK through Telegram Bot API"
  run_curl \
    -F "document=@$1;type=application/vnd.android.package-archive" \
    -F "caption=${caption}" \
    -F "parse_mode=HTML" \
    "${api}/sendDocument"
else
  upload_args=()
  json_items=()
  index=0
  last_index=$(($# - 1))

  for file in "$@"; do
    field="file${index}"
    upload_args+=(-F "${field}=@${file};type=application/vnd.android.package-archive")
    
    # 构建单个 JSON 对象项
    if (( index == last_index )); then
      json_items+=("$(jq -cn --arg attachment "attach://${field}" --arg caption "$caption" \
        '{type: "document", media: $attachment, caption: $caption, parse_mode: "HTML"}')")
    else
      json_items+=("$(jq -cn --arg attachment "attach://${field}" \
        '{type: "document", media: $attachment}')")
    fi
    ((index += 1))
  done

  media="$(printf '%s\n' "${json_items[@]}" | jq -cs '.')"

  echo "[+] Uploading $# APKs in one Telegram media group"
  run_curl \
    -F "media=${media}" \
    "${upload_args[@]}" \
    "${api}/sendMediaGroup"
fi

if ! jq -e '.ok == true' "$response" >/dev/null 2>&1; then
  echo "[-] Telegram API rejected the upload:" >&2
  jq . "$response" >&2 || cat "$response" >&2
  exit 1
fi

echo "[+] Telegram upload completed"
