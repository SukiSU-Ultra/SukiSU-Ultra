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

common_args=(
  --silent --show-error --fail-with-body
  --retry 3 --retry-delay 2 --retry-all-errors
  --connect-timeout 30 --max-time 1800
  -o "$response"
  -F "chat_id=${CHAT_ID}"
)
if [[ -n "${MESSAGE_THREAD_ID:-}" ]]; then
  common_args+=(-F "message_thread_id=${MESSAGE_THREAD_ID}")
fi

if (( $# == 1 )); then
  echo "[+] Uploading 1 APK through Telegram Bot API"
  curl "${common_args[@]}" \
    -F "document=@$1;type=application/vnd.android.package-archive" \
    -F "caption=${caption}" \
    -F "parse_mode=HTML" \
    "${api}/sendDocument"
else
  media='[]'
  upload_args=()
  index=0
  last_index=$(($# - 1))

  for file in "$@"; do
    field="file${index}"
    upload_args+=(-F "${field}=@${file};type=application/vnd.android.package-archive")
    if (( index == last_index )); then
      media="$(jq -cn \
        --argjson current "$media" \
        --arg attachment "attach://${field}" \
        --arg caption "$caption" \
        '$current + [{type: "document", media: $attachment, caption: $caption, parse_mode: "HTML"}]')"
    else
      media="$(jq -cn \
        --argjson current "$media" \
        --arg attachment "attach://${field}" \
        '$current + [{type: "document", media: $attachment}]')"
    fi
    ((index += 1))
  done

  echo "[+] Uploading $# APKs in one Telegram media group"
  curl "${common_args[@]}" \
    -F "media=${media}" \
    "${upload_args[@]}" \
    "${api}/sendMediaGroup"
fi

if ! jq -e '.ok == true' "$response" >/dev/null; then
  echo "[-] Telegram API rejected the upload:" >&2
  jq . "$response" >&2 || cat "$response" >&2
  exit 1
fi

echo "[+] Telegram upload completed"
