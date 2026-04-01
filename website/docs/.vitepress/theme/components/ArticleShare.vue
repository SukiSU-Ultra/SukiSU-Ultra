<script setup lang="ts">
import { ref, computed } from 'vue'
import { useData } from 'vitepress'

const props = defineProps({
  shareText: {
    type: String,
    default: undefined,
  },
  copiedText: {
    type: String,
    default: undefined,
  },
  includeQuery: {
    type: Boolean,
    default: false,
  },
  includeHash: {
    type: Boolean,
    default: false,
  },
  copiedTimeout: {
    type: Number,
    default: 2000,
  },
})

defineOptions({ name: 'ArticleShare' })

const copied = ref(false)
const isClient = typeof window !== 'undefined' && typeof document !== 'undefined'

const { theme, lang } = useData()

const defaultShareText = computed(() =>
  lang.value?.toLowerCase().startsWith('zh') ? '分享链接' : 'Share link'
)
const defaultCopiedText = computed(() =>
  lang.value?.toLowerCase().startsWith('zh') ? '已复制!' : 'Copied!'
)
const defaultCopyFailedText = computed(() =>
  lang.value?.toLowerCase().startsWith('zh') ? '复制链接失败:' : 'Failed to copy link:'
)

const i18nShareText = computed(
  () => props.shareText ?? (theme.value as any)?.articleShare?.shareText ?? defaultShareText.value
)
const i18nCopiedText = computed(
  () =>
    props.copiedText ?? (theme.value as any)?.articleShare?.copiedText ?? defaultCopiedText.value
)
const i18nCopyFailedText = computed(
  () => (theme.value as any)?.articleShare?.copyFailed ?? defaultCopyFailedText.value
)

const shareLink = computed(() => {
  if (!isClient) return ''

  const { origin, pathname, search, hash } = window.location
  const finalSearch = props.includeQuery ? search : ''
  const finalHash = props.includeHash ? hash : ''
  return `${origin}${pathname}${finalSearch}${finalHash}`
})

async function copyToClipboard() {
  if (copied.value || !isClient) return

  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(shareLink.value)
    } else {
      const input = document.createElement('input')
      input.setAttribute('readonly', 'readonly')
      input.setAttribute('value', shareLink.value)
      document.body.appendChild(input)
      input.select()
      document.execCommand('copy')
      document.body.removeChild(input)
    }

    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, props.copiedTimeout)
  } catch (error) {
    console.error(i18nCopyFailedText.value, error)
  }
}

const shareIconSvg = `
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path>
    <polyline points="16 6 12 2 8 6"></polyline>
    <line x1="12" y1="2" x2="12" y2="15"></line>
  </svg>
`

const copiedIconSvg = `
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M20 6 9 17l-5-5"></path>
  </svg>
`
</script>

<template>
  <div class="article-share">
    <button
      :class="['article-share__button', { copied: copied }]"
      :aria-label="copied ? i18nCopiedText : i18nShareText"
      aria-live="polite"
      @click="copyToClipboard"
    >
      <div v-if="!copied" class="content-wrapper">
        <span class="icon" v-html="shareIconSvg"></span>
        {{ i18nShareText }}
      </div>

      <div v-else class="content-wrapper">
        <span class="icon" v-html="copiedIconSvg"></span>
        {{ i18nCopiedText }}
      </div>
    </button>
  </div>
</template>

<style scoped>
.article-share {
  padding: 14px 0;
}

.article-share__button {
  display: flex;
  justify-content: center;
  align-items: center;
  font-weight: 500;
  font-size: 14px;
  position: relative;
  z-index: 1;
  transition: all 0.4s var(--ease-out-cubic, cubic-bezier(0.33, 1, 0.68, 1));
  cursor: pointer;
  border: 1px solid transparent;
  border-radius: 14px;
  padding: 7px 14px;
  width: 100%;
  overflow: hidden;
  color: var(--vp-c-text-1, #333);
  background-color: var(--vp-c-bg-alt, #f6f6f7);
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.02);
  will-change: transform, box-shadow;
}

.article-share__button::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  z-index: -1;
  transition: left 0.6s ease;
  background-color: var(--vp-c-brand-soft, #ddf4ff);
  width: 100%;
  height: 100%;
}

.article-share__button:hover {
  transform: translateY(-1px);
  border-color: var(--vp-c-brand-soft, #ddf4ff);
  background-color: var(--vp-c-brand-soft, #ddf4ff);
}

.article-share__button:active {
  transform: scale(0.9);
}

.article-share__button.copied {
  color: var(--vp-c-brand-1, #007acc);
  background-color: var(--vp-c-brand-soft, #ddf4ff);
}

.article-share__button.copied::before {
  left: 0;
  background-color: var(--vp-c-brand-soft, #ddf4ff);
}

.content-wrapper {
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon {
  display: inline-flex;
  align-items: center;
  margin-right: 6px;
}
</style>
