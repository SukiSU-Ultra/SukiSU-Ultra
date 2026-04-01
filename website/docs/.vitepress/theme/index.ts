// .vitepress/theme/index.ts
import DefaultTheme from 'vitepress/theme'
import { NolebaseGitChangelogPlugin } from '@nolebase/vitepress-plugin-git-changelog/client'
import 'virtual:group-icons.css'
import { h, onMounted } from 'vue'
import './style/style.css'
import ArticleShare from './components/ArticleShare.vue'
import backtotop from './components/backtotop.vue'
import '@nolebase/vitepress-plugin-git-changelog/client/style.css'

export default {
  extends: DefaultTheme,
  Layout: () => {
    return h(DefaultTheme.Layout, null, {
      'aside-outline-before': () => h(ArticleShare),
      'doc-footer-before': () => h(backtotop),
    })
  },
  enhanceApp({ app }) {
    app.use(NolebaseGitChangelogPlugin)

    // Register service worker in production for offline support and caching
    if (
      typeof window !== 'undefined' &&
      'serviceWorker' in navigator &&
      (import.meta as any).env?.PROD
    ) {
      onMounted(() => {
        navigator.serviceWorker.register('/sw.js').catch(() => {})
      })
    }
  },
}
