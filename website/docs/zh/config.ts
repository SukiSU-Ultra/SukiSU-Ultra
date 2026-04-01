import { defineConfig, type DefaultTheme } from 'vitepress'

export default defineConfig({
  lang: 'zh-Hans',
  description: '下一代 Android Root 解决方案 - Android 上的内核级的高级 root 方案',

  themeConfig: {
    nav: nav(),

    sidebar: {
      '/zh/': { base: '/zh/', items: sidebar() },
    },

    search: { options: searchOptions() },
    editLink: {
      pattern: 'https://github.com/sukisu-ultra/sukisu-ultra/edit/main/docs/:path',
      text: '在 GitHub 上编辑此页面',
    },

    docFooter: {
      prev: '上一页',
      next: '下一页',
    },

    outline: {
      label: '页面导航',
    },

    lastUpdated: {
      text: '最后更新于',
    },

    notFound: {
      title: '页面未找到',
      quote: '抱歉，我们无法找到您要查找的页面。',
      linkLabel: '前往首页',
      linkText: '带我回首页',
    },

    langMenuLabel: '多语言',
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '菜单',
    darkModeSwitchLabel: '主题',
    lightModeSwitchTitle: '切换到浅色模式',
    darkModeSwitchTitle: '切换到深色模式',
    skipToContentLabel: '跳转到内容',
  },
})

function nav(): DefaultTheme.NavItem[] {
  return [
    { text: '首页', link: '/zh/' },
    {
      text: '开始使用',
      items: [
        { text: '介绍', link: '/zh/guide/' },
        { text: '安装', link: '/zh/guide/installation' },
        { text: '集成', link: '/zh/guide/how-to-integrate' },
        { text: '兼容性', link: '/zh/guide/compatibility' },
        { text: '链接', link: '/zh/guide/links' },
        { text: '许可', link: '/zh/guide/license' },
      ],
    },
  ]
}

function sidebar(): DefaultTheme.SidebarItem[] {
  return [
    {
      text: '开始使用',
      items: [
        { text: '介绍', link: '/guide/' },
        { text: '安装', link: '/guide/installation' },
        { text: '集成', link: '/guide/how-to-integrate' },
        { text: '兼容性', link: '/guide/compatibility' },
        { text: '链接', link: '/guide/links' },
        { text: '许可', link: '/guide/license' },
      ],
    },
  ]
}

function searchOptions(): Partial<DefaultTheme.LocalSearchOptions> {
  return {
    translations: {
      button: {
        buttonText: '搜索文档',
        buttonAriaLabel: '搜索文档',
      },
      modal: {
        noResultsText: '无法找到相关结果',
        resetButtonTitle: '清除查询条件',
        footer: {
          selectText: '选择',
          navigateText: '切换',
          closeText: '关闭',
        },
      },
    },
  }
}
