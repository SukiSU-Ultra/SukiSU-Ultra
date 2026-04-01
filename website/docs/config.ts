import { defineConfig, type DefaultTheme } from 'vitepress'
import { groupIconMdPlugin, groupIconVitePlugin } from 'vitepress-plugin-group-icons'

export default defineConfig({
  lang: 'en-US',
  description:
    'Next-Generation Android Root Solution - Advanced kernel-based root management for Android devices with KernelSU integration',

  themeConfig: {
    nav: nav(),

    sidebar: {
      '/': { base: '/', items: sidebar() },
    },

    search: { options: searchOptions() },
    editLink: {
      pattern: 'https://github.com/sukisu-ultra/sukisu-ultra/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    docFooter: {
      prev: 'Previous',
      next: 'Next',
    },

    outline: {
      label: 'On this page',
    },

    lastUpdated: {
      text: 'Last updated',
    },

    notFound: {
      title: 'Page Not Found',
      quote: "Sorry, we couldn't find what you're looking for.",
      linkLabel: 'Go to home',
      linkText: 'Take me home',
    },

    langMenuLabel: 'Languages',
    returnToTopLabel: 'Return to top',
    sidebarMenuLabel: 'Menu',
    darkModeSwitchLabel: 'Theme',
    lightModeSwitchTitle: 'Switch to light theme',
    darkModeSwitchTitle: 'Switch to dark theme',
    skipToContentLabel: 'Skip to content',
  },
})

function nav(): DefaultTheme.NavItem[] {
  return [
    { text: 'Home', link: '/' },
    {
      text: 'Getting Started',
      items: [
        { text: 'Introduction', link: '/guide/' },
        { text: 'Installation', link: '/guide/installation' },
        { text: 'Compatibility', link: '/guide/compatibility' },
        { text: 'Links', link: '/guide/links' },
        { text: 'license', link: '/guide/license' },
      ],
    },
  ]
}

function sidebar(): DefaultTheme.SidebarItem[] {
  return [
    {
      text: 'Getting Started',
      items: [
        { text: 'Introduction', link: '/guide/' },
        { text: 'Installation', link: '/guide/installation' },
        { text: 'Compatibility', link: '/guide/compatibility' },
        { text: 'Links', link: '/guide/links' },
        { text: 'license', link: '/guide/license' },
      ],
    },
  ]
}

function searchOptions(): Partial<DefaultTheme.LocalSearchOptions> {
  return {
    translations: {
      button: {
        buttonText: 'Search docs',
        buttonAriaLabel: 'Search docs',
      },
      modal: {
        noResultsText: 'No results found',
        resetButtonTitle: 'Clear query',
        footer: {
          selectText: 'Select',
          navigateText: 'Navigate',
          closeText: 'Close',
        },
      },
    },
  }
}
