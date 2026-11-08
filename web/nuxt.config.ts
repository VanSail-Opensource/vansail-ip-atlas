import { createHash } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

function publicBuildId() {
  const root = fileURLToPath(new URL('.', import.meta.url))
  const files: string[] = []
  const visit = (directory: string) => {
    for (const item of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, item.name)
      if (item.isDirectory()) visit(path)
      else if (item.isFile()) files.push(path)
    }
  }
  visit(join(root, 'app')); visit(join(root, 'public'))
  for (const name of ['nuxt.config.ts', 'tsconfig.json', 'package.json', 'pnpm-lock.yaml']) files.push(join(root, name))
  const hash = createHash('sha256')
  for (const path of files.sort()) hash.update(relative(root, path).replaceAll('\\', '/')).update('\0').update(readFileSync(path)).update('\0')
  return hash.digest('hex').slice(0, 32)
}

export default defineNuxtConfig({
  buildId: publicBuildId(),
  debug: false,
  ssr: true,
  modules: ['@nuxt/ui', 'motion-v/nuxt'],
  css: ['~/assets/main.css'],
  devtools: { enabled: false },
  telemetry: false,
  ui: { fonts: false, theme: { colors: ['primary', 'error'] }, experimental: { componentDetection: true } },
  icon: { provider: 'none' },
  app: {
    head: {
      title: 'VanSail IP Atlas',
      htmlAttrs: { lang: 'en' },
      meta: [
        { name: 'description', content: 'IP and network intelligence. A static atlas with private, local lookups.' },
        { name: 'referrer', content: 'no-referrer' },
        { name: 'color-scheme', content: 'light dark' },
      ],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
  },
  nitro: {
    preset: 'static',
    prerender: { routes: ['/ip', '/ip/overview', '/ip/quality', '/ip/class-c', '/ip/bgp', '/ip/asn'] },
  },
  sourcemap: false,
  vite: { build: { target: 'chrome156', modulePreload: { polyfill: false } } },
  compatibilityDate: '2026-11-08',
})
