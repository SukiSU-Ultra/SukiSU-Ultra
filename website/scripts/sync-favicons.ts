import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const srcDir = path.join(__dirname, '../favicon')
const dstDir = path.join(__dirname, '../docs/public')

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
}

function copyAll(src: string, dst: string) {
  ensureDir(dst)
  const entries = fs.readdirSync(src, { withFileTypes: true })
  let count = 0
  for (const entry of entries) {
    const s = path.join(src, entry.name)
    const d = path.join(dst, entry.name)
    if (entry.isDirectory()) {
      copyAll(s, d)
    } else if (entry.isFile()) {
      fs.copyFileSync(s, d)
      count++
    }
  }
  return count
}

if (!fs.existsSync(srcDir)) {
  console.warn('Favicons source folder not found:', srcDir)
  process.exit(0)
}

const copied = copyAll(srcDir, dstDir)
console.log(`✅ Synced ${copied} favicon file(s) from \'favicon\' to docs/public`)
