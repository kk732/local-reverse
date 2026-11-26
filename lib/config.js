// 路径与外部工具解析：优先环境变量，其次配置文件，最后自动探测。
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { delimiter, join } from 'node:path'

const DEFAULTS = {
  dirs: ['/sdcard/Download', '/sdcard/Download/DSH-Go', '/sdcard/APK'],
  outDir: '/sdcard/Download/DSH-Go/re',
  jadx: ['/opt/jadx/bin/jadx', '/usr/local/bin/jadx', '/usr/bin/jadx'],
  apktool: ['/opt/apktool/apktool.jar', '/usr/share/apktool/apktool.jar', '/usr/local/share/apktool/apktool.jar'],
}

function firstExisting(list) {
  for (const p of list || []) {
    if (p && existsSync(p)) return p
  }
  return null
}

function which(bin) {
  for (const dir of (process.env.PATH || '').split(delimiter)) {
    if (!dir) continue
    const p = join(dir, bin)
    if (existsSync(p)) return p
  }
  return null
}

function configPath() {
  return process.env.DSH_RE_CONFIG || join(process.env.DSH_HOME || join(homedir(), '.dsh'), 're-kit.json')
}

function readFileConfig() {
  const p = configPath()
  try {
    if (!existsSync(p)) return {}
    return JSON.parse(readFileSync(p, 'utf8')) || {}
  } catch {
    return {}
  }
}

function detectJavaHome() {
  const env = process.env.JAVA_HOME
  if (env && existsSync(join(env, 'bin', 'java'))) return env
  const home = process.env.HOME || homedir()
  const bases = ['/usr/lib/jvm', join(home, 'java'), '/opt/java', '/Library/Java/JavaVirtualMachines']
  for (const base of bases) {
    let names = []
    try {
      names = readdirSync(base)
    } catch {
      continue
    }
    for (const n of names) {
      const p = join(base, n)
      if (existsSync(join(p, 'bin', 'java'))) return p
      if (existsSync(join(p, 'Contents', 'Home', 'bin', 'java'))) return join(p, 'Contents', 'Home')
    }
  }
  return null
}

function pickDirs(file) {
  const fromEnv = process.env.DSH_RE_DIRS
  if (fromEnv) return fromEnv.split(delimiter).filter(Boolean)
  if (Array.isArray(file.dirs) && file.dirs.length) return file.dirs
  const phone = DEFAULTS.dirs.filter((d) => existsSync(d))
  if (phone.length) return phone
  const generic = [join(homedir(), 'Downloads'), join(homedir(), 'Download'), process.cwd()].filter((d) =>
    existsSync(d),
  )
  return generic.length ? generic : [process.cwd()]
}

function pickOutDir(file) {
  if (process.env.DSH_RE_OUT) return process.env.DSH_RE_OUT
  if (file.outDir) return file.outDir
  if (existsSync('/sdcard/Download')) return DEFAULTS.outDir
  return join(process.env.DSH_HOME || join(homedir(), '.dsh'), 're-kit', 'out')
}

export function loadConfig() {
  const file = readFileConfig()
  return {
    configPath: configPath(),
    dirs: pickDirs(file),
    outDir: pickOutDir(file),
    jadx: process.env.DSH_RE_JADX || file.jadx || which('jadx') || firstExisting(DEFAULTS.jadx),
    apktool: process.env.DSH_RE_APKTOOL || file.apktool || firstExisting(DEFAULTS.apktool),
    javaHome: file.javaHome || detectJavaHome(),
    python: process.env.DSH_RE_PYTHON || file.python || which('python3') || 'python3',
  }
}

let cached = null
export function getConfig() {
  if (!cached) cached = loadConfig()
  return cached
}
export function resetConfig() {
  cached = null
}
