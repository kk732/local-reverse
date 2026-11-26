// 逆向工具箱：在手机上看 APK 的包名、权限、加固、框架和签名，不用电脑。
import { execFile } from 'node:child_process'
import { readdirSync, statSync, existsSync, readFileSync, rmSync, mkdirSync } from 'node:fs'
import { writeFile, unlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getConfig } from './config.js'

export const name = 'local-reverse'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(HERE, '..', 'bin', 'apk_info.py')
const CLASS_SCRIPT = join(HERE, '..', 'bin', 'dex_classes.py')
const STRINGS_SCRIPT = join(HERE, '..', 'bin', 'dex_strings.py')
const CRYPTO_SCRIPT = join(HERE, '..', 'bin', 'crypto_scan.py')
const TRY_SCRIPT = join(HERE, '..', 'bin', 'crypto_try.py')
const CODE_MAX = 8000
const VIEW_MAX = 3500
const MAX_APK_BYTES = 400 * 1024 * 1024

const selected = new Map() // sessionId -> 绝对路径
const cache = new Map() // path:mtime -> 解析结果

function zhOf(locale) {
  return !String(locale).startsWith('en')
}

function sizeText(bytes) {
  if (!Number.isFinite(bytes)) return '—'
  if (bytes > 1024 * 1024 * 1024) return `${(bytes / 1023 ** 3).toFixed(1)} GB`
  if (bytes > 1024 * 1024) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${Math.max(1, Math.round(bytes / 1024))} KB`
}

function listApks() {
  const cfg = getConfig()
  const out = []
  const seen = new Set()
  for (const dir of cfg.dirs) {
    let names = []
    try {
      if (!existsSync(dir)) continue
      names = readdirSync(dir)
    } catch {
      continue
    }
    for (const raw of names) {
      if (!/\.apk$/i.test(raw)) continue
      const path = join(dir, raw)
      let st
      try {
        st = statSync(path)
      } catch {
        continue
      }
      if (!st.isFile() || st.size < 4096) continue
      if (seen.has(path)) continue
      seen.add(path)
      out.push({ path, name: raw, size: st.size, mtime: st.mtimeMs })
    }
  }
  out.sort((a, b) => b.mtime - a.mtime)
  return out
}

function analyze(path) {
  const cfg = getConfig()
  let key = path
  try {
    key = `${path}:${statSync(path).mtimeMs}`
  } catch {
    // 文件没了就照常报错
  }
  if (cache.has(key)) return Promise.resolve(cache.get(key))
  return new Promise((resolve, reject) => {
    execFile(
      cfg.python,
      [SCRIPT, path],
      { timeout: 180_000, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => {
        if (err && !stdout) return reject(new Error(err.killed ? '解析超时' : '解析失败'))
        let data
        try {
          data = JSON.parse(String(stdout).trim().split('\n').pop())
        } catch {
          return reject(new Error('解析结果看不懂'))
        }
        if (!data.ok) return reject(new Error(data.error || '解析失败'))
        data.mtime = key.split(':').pop()
        if (cache.size > 12) cache.clear()
        cache.set(key, data)
        resolve(data)
      },
    )
  })
}

function runPython(script, args, timeout = 180_000) {
  const cfg = getConfig()
  return new Promise((resolve, reject) => {
    execFile(cfg.python, [script, ...args], { timeout, maxBuffer: 32 * 1024 * 1024 }, (err, stdout) => {
      if (err && !stdout) return reject(new Error(err.killed ? '超时' : '脚本失败'))
      let data
      try {
        data = JSON.parse(String(stdout).trim().split('\n').pop())
      } catch {
        return reject(new Error('输出看不懂'))
      }
      if (!data.ok) return reject(new Error(data.error || '脚本报错'))
      resolve(data)
    })
  })
}

// apktool 解包：mode=res 只出资源和清单，mode=src 只出 smali
function apktoolDecode(apkPath, mode) {
  const cfg = getConfig()
  const base = String(apkPath.split('/').pop() || 'apk').replace(/\.apk$/i, '').replace(/[^\w.\-]/g, '_').slice(0, 40)
  const out = join(cfg.outDir, `${base}-${mode === 'src' ? 'smali' : 'res'}`)
  return new Promise((resolve, reject) => {
    mkdirSync(cfg.outDir, { recursive: true })
    execFile(
      `${cfg.javaHome}/bin/java`,
      ['-Xmx700m', '-jar', cfg.apktool, 'd', '-f', '--no-assets', mode === 'src' ? '-r' : '-s', '-o', out, apkPath],
      { timeout: 600_000, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const log = `${stdout || ''}\n${stderr || ''}`
        if (err && !/Androguard|Copying|I: /.test(log)) {
          return reject(new Error(String(err.message || 'apktool 失败').slice(0, 60)))
        }
        const manifest = join(out, 'AndroidManifest.xml')
        resolve({ out, manifest: existsSync(manifest) ? readFileSync(manifest, 'utf8') : '' })
      },
    )
  })
}

// 整包导出 Java 源码：jadx 全量跑，输出到 Download/DSH-Go/re/<包名>-java
function exportJava(apkPath, onProgress) {
  const cfg = getConfig()
  const base = String(apkPath.split('/').pop() || 'apk').replace(/\.apk$/i, '').replace(/[^\w.\-]/g, '_').slice(0, 40)
  const out = join(cfg.outDir, `${base}-java`)
  mkdirSync(cfg.outDir, { recursive: true })
  rmSync(out, { recursive: true, force: true })
  let files = 0
  const tick = setInterval(() => {
    try {
      files = countJava(out)
      onProgress?.(files)
    } catch { /* 目录还没建好 */ }
  }, 2000)
  return new Promise((resolve, reject) => {
    execFile(
      cfg.jadx,
      ['-d', out, '--no-res', '-j', '2', apkPath],
      {
        timeout: 1_500_000,
        maxBuffer: 8 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${cfg.javaHome}/bin:${process.env.PATH || ''}`,
          JAVA_OPTS: '-Xmx900m -XX:+UseSerialGC',
        },
      },
      (err) => {
        clearInterval(tick)
        files = countJava(out)
        if (!files) {
          return reject(new Error(err ? String(err.message || '导出失败').slice(0, 50) : '没有导出文件'))
        }
        resolve({ out, files })
      },
    )
  })
}

function countJava(dir) {
  let n = 0
  const walk = (p) => {
    let list = []
    try {
      list = readdirSync(p, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of list) {
      if (e.isDirectory()) walk(join(p, e.name))
      else if (e.name.endsWith('.java')) n += 1
    }
  }
  walk(dir)
  return n
}

const cryptoText = (scan, tried) => {
  const out = []
  const algos = scan.algorithms || []
  out.push('【算法 · ' + algos.length + ' 种】')
  out.push(algos.length ? algos.map((a) => a.name + '×' + a.count).join('  ') : '没扫到加密 API 调用')
  const modes = scan.modes || []
  if (modes.length) {
    out.push('')
    out.push('【模式/填充】')
    out.push(modes.slice(0, 8).map((m) => m.name).join('  '))
  }
  const keys = scan.keys || []
  out.push('')
  out.push('【候选 key · ' + keys.length + ' 个，猜测】')
  out.push(keys.length ? keys.slice(0, 8).join('\n') : '没有像 key 的常量')
  const ent = scan.entropy || []
  if (ent.length) {
    out.push('')
    out.push('【高熵资源 · 可能是加密载荷】')
    out.push(ent.slice(0, 6).map((e) => e.name + '  ' + e.entropy).join('\n'))
  }
  const sus = scan.suspect || []
  if (sus.length) {
    out.push('')
    out.push('【可疑资源 · ' + sus.length + ' 个】')
    out.push(sus.slice(0, 6).map((x) => x.name).join('\n'))
  }
  out.push('')
  if (!tried) {
    out.push('【试解密】准备中…')
  } else if (!tried.ok) {
    out.push('【试解密】跑不起来：' + (tried.error || '未知错误'))
  } else {
    out.push('【试解密】' + tried.files + ' 个文件 × ' + tried.keys + ' 个 key，' + tried.attempts + ' 次尝试')
    if (tried.hits?.length) {
      out.push(tried.hits.map((h) => '解开：' + h.file + ' → ' + h.magic + '（' + h.mode + '，key ' + h.key + '）').join('\n'))
    } else {
      out.push('没解开。常见原因：key 藏在 so 里、key 做过分段变换、或者只是普通压缩数据。')
    }
  }
  return out.join('\n')
}

const classCache = new Map() // apk 路径 -> 类名数组

async function classesOf(apkPath) {
  if (classCache.has(apkPath)) return classCache.get(apkPath)
  const data = await runPython(CLASS_SCRIPT, [apkPath, '--limit', '400000'])
  const list = data.classes || []
  if (classCache.size > 6) classCache.clear()
  classCache.set(apkPath, list)
  return list
}

function shortName(full) {
  const i = full.lastIndexOf('.')
  return i < 0 ? full : full.slice(i + 1)
}

// 用 jadx 把一个类反编译成 Java；返回 { code, file }
function decompileClass(apkPath, cls) {
  const cfg = getConfig()
  return new Promise((resolve, reject) => {
    const out = join(tmpdir(), `dsh-jadx-${Date.now()}`)
    const target = `${shortName(cls).replace(/[^\w$]/g, '_')}.java`
    execFile(
      cfg.jadx,
      ['--single-class', cls, '--single-class-output', join(out, target), '-r', '-d', out, apkPath],
      {
        timeout: 240_000,
        maxBuffer: 4 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${cfg.javaHome}/bin:${process.env.PATH || ''}`,
          JAVA_OPTS: '-Xmx700m -XX:+UseSerialGC',
        },
      },
      (err, stdout, stderr) => {
        const file = join(out, target)
        const text = existsSync(file) ? readFileSync(file, 'utf8') : ''
        if (!text) {
          const why = String(stderr || (err && err.message) || '没有输出').split('\n').filter(Boolean).slice(-1)[0]
          return reject(new Error(why ? why.slice(0, 60) : '反编译失败'))
        }
        try { rmSync(out, { recursive: true, force: true }) } catch { /* 清不掉就算了 */ }
        resolve({ code: text, file })
      },
    )
  })
}

function detailData(apk, en) {
  const dash = (v) => (v === null || v === undefined || v === '' ? '—' : String(v))
  const head = `${apk.package}`
  const sub = `v${dash(apk.versionName)} (${dash(apk.versionCode)}) · ${sizeText(apk.size)}`
  const kv = [
    ['SDK', `min ${dash(apk.minSdk)} / target ${dash(apk.targetSdk)}`],
    ['dex', `${apk.dex} 个 · ${apk.dexClasses} 个类`],
    ['架构', apk.abis.length ? apk.abis.join(', ') : '无 so'],
    ['加固', apk.packers.length ? apk.packers.join('、') : '未见常见加固'],
    ['框架', apk.frameworks.length ? apk.frameworks.join('、') : '原生'],
    ['签名', apk.sig.length ? apk.sig.join(' + ') : '无签名信息'],
    ['组件', `${apk.counts.activity} activity · ${apk.counts.service} service · ${apk.counts.receiver} receiver`],
    ['可调试', apk.debuggable ? '是' : '否'],
  ]
  if (apk.exported) kv.push(['导出组件', `${apk.exported} 个`])
  if (apk.cleartext !== null && apk.cleartext !== undefined) kv.push(['明文流量', apk.cleartext ? '允许' : '禁止'])

  const shown = apk.perms.filter((p) => p.startsWith('android.permission.') || p.startsWith('com.android.'))
  const perms = shown.slice(0, 24).map((p) => ({
    title: p.replace('android.permission.', ''),
    subtitle: apk.dangerPerms.includes(p) ? (en ? 'Dangerous' : '敏感权限') : undefined,
    tone: apk.dangerPerms.includes(p) ? 'warn' : undefined,
  }))
  if (shown.length > perms.length) {
    perms.push({ title: `…还有 ${shown.length - perms.length} 个`, tone: 'muted' })
  }
  const notes = []
  if (en) {
    notes.push(`${apk.size > 20 * 1024 * 1024 ? 'Large APK, static parse only. ' : ''}${apk.soCount} native libs`)
  } else {
    notes.push(`${apk.size > 20 * 1024 * 1024 ? 'APK 偏大，静态看会慢一点。' : ''}so ${apk.soCount} 个`)
    if (apk.junk.length) notes.push(`包内还嵌了：${apk.junk.join('、')}`)
    if (apk.certs.length) notes.push(`可疑证书文件：${apk.certs.join('、')}`)
  }
  return {
    head,
    sub,
    kv: kv.map(([label, value]) => ({ label, value })),
    perms,
    note: notes.join(' '),
    sha: apk.sha256.slice(0, 16),
    path: apk.path,
    name: apk.name,
  }
}

function reportText(apk, en) {
  const d = detailData(apk, en)
  const lines = [
    `${en ? 'APK report' : 'APK 体检'}：${apk.name}`,
    `包名 ${apk.package}  v${apk.versionName} (${apk.versionCode})  ${sizeText(apk.size)}`,
    ...d.kv.map((r) => `${r.label}: ${r.value}`),
    `SHA-256 ${apk.sha256}`,
    `${en ? 'Permissions' : '权限'} (${apk.perms.length})：`,
    ...apk.perms.map((p) => `  ${p}${apk.dangerPerms.includes(p) ? (en ? '  [danger]' : '  [敏感]') : ''}`),
  ]
  return lines.join('\n')
}

export function apply(ctx) {
  ctx.inject(['dshGo'], (ctx) => {
    const sid = (scope) => scope?.sessionId || '_'
    const current = new Map() // sessionId -> { apk, en }，给「复制报告」用

    // 输入框上方的按钮：直接开工具箱
    ctx.dshGo.on('open-box', () => ({ open: 'panel:apk-list' }))

    // 加号面板：选一个 APK 来体检
    // 同一个 id 两种情形：点按发起选择，选完回来处理文件
    ctx.dshGo.on('scan-apk', async (scope, event) => pickOrHandle(scope, event))

    const pickOrHandle = async (scope, event) => {
      if (!event?.value) return { type: 'pickFile', action: 'scan-apk', maxFiles: 1 }
      const en = zhOf(event?.locale)
      const value = event?.value
      if (!value || value.status !== 'selected') {
        return { toast: en ? 'Nothing picked' : '没有选中文件' }
      }
      const file = (value.files || [])[0]
      if (!file) return { toast: en ? 'Nothing picked' : '没有选中文件' }
      if (file.bytes > MAX_APK_BYTES) return { toast: en ? 'APK too large' : 'APK 太大了，先传到电脑上看' }
      let buf
      try {
        buf = await ctx.dshGo.readPickedFile(file.handle)
      } catch {
        return { toast: en ? 'Cannot read the file; put it in Download' : '读不到这个文件，放到 Download 再试' }
      }
      const tmp = join(tmpdir(), `dsh-apk-${Date.now()}.apk`)
      try {
        await writeFile(tmp, buf)
        selected.set(sid(scope), tmp)
        const data = await analyze(tmp)
        if (data.name === tmp.split('/').pop()) data.name = file.name || data.name
        selected.set(sid(scope), tmp)
        return { open: 'panel:apk-detail', toast: en ? `${data.package} ready` : `${data.package} 看好了` }
      } catch (err) {
        await unlink(tmp).catch(() => {})
        return { toast: `解析失败：${String(err.message || err).slice(0, 30)}` }
      }
    }

    const listPanel = {
      view: (scope, caps) => ({
        type: 'stack',
        children: [
          { type: 'text', text: { $: 'data.hint' }, tone: 'muted' },
          { type: 'list', items: { $: 'data.items' } },
          {
            type: 'actions',
            items: [
              { label: '刷新', action: 'refresh', icon: 'refresh' },
              { label: '选 APK', action: 'pick', icon: 'folder', style: 'primary' },
            ],
          },
        ],
      }),
      data: (scope, emit) => {
        const push = () => {
          const apks = listApks()
          emit({
            hint: apks.length ? `Download 里 ${apks.length} 个 APK，点一个体检` : 'Download 里还没有 APK',
            items: apks.slice(0, 40).map((a) => ({
              title: a.name,
              subtitle: sizeText(a.size),
              icon: 'file',
              action: { id: 'open', args: { path: a.path } },
            })),
          })
        }
        push()
        return () => {}
      },
      actions: {
        refresh: () => ({ refresh: true, toast: '已刷新' }),
        pick: (scope, event) => pickOrHandle(scope, event),
        open: (scope, event) => {
          const path = event?.value?.path || event?.value?.args?.path
          if (!path) return { toast: '打不开这个文件' }
          selected.set(sid(scope), path)
          return { open: 'panel:apk-detail' }
        },
      },
    }

    const jobs = new Map() // sessionId -> { busy, text, out, manifest }
    const doc = new Map() // sessionId -> { head, text } 给代码面板看清单/日志

    const detailPanel = {
      view: (scope, caps) => ({
        type: 'stack',
        children: [
          { type: 'text', text: { $: 'data.head' }, style: { size: 'title', weight: 'bold' } },
          { type: 'text', text: { $: 'data.sub' }, tone: 'muted' },
          { type: 'keyValue', items: { $: 'data.kv' } },
          { type: 'text', text: '权限', style: { weight: 'bold' } },
          { type: 'list', items: { $: 'data.perms' } },
          { type: 'callout', text: { $: 'data.note' }, tone: 'info' },
          {
            type: 'actions',
            items: [
              { label: '复制报告', action: 'copy', icon: 'copy' },
              { label: '解包资源', action: 'unpack', icon: 'zip' },
              { label: '出 smali', action: 'smali', icon: 'code' },
            ],
          },
          {
            type: 'actions',
            items: [
              { label: '看清单', action: 'manifest', icon: 'document' },
              { label: '扫字符串', action: 'strings', icon: 'search' },
              { label: '导出源码', action: 'java', icon: 'code', style: 'primary' },
              { label: '换个 APK', action: 'back', icon: 'folder' },
            ],
          },
          {
            type: 'actions',
            items: [
              { label: '重新体检', action: 'rescan', icon: 'refresh' },
              { label: '加密扫描', action: 'crypto', icon: 'puzzle' },
            ],
          },
        ],
      }),
      data: (scope, emit, caps) => {
        const en = !zhOf(caps?.locale)
        const path = selected.get(sid(scope))
        if (!path) {
          emit({ head: en ? 'No APK yet' : '还没选 APK', sub: en ? 'Pick one in the list' : '先去列表里挑一个', kv: [], perms: [], note: '' })
          return () => {}
        }
        let alive = true
        let last = null
        const paint = () => {
          if (!alive || !last) return
          const job = jobs.get(sid(scope))
          let note = last.note || ''
          if (job) note = job.text
          emit({ ...last, note })
        }
        const timer = setInterval(paint, 2500)
        analyze(path)
          .then((apk) => {
            if (!alive) return
            const d = detailData(apk, en)
            current.set(sid(scope), { apk, en })
            last = { head: d.head, sub: d.sub, kv: d.kv, perms: d.perms, note: d.note }
            paint()
          })
          .catch((err) => {
            if (!alive) return
            last = { head: en ? 'Parse failed' : '解析失败', sub: String(err.message || err).slice(0, 60), kv: [], perms: [], note: '' }
            paint()
          })
        return () => {
          alive = false
          clearInterval(timer)
        }
      },
      actions: {
        copy: (scope, event) => {
          const en = !zhOf(event?.locale)
          const cur = current.get(sid(scope))
          if (!cur) return { toast: en ? 'Nothing to copy yet' : '还没解析完' }
          return { copy: reportText(cur.apk, en), toast: en ? 'Report copied' : '报告已复制' }
        },
        rescan: () => ({ refresh: true, toast: '重新解析中' }),
        back: () => ({ open: 'panel:apk-list' }),
        strings: (scope, event) => {
          const en = !zhOf(event?.locale)
          const path = selected.get(sid(scope))
          if (!path) return { toast: en ? 'Pick an APK first' : '先选一个 APK' }
          const key = sid(scope)
          jobs.set(key, { busy: true, text: '扫字符串中…' })
          runPython(STRINGS_SCRIPT, [path, '--limit', '40'], 120_000)
            .then((d) => {
              jobs.delete(key)
              if (!d.groups?.length) {
                doc.set(key, { head: '字符串线索', hint: '从 dex 字符串池里筛出来的', text: '没扫到 URL、密钥之类的线索' })
              } else {
                const lines = d.groups.map((g) => `【${g.name}·${g.total}】\n${g.items.join('\n')}`)
                doc.set(key, { head: `字符串线索（共 ${d.total} 条）`, hint: '从 dex 字符串池里筛出来的', text: lines.join('\n\n') })
              }
            })
            .catch((err) => jobs.set(key, { busy: false, text: `扫描失败：${String(err.message || err).slice(0, 40)}` }))
          return { open: 'panel:code', toast: en ? 'Scanning strings' : '正在扫字符串' }
        },
        crypto: (scope, event) => {
          const en = !zhOf(event?.locale)
          const path = selected.get(sid(scope))
          if (!path) return { toast: en ? 'Pick an APK first' : '先选一个 APK' }
          const key = sid(scope)
          doc.delete(key)
          jobs.set(key, { busy: true, text: '扫加密线索…' })
          runPython(CRYPTO_SCRIPT, [path, '--limit', '20'], 120_000)
            .then((scan) => {
              doc.set(key, { head: '加密线索', hint: '先扫，再试解密', text: cryptoText(scan, null) })
              jobs.set(key, { busy: true, text: '试着解密…' })
              return runPython(TRY_SCRIPT, [path, '--limit', '12'], 300_000).then((tried) => {
                const n = tried.hits?.length || 0
                jobs.set(key, { busy: false, text: n ? `解开了 ${n} 个文件` : '没解开，key 可能藏在 so 里' })
                doc.set(key, { head: '加密线索', hint: '先扫，再试解密', text: cryptoText(scan, tried) })
              })
            })
            .catch((err) => jobs.set(key, { busy: false, text: `扫描失败：${String(err.message || err).slice(0, 40)}` }))
          return { open: 'panel:code', toast: en ? 'Scanning, then trying keys' : '先扫，再试解密' }
        },
        java: (scope, event) => {
          const en = !zhOf(event?.locale)
          const key = sid(scope)
          const path = selected.get(key)
          if (!path) return { toast: en ? 'Pick an APK first' : '先选一个 APK' }
          const job = jobs.get(key)
          if (job?.busy) return { toast: en ? 'Still running' : '还在跑，等它做完' }
          if (!existsSync(getConfig().jadx)) return { toast: 'jadx 没装好' }
          const t0 = Date.now()
          jobs.set(key, { busy: true, text: '导出 Java 源码中…刚开始要几十秒才出文件' })
          doc.delete(key)
          exportJava(path, (n) => {
            jobs.set(key, { busy: true, text: `导出中…已写 ${n} 个 .java` })
          })
            .then((r) => {
              const secs = Math.round((Date.now() - t0) / 1000)
              jobs.set(key, { busy: false, text: `导出完成：${r.files} 个 Java 文件，${secs} 秒` })
              doc.set(key, {
                head: `Java 源码 · ${r.files} 个文件`,
                hint: `${secs} 秒导完，目录在手机里`,
                text: `目录：${r.out}\n类文件：${r.files}\n耗时：${secs} 秒\n\n用文件管理器进这个目录就能逐个看；\n也可以点「搜类」按关键词找类，\n或者把某个类名发给我，我帮你读。`,
              })
            })
            .catch((err) => {
              jobs.set(key, { busy: false, text: `导出失败：${String(err.message || err).slice(0, 40)}` })
            })
          return { toast: en ? 'Exporting sources' : '开始导出，进度看详情面板' }
        },
        unpack: (scope) => startDecode(scope, 'res'),
        smali: (scope) => startDecode(scope, 'src'),
        manifest: (scope, event) => {
          const en = !zhOf(event?.locale)
          const job = jobs.get(sid(scope))
          if (!job?.manifest) return { toast: en ? 'Decode first' : '先点「解包资源」' }
          doc.set(sid(scope), { head: 'AndroidManifest.xml', hint: 'apktool 解码后的清单', text: job.manifest })
          return { open: 'panel:code' }
        },
      },
    }

    const startDecode = (scope, mode) => {
      const key = sid(scope)
      const path = selected.get(key)
      if (!path) return { toast: '先选一个 APK' }
      const running = jobs.get(key)
      if (running && running.busy) return { toast: '还在解包，等它做完' }
      if (!existsSync(getConfig().apktool)) return { toast: 'apktool 没装好' }
      const label = mode === 'src' ? '导出 smali' : '解包资源'
      const job = { busy: true, text: `${label}中…大的包要一两分钟` }
      jobs.set(key, job)
      apktoolDecode(path, mode)
        .then((r) => {
          jobs.set(key, { busy: false, manifest: r.manifest, out: r.out, text: `${label}完成：${r.out}` })
        })
        .catch((err) => {
          jobs.set(key, { busy: false, text: `${label}失败：${String(err.message || err).slice(0, 40)}` })
        })
      return { toast: `${label}开始了` }
    }

    // ---- 搜类 + 反编译 ----
    const found = new Map() // sessionId -> { apk, kw, matched, classes }
    const target = new Map() // sessionId -> { apk, cls }

    const searchClasses = async (scope, kw) => {
      const en = !zhOf(scope?.locale)
      const sid0 = sid(scope)
      let apk = selected.get(sid0)
      if (!apk || !existsSync(apk)) {
        const newest = listApks()[0]
        if (!newest) return { toast: en ? 'No APK in Download' : 'Download 里没有 APK' }
        apk = newest.path
        selected.set(sid0, apk)
      }
      if (!existsSync(getConfig().jadx)) return { toast: en ? 'jadx missing' : '反编译器没装好' }
      let all
      try {
        all = await classesOf(apk)
      } catch (err) {
        return { toast: `读类名失败：${String(err.message || err).slice(0, 24)}` }
      }
      const hit = kw ? all.filter((c) => c.toLowerCase().includes(kw.toLowerCase())) : all
      found.set(sid0, { apk, kw, matched: hit.length, classes: hit.slice(0, 60) })
      return { open: 'panel:class-list', toast: en ? `${hit.length} classes` : `命中 ${hit.length} 个类` }
    }

    // 输入框上方的按钮：拿输入框里的词去搜类
    ctx.dshGo.on('find-class', (scope) => {
      const kw = String(scope?.draft || '').trim()
      if (!kw) {
        return { toast: zhOf(scope?.locale) ? '先在输入框写个类名关键词，比如 Activity' : 'Type a class keyword first' }
      }
      return searchClasses(scope, kw)
    })

    const classPanel = {
      view: () => ({
        type: 'stack',
        children: [
          { type: 'text', text: { $: 'data.head' }, style: { size: 'title', weight: 'bold' } },
          { type: 'text', text: { $: 'data.hint' }, tone: 'muted' },
          { type: 'list', items: { $: 'data.items' } },
          {
            type: 'actions',
            items: [
              { label: '复制名单', action: 'copyList', icon: 'copy' },
              { label: '换个 APK', action: 'pick', icon: 'folder' },
            ],
          },
        ],
      }),
      data: (scope, emit) => {
        const en = !zhOf(emit?.locale)
        const f = found.get(sid(scope))
        if (!f) {
          emit({ head: en ? 'Search a class' : '还没搜过', hint: en ? 'Type a keyword, then tap the class chip' : '在输入框写个词，再点胶囊里的「搜类」', items: [] })
          return () => {}
        }
        const pkgOf = (c) => (c.includes('.') ? c.slice(0, c.lastIndexOf('.')) : '')
        emit({
          head: f.kw ? `“${f.kw}” · ${f.matched} 个类` : `全部 ${f.matched} 个类`,
          hint: en ? 'Tap one to decompile' : '点一个反编译成 Java，慢的类要等十几秒',
          items: f.classes.map((c) => ({
            title: shortName(c),
            subtitle: pkgOf(c),
            icon: 'code',
            action: { id: 'klass', args: { name: c } },
          })),
        })
        return () => {}
      },
      actions: {
        copyList: (scope) => {
          const f = found.get(sid(scope))
          if (!f) return { toast: '还没有结果' }
          return { copy: f.classes.join('\n'), toast: '类名已复制' }
        },
        pick: (scope, event) => pickOrHandle(scope, event),
        klass: (scope, event) => {
          const name = event?.value?.name || event?.value?.args?.name
          if (!name) return { toast: '这个类名丢了' }
          const apk = found.get(sid(scope))?.apk
          if (!apk) return { toast: '先搜一次类' }
          doc.delete(sid(scope))
          target.set(sid(scope), { apk, cls: name })
          return { open: 'panel:code' }
        },
      },
    }

    const codePanel = {
      view: () => ({
        type: 'stack',
        children: [
          { type: 'text', text: { $: 'data.head' }, style: { size: 'title', weight: 'bold' } },
          { type: 'text', text: { $: 'data.hint' }, tone: 'muted' },
          { type: 'text', text: { $: 'data.code' }, style: { size: 'small' } },
          {
            type: 'actions',
            items: [
              { label: '复制代码', action: 'copyCode', icon: 'copy', style: 'primary' },
              { label: '返回列表', action: 'back', icon: 'list' },
            ],
          },
        ],
      }),
      data: (scope, emit) => {
        const d = doc.get(sid(scope))
        if (d) {
          emit({ head: d.head, hint: d.hint || '', code: d.text.slice(0, VIEW_MAX) })
          return () => {}
        }
        const t = target.get(sid(scope))
        if (!t) {
          const key = sid(scope)
          emit({ head: '准备中…', hint: '', code: '' })
          let ticks = 0
          const poll = setInterval(() => {
            ticks += 1
            const j = jobs.get(key)
            if (doc.has(key)) {
              clearInterval(poll)
              const d = doc.get(key)
              emit({ head: d.head, hint: d.hint || '', code: d.text.slice(0, VIEW_MAX) })
            } else if (j?.busy && ticks < 40) {
              emit({ head: '进行中…', hint: j.text, code: '' })
            } else {
              clearInterval(poll)
              emit({ head: '没有选中类', hint: j?.text || '先在列表里挑一个类', code: '' })
            }
          }, 1200)
          return () => clearInterval(poll)
        }
        let alive = true
        emit({ head: shortName(t.cls), hint: '正在反编译，大的 APK 要等十几秒…', code: '' })
        decompileClass(t.apk, t.cls)
          .then((r) => {
            if (!alive) return
            const lines = r.code.split('\n').length
            const cut = r.code.length > VIEW_MAX
            emit({
              head: shortName(t.cls),
              hint: `Java · ${lines} 行${cut ? ' · 太长只显示前面部分' : ''}`,
              code: cut ? `${r.code.slice(0, VIEW_MAX)}\n// …截断` : r.code,
            })
            target.set(sid(scope), { ...t, code: r.code })
          })
          .catch((err) => {
            if (!alive) return
            emit({ head: shortName(t.cls), hint: `反编译失败：${String(err.message || err).slice(0, 50)}`, code: '' })
          })
        return () => {
          alive = false
        }
      },
      actions: {
        copyCode: (scope) => {
          const d = doc.get(sid(scope))
          if (d) return { copy: d.text.slice(0, CODE_MAX * 2), toast: '已复制' }
          const t = target.get(sid(scope))
          if (!t?.code) return { toast: '还没反编译完' }
          return { copy: t.code.slice(0, CODE_MAX), toast: '代码已复制' }
        },
        back: () => ({ open: 'panel:class-list' }),
      },
    }

    ctx.dshGo.panel('apk-list', listPanel)
    ctx.dshGo.panel('apk-detail', detailPanel)
    ctx.dshGo.panel('class-list', classPanel)
    ctx.dshGo.panel('code', codePanel)
  })
}
