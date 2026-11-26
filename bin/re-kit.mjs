#!/usr/bin/env node
// 不上 dsh-go 也能用的命令行入口：只依赖 python3，jadx/apktool 只在导出时用到。
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getConfig } from '../lib/config.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const py = (name) => join(HERE, name)

function javaEnv() {
  const cfg = getConfig()
  if (!cfg.javaHome) return process.env
  return { ...process.env, JAVA_HOME: cfg.javaHome, PATH: `${cfg.javaHome}/bin:${process.env.PATH || ''}` }
}

function run(bin, args, timeout = 300_000) {
  return new Promise((res, rej) => {
    execFile(bin, args, { timeout, maxBuffer: 64 * 1024 * 1024, env: javaEnv() }, (err, stdout, stderr) => {
      if (err && !stdout) return rej(new Error(err.killed ? 'timed out' : `command failed: ${stderr || err.message}`))
      res(String(stdout))
    })
  })
}

function runJson(script, args) {
  return run(getConfig().python, [py(script), ...args]).then((out) => {
    const line = out.trim().split('\n').pop()
    const data = JSON.parse(line)
    if (!data.ok) throw new Error(data.error || 'script error')
    return data
  })
}

function resolveApk(arg) {
  if (!arg) throw new Error('missing <apk> argument')
  if (existsSync(arg)) return resolve(arg)
  const cfg = getConfig()
  for (const dir of cfg.dirs) {
    try {
      for (const name of readdirSync(dir)) {
        if (name === arg || name.replace(/\.apk$/i, '') === arg) {
          const p = join(dir, name)
          if (/\.apk$/i.test(name) && statSync(p).isFile()) return p
        }
      }
    } catch {
      continue
    }
  }
  throw new Error(`APK not found: ${arg}`)
}

function usage() {
  console.log(`re-kit — Android APK inspection without a PC

Usage:
  re-kit list                       list APKs found in the configured folders
  re-kit info <apk>                 package id, SDK, ABI, hardening, framework, signing
  re-kit classes <apk> [keyword]    search classes in dex
  re-kit strings <apk>              URLs, keys and other leads from the dex string pool
  re-kit crypto <apk> [--try]       crypto API usage, candidate keys, optional decrypt attempt
  re-kit java <apk> [--out DIR]     decompile the whole APK to Java with jadx
  re-kit decode <apk> [--mode res|src]  apktool: resources or smali
  re-kit report <apk> [-o FILE]     write a Markdown inspection report
  re-kit diff <old.apk> <new.apk>   compare two builds of the same app
  re-kit scan [dir]                 inspect every APK in a folder, one table
  re-kit doctor                     check python / jadx / java / apktool
  re-kit config                     print the resolved config
  re-kit list --json                any command accepts --json for raw output

Config: ${getConfig().configPath} (env: DSH_RE_JADX, DSH_RE_APKTOOL, DSH_RE_DIRS, DSH_RE_OUT, JAVA_HOME)`)
}

const argv = process.argv.slice(2)
const json = argv.includes('--json')
const flag = (name) => {
  const i = argv.indexOf(name)
  if (i < 0) return null
  return argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true
}
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')))
const [cmd = 'list', a1, a2] = positional


function buildReport(d, scan) {
  const L = []
  const perm = d.perms || []
  L.push(`# ${d.package} ${d.versionName} (${d.versionCode})`)
  L.push('')
  L.push('| 项目 | 值 |')
  L.push('| --- | --- |')
  L.push(`| 签名 | ${(d.sig || []).join(' + ') || 'unknown'} |`)
  L.push(`| SHA-256 | \`${d.sha256}\` |`)
  L.push(`| SDK | min ${d.minSdk} / target ${d.targetSdk} |`)
  L.push(`| ABI | ${(d.abis || []).join(', ') || 'none'} |`)
  L.push(`| dex | ${d.dex} 个，${d.dexClasses} 个类 |`)
  L.push(`| 加固 | ${(d.packers || []).join(', ') || '未检出'} |`)
  L.push(`| 框架 | ${(d.frameworks || []).join(', ') || '原生'} |`)
  L.push('')
  L.push(`## 权限 (${perm.length})`)
  L.push('')
  for (const p of perm) L.push(`- \`${p}\`${(d.dangerPerms || []).includes(p) ? ' **[危险]**' : ''}`)
  if (scan) {
    L.push('')
    L.push('## 加密线索')
    L.push('')
    L.push(`- 算法：${((scan.algorithms || []).map((a) => `${a.name}×${a.count}`).join('，')) || '无'}`)
    L.push(`- 候选密钥：${((scan.keys || []).slice(0, 10).map((k) => `\`${k}\``).join('，')) || '无'}`)
  }
  L.push('')
  L.push(`> 由 re-kit 生成于 ${new Date().toISOString().slice(0, 19).replace('T', ' ')}`)
  return L.join('\n') + '\n'
}

function diffOne(a, b) {
  const out = []
  if (a.package !== b.package) out.push(`包名不同：${a.package} → ${b.package}`)
  if (a.versionName !== b.versionName || a.versionCode !== b.versionCode) {
    out.push(`版本：${a.versionName} (${a.versionCode}) → ${b.versionName} (${b.versionCode})`)
  }
  if (a.minSdk !== b.minSdk || a.targetSdk !== b.targetSdk) {
    out.push(`SDK：min ${a.minSdk}/target ${a.targetSdk} → min ${b.minSdk}/target ${b.targetSdk}`)
  }
  if (a.sha256 !== b.sha256) out.push('内容 SHA-256 变了')
  if ((a.sig || []).join() !== (b.sig || []).join()) {
    out.push(`签名方案：${(a.sig || []).join('+')} → ${(b.sig || []).join('+')}`)
  }
  const pa = new Set(a.perms || [])
  const pb = new Set(b.perms || [])
  const added = [...pb].filter((x) => !pa.has(x))
  const removed = [...pa].filter((x) => !pb.has(x))
  if (added.length) out.push(`新增权限 ${added.length}：\n${added.map((x) => '  + ' + x).join('\n')}`)
  if (removed.length) out.push(`移除权限 ${removed.length}：\n${removed.map((x) => '  - ' + x).join('\n')}`)
  const dk = (b.dexClasses || 0) - (a.dexClasses || 0)
  if (dk) out.push(`dex 类数 ${a.dexClasses} → ${b.dexClasses} (${dk > 0 ? '+' : ''}${dk})`)
  if ((a.packers || []).join() !== (b.packers || []).join()) {
    out.push(`加固：${(a.packers || []).join(',') || '无'} → ${(b.packers || []).join(',') || '无'}`)
  }
  return out.length ? out.join('\n') : '没有可见差异'
}

function table(rows, cols) {
  const header = cols.map((c) => c.title)
  const body = rows.map((r) => cols.map((c) => String(c.get(r) ?? '')))
  const width = header.map((_, i) =>
    Math.min(30, Math.max(1, ...body.concat([header]).map((row) => [...String(row[i])].length))),
  )
  const cut = (text, n) => {
    const chars = [...text]
    return chars.length > n ? chars.slice(0, n - 1).join('') + '…' : text
  }
  const line = (row) =>
    row
      .map((cell, i) => {
        const text = cut(String(cell), width[i])
        return text + ' '.repeat(Math.max(0, width[i] - [...text].length))
      })
      .join('  ')
  const rule = width.map((n) => '-'.repeat(n)).join('  ')
  return [line(header), rule, ...body.map(line)].join('\n')
}

async function inspect(apk) {
  return await runJson('apk_info.py', [apk])
}

async function main() {
  const cfg = getConfig()
  if (cmd === 'config') return console.log(JSON.stringify(cfg, null, 2))

  if (cmd === 'list') {
    const rows = []
    for (const dir of cfg.dirs) {
      try {
        for (const name of readdirSync(dir)) {
          if (!/\.apk$/i.test(name)) continue
          const p = join(dir, name)
          const st = statSync(p)
          if (st.isFile() && st.size > 4096) rows.push({ name, path: p, size: st.size })
        }
      } catch {
        continue
      }
    }
    if (json) return console.log(JSON.stringify(rows, null, 2))
    if (!rows.length) return console.log('no APK found in: ' + cfg.dirs.join(', '))
    for (const r of rows) console.log(`${r.name}\t${(r.size / 1024 / 1024).toFixed(1)} MB\t${r.path}`)
    return
  }

  if (cmd === 'info') {
    const apk = resolveApk(a1)
    const d = await runJson('apk_info.py', [apk])
    if (json) return console.log(JSON.stringify(d, null, 2))
    console.log(`package   ${d.package}`)
    console.log(`version   ${d.versionName} (${d.versionCode})`)
    console.log(`sdk       min ${d.minSdk} / target ${d.targetSdk}`)
    console.log(`dex       ${d.dex} dex, ${d.dexClasses} classes`)
    console.log(`abi       ${(d.abis || []).join(', ') || 'none'}`)
    console.log(`packer    ${(d.packers || []).join(', ') || 'none detected'}`)
    console.log(`framework ${(d.frameworks || []).join(', ') || 'native'}`)
    console.log(`signature ${(d.sig || []).join(' + ') || 'unknown'}`)
    console.log(`sha256    ${d.sha256}`)
    console.log(`permissions (${(d.perms || []).length}):`)
    for (const p of d.perms || []) console.log(`  ${p}${(d.dangerPerms || []).includes(p) ? '  [danger]' : ''}`)
    return
  }

  if (cmd === 'classes') {
    const apk = resolveApk(a1)
    const kw = a2 || (flag('--match') === true ? '' : flag('--match') || '')
    const d = await runJson('dex_classes.py', [apk, '--limit', '400000'])
    const all = d.classes || []
    const hit = kw ? all.filter((c) => c.toLowerCase().includes(String(kw).toLowerCase())) : all
    if (json) return console.log(JSON.stringify({ total: all.length, matched: hit.length, classes: hit }, null, 2))
    console.log(`${hit.length} / ${all.length} classes${kw ? ` matching "${kw}"` : ''}`)
    for (const c of hit.slice(0, 200)) console.log('  ' + c)
    if (hit.length > 200) console.log(`  … ${hit.length - 200} more (use --json)`)
    return
  }

  if (cmd === 'strings') {
    const apk = resolveApk(a1)
    const d = await runJson('dex_strings.py', [apk, '--limit', String(flag('--limit') || 40)])
    if (json) return console.log(JSON.stringify(d, null, 2))
    for (const g of d.groups || []) {
      console.log(`[${g.name}] ${g.total}`)
      for (const it of g.items) console.log('  ' + it)
    }
    return
  }

  if (cmd === 'crypto') {
    const apk = resolveApk(a1)
    const scan = await runJson('crypto_scan.py', [apk, '--limit', String(flag('--limit') || 20)])
    let tried = null
    if (argv.includes('--try')) tried = await runJson('crypto_try.py', [apk, '--limit', String(flag('--try') || 12)])
    if (json) return console.log(JSON.stringify({ scan, tried }, null, 2))
    console.log('algorithms: ' + ((scan.algorithms || []).map((a) => `${a.name}x${a.count}`).join('  ') || 'none'))
    console.log('modes:      ' + ((scan.modes || []).map((m) => m.name).join('  ') || 'none'))
    console.log('keys:       ' + ((scan.keys || []).slice(0, 12).join(', ') || 'none'))
    if (tried) {
      console.log(`tried:      ${tried.files} files x ${tried.keys} keys, ${tried.attempts} attempts`)
      for (const h of tried.hits || []) console.log(`  hit: ${h.file} -> ${h.magic} (${h.mode}, key ${h.key})`)
    }
    return
  }

  if (cmd === 'java' || cmd === 'decode') {
    const apk = resolveApk(a1)
    if (cmd === 'java') {
      if (!cfg.jadx) throw new Error('jadx not found; set DSH_RE_JADX')
      if (!cfg.javaHome) throw new Error('java not found; set JAVA_HOME')
      const out = (flag('--out') === true ? null : flag('--out')) || join(cfg.outDir, 'java')
      console.log(`decompiling to ${out} …`)
      await run(cfg.jadx, ['-d', out, '--no-res', '-j', '2', apk], 1_500_000)
      console.log('done')
      return
    }
    if (!cfg.apktool) throw new Error('apktool not found; set DSH_RE_APKTOOL')
    const mode = flag('--mode') === 'src' ? 'src' : 'res'
    const out = join(cfg.outDir, `${mode === 'src' ? 'smali' : 'res'}`)
    console.log(`decoding (${mode}) to ${out} …`)
    await run(`${cfg.javaHome}/bin/java`, ['-Xmx700m', '-jar', cfg.apktool, 'd', '-f', '--no-assets', mode === 'src' ? '-r' : '-s', '-o', out, apk], 600_000)
    console.log('done')
    return
  }

  if (cmd === 'doctor') {
    const rows = []
    const probe = async (name, bin, args, note) => {
      if (!bin || !existsSync(bin)) return rows.push({ tool: name, ok: 0, detail: note || 'not found' })
      try {
        const out = await run(bin, args, 20_000)
        rows.push({ tool: name, ok: 1, detail: (out.trim().split('\n')[0] || 'ok').slice(0, 60) })
      } catch (err) {
        rows.push({ tool: name, ok: 0, detail: (err.message || String(err)).slice(0, 60) })
      }
    }
    await probe('python', cfg.python, ['-V'])
    await probe('jadx', cfg.jadx, ['--version'], 'not found (optional, only for `java`)')
    const javaBin = cfg.javaHome && existsSync(join(cfg.javaHome, 'bin', 'java')) ? join(cfg.javaHome, 'bin', 'java') : null
    await probe('java', javaBin, ['-version'], 'not found (optional)')
    if (javaBin && cfg.apktool && existsSync(cfg.apktool)) {
      await probe('apktool', javaBin, ['-jar', cfg.apktool, '--version'])
    } else {
      rows.push({ tool: 'apktool', ok: 0, detail: cfg.apktool ? 'java missing' : 'not found (optional, only for `decode`)' })
    }
    if (json) return console.log(JSON.stringify(rows, null, 2))
    for (const r of rows) console.log(`${r.ok ? '✓' : '✗'} ${r.tool.padEnd(8)} ${r.detail}`)
    console.log(`\nconfig: ${cfg.configPath}`)
    console.log(`dirs:   ${cfg.dirs.join(', ')}`)
    console.log(`out:    ${cfg.outDir}`)
    return
  }

  if (cmd === 'report') {
    const apk = resolveApk(a1)
    const d = await inspect(apk)
    const scan = await runJson('crypto_scan.py', [apk, '--limit', '10']).catch(() => null)
    if (json) return console.log(JSON.stringify({ ...d, scan }, null, 2))
    const md = buildReport(d, scan)
    const target = flag('-o') === true ? null : flag('-o') || flag('--out')
    if (target && target !== true) {
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, md)
      return console.log('written ' + target)
    }
    return console.log(md)
  }

  if (cmd === 'diff') {
    const pa = resolveApk(a1)
    const pb = resolveApk(a2)
    const [A, B] = await Promise.all([inspect(pa), inspect(pb)])
    if (json) return console.log(JSON.stringify({ a: A, b: B }, null, 2))
    console.log(`${basename(pa)}  →  ${basename(pb)}`)
    console.log(diffOne(A, B))
    return
  }

  if (cmd === 'scan') {
    const dirs = a1 ? [resolve(a1)] : cfg.dirs
    const files = []
    for (const dir of dirs) {
      let names = []
      try {
        names = readdirSync(dir)
      } catch {
        continue
      }
      for (const name of names) if (/\.apk$/i.test(name)) files.push(join(dir, name))
    }
    if (!files.length) throw new Error('no APK in: ' + dirs.join(', '))
    const rows = []
    for (const f of files) {
      process.stderr.write(`· ${basename(f)}\n`)
      try {
        const d = await inspect(f)
        rows.push({
          name: basename(f),
          package: d.package,
          version: d.versionName,
          sdk: `${d.minSdk}/${d.targetSdk}`,
          packer: (d.packers || []).join(',') || '-',
          classes: d.dexClasses,
          size: (statSync(f).size / 1048576).toFixed(1) + 'M',
        })
      } catch (err) {
        rows.push({ name: basename(f), package: 'ERR ' + (err.message || err).slice(0, 40) })
      }
    }
    if (json) return console.log(JSON.stringify(rows, null, 2))
    console.log(
      table(rows, [
        { title: 'APK', get: (r) => r.name },
        { title: '包名', get: (r) => r.package },
        { title: '版本', get: (r) => r.version },
        { title: 'SDK', get: (r) => r.sdk },
        { title: '加固', get: (r) => r.packer },
        { title: '类数', get: (r) => r.classes },
        { title: '大小', get: (r) => r.size },
      ]),
    )
    return
  }

  usage()
  process.exitCode = 1
}

main().catch((err) => {
  console.error('re-kit: ' + (err.message || err))
  process.exitCode = 1
})
