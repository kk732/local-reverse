# 逆向工具箱 · local-reverse

Android APK 静态分析小工具：一条命令看包名、签名、权限、加固特征和框架痕迹，按需列出 dex 类、可疑字符串和加密线索，必要时调 jadx / apktool 导出源码。

装在 dsh-go 里是插件（输入框上方「逆向工具」按钮 + 四个面板：APK 列表、APK 详情、类搜索、反编译代码），没装 App 也能当命令行用。

## 能做什么

| 能力 | 看什么 |
| --- | --- |
| 体检 | 包名、版本、SDK 等级、签名方案与指纹、权限、导出组件 |
| 加固识别 | 360 / 梆梆 / 乐固 / 爱加密 / 娜迦等壳的特征类与特征串 |
| 框架痕迹 | Flutter、React Native、Cordova、Unity、Xposed、Frida |
| 类与字符串 | dex 类列表、按关键字匹配类名、URL / 密钥 / 路径等可疑串 |
| 加密线索 | `Cipher`、`MessageDigest`、native 库、常量密钥候选 |
| 反编译 | jadx 导出 Java，apktool 解 res / smali |
| 报告与对比 | 导出 Markdown 体检报告；对比两个版本的权限、签名、类数差异 |
| 批量 | 一次扫完一个目录，出表格 |

纯静态读取，不改 APK，不联网。

## 安装

```bash
dsh plugin --profile web add /path/to/local-reverse
```

## 依赖

Python 3.9+ 即可，体检与 dex 分析只用标准库。只有「导出 Java」「解 smali/res」需要 jadx、apktool 和 Java 17：

```bash
apt-get install -y python3 openjdk-17-jre-headless
```

## 配置

能自动探测就不用配。优先级：环境变量 > 配置文件 > 自动探测。配置文件默认 `$DSH_HOME/re-kit.json`：

```json
{
  "dirs": ["/sdcard/Download", "/sdcard/Download/DSH-Go"],
  "outDir": "/sdcard/Download/DSH-Go/re",
  "jadx": "/opt/jadx/bin/jadx",
  "apktool": "/opt/apktool/apktool.jar",
  "javaHome": "/usr/lib/jvm/java-17-openjdk-arm64",
  "python": "/usr/local/bin/python3"
}
```

| 环境变量 | 作用 |
| --- | --- |
| `DSH_RE_CONFIG` | 配置文件路径 |
| `DSH_RE_DIRS` | APK 搜索目录，`:` 分隔 |
| `DSH_RE_OUT` | 导出目录 |
| `DSH_RE_JADX` / `DSH_RE_APKTOOL` | jadx 可执行文件 / apktool.jar |
| `DSH_RE_PYTHON` | Python 解释器 |
| `JAVA_HOME` | 跑 jadx / apktool 的 JDK |

缺省回落：`dirs` 先找手机 `/sdcard/Download`，再 `~/Downloads` 和当前目录；`outDir` 有 `/sdcard/Download` 就用其下 `DSH-Go/re`，否则 `$DSH_HOME/re-kit/out`。

## 命令行

```bash
re-kit config                     # 当前解析到的路径
re-kit list                       # 列出搜索目录里的 APK
re-kit info app.apk               # 体检报告
re-kit classes app.apk -m login   # 按关键字匹配类名
re-kit strings app.apk -m http    # 匹配字符串
re-kit crypto app.apk --try       # 加密线索，并试跑常量密钥候选
re-kit java app.apk               # jadx 导出 Java
re-kit decode app.apk -m res      # apktool 解资源，-m src 解 smali
re-kit report app.apk -o r.md     # 导出 Markdown 体检报告
re-kit diff old.apk new.apk       # 对比两个版本
re-kit scan                       # 批量扫目录，出一张表
re-kit doctor                     # 检查 python / jadx / java / apktool 是否就绪
```

参数可以是路径，也可以只写文件名（会在 `dirs` 里找）。加 `--json` 拿原始结构。

导出产物写在 `outDir` 下，按 `<apk名>-java` / `-smali` / `-res` 分目录；体检和 dex 结果只进内存。

## 说明

- 类名匹配和字符串扫描是启发式的，用来快速定位，不保证全覆盖。
- 加固识别靠特征名，改过壳名的包可能认不出。
- 只在你有权分析的 APK 上使用。

## License

MIT
