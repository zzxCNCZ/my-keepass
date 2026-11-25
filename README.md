# My KeePass

My KeePass 是一个面向个人的 KeePass 桌面密码管理器，支持 **macOS Apple Silicon (arm64)** 和 **Windows x64**。参考 `my-windterm` 的 Tauri v2 + Rust + Vite 轻量架构，完整实现 KeePassX 风格的 `.kdbx` 加密数据库管理与 GitHub Releases 应用内签名在线升级。

## 核心特性

- **标准 KeePass 加密格式**：原生支持读取与解密 **KDBX 4**、**KDBX 3**（KeePassX / KeePass 2）和 **KDB**（KeePass 1）数据库，保存时写入兼容 KeePassXC / KeePass 2 的 KDBX 4（AES-256 / ChaCha20 / Twofish + Argon2id / Argon2d / AES-KDF）。
- **主密码 + 密钥文件双因素解锁**：支持主密码、密钥文件（XML v1/v2、十六进制、二进制、任意文件）或两者组合解锁，支持一键生成标准密钥文件与修改主密钥。
- **多数据库标签与分组树**：同时打开多个密码库标签页，支持层级分组管理、移动分组/条目、回收站软删除与清空回收站。
- **完整条目管理**：支持标准字段、自定义属性（可选内存保护隐藏）、加密文件附件（添加/导出/删除）、标签、过期时间、条目克隆、修改历史版本快照与一键恢复。
- **TOTP 动态验证码**：自动解析条目中的 `otpauth://` 字段，实时显示动态验证码与倒计时，一键复制。
- **密码生成器与强度评估**：基于操作系统密码学安全随机数生成器（CSPRNG），无模偏采样，支持自定义长度、字符类型、排除易混淆字符与每组必选规则。
- **安全机制**：
  - 锁定数据库或关闭标签时，后端立即释放并清零内存中的解密数据与主密钥（`ZeroizeOnDrop`）。
  - 复制用户名/密码后按设定时间自动清空剪贴板（仅当剪贴板内容未变化时清空）。
  - 支持空闲超时自动锁定全部数据库。
  - 原子写入保存（`NamedTempFile` + `sync_all` + `persist`）并检测外部文件变动冲突。
- **导出与多语言**：支持导出 CSV，支持简体中文 / English / 跟随系统切换。
- **GitHub Releases 应用内在线升级**：基于 `tauri-plugin-updater`，使用内置公钥校验更新包签名与版本，支持进度条下载与自动重启安装。

## 下载与更新

首次安装请从 [GitHub Releases](https://github.com/zzxCNCZ/my-keepass/releases) 下载对应平台的安装包：
- **macOS Apple Silicon (arm64)**：`My-KeePass-vX.Y.Z-macos-arm64.dmg`
- **Windows x64**：`My-KeePass-vX.Y.Z-windows-x64-setup.exe`

在 **偏好设置（⌘ , / Ctrl+,）→ 版本更新 → 检查更新** 中发现新版本后，点击 **下载并安装** 即可完成签名校验与在线升级。

## 开发与构建

需要 Rust（支持 edition 2024）、Node.js（20.19+ / 22.12+ / 24+）及对应平台构建工具。

```sh
npm ci
npm run tauri -- dev
```

如果使用本地 `.toolchain` 中的 Rust 工具链（如共享 `my-windterm/.toolchain`）：

```sh
export RUSTUP_HOME="/Volumes/data/Users/zexinzhuang/Project/my-windterm/.toolchain/rustup"
export CARGO_HOME="/Volumes/data/Users/zexinzhuang/Project/my-windterm/.toolchain/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
```

### 本地打包 macOS ARM64

```sh
npm run tauri -- build --target aarch64-apple-darwin --bundles app
```

构建产物位于 `src-tauri/target/aarch64-apple-darwin/release/bundle/macos/My KeePass.app`，可使用 `hdiutil` 生成 DMG。

### GitHub Actions 双平台自动发布（macOS arm64 + Windows x64）

1. 将本地生成的私钥与密码（位于 `.toolchain/updater/`，已加入 `.gitignore`）配置到 GitHub 仓库的 Actions Secrets：
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
2. 同步更新 `package.json`、`package-lock.json`、`src-tauri/Cargo.toml`、`src-tauri/Cargo.lock`、`src-tauri/tauri.conf.json` 中的版本号。
3. 提交并推送对应 tag（例如 `v1.0.0`），`.github/workflows/release.yml` 将自动运行测试、编译并签名 **macOS arm64 (`.dmg` + `.app.tar.gz`)** 和 **Windows x64 (`-setup.exe`)**，并发布包含 `latest.json` 与 `SHA256SUMS.txt` 的 GitHub Release。

## 验证

```sh
npm test
node scripts/check-release-version.mjs
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
```
