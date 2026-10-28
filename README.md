# AI 网页加密流量采集：项目 README / AI 接手指南

本文供研究人员及其 AI 助手接手项目使用。请先读完“当前状态”和“采集边界”，再部署或修改代码。用户希望程序尽可能自动运行，人工处理登录与验证；不要自动绕过验证码，也不要索取或传递账号密码、Cookie、登录态文件。

## 1. 目标和当前状态

在 Windows 上使用浏览器访问元宝和豆包，让程序按指定活动发送英文提示词，使用 Wireshark 的 `dumpcap` 抓取 WLAN 流量；每次活动保存原始 PCAP 和操作记录。按所选应用和活动打包，格式尽量保持项目原数据集的结构。

默认研究对象为网页端元宝和豆包；千问不在交互菜单中，虽然个别旧代码仍保留其分支，但由于验证频繁，本轮不要采集它。

目前有 100 组英文提示词，每组 4 条，各对应以下活动；100 张不同的 COCO 照片分别用于 A4。相同组号下，两家应用使用同一提示词和同一图片。

| 活动 | 当前定义 | 注意 |
|---|---|---|
| A1 | 简单文本问答 | 1 次提问并等待回答 |
| A2 | 长文生成 | 回答需达到 500 个英文单词，否则记为失败 |
| A3 | 根据英文描述生成图片 | 需等待页面出现图片；图片在停止抓包后另行保存 |
| A4 | 上传照片并要求描述图片 | 抓包开始后上传照片，然后发送问题 |

重要：程序已做过提示词结构、批量选择模拟、WLAN 抓包与单活动打包测试；新版的完整批量流程和在其他电脑上的部署**尚未端到端验证**。安装示例、网页 UI 选择器、登录和抓包权限需要在目标机器上实际检查。

## 2. 运行边界与网络路径

- 脚本当前使用名称精确为 `WLAN` 的网卡，调用 `dumpcap -D` 查找并抓取；Wireshark 工具路径写死在 `C:\Program Files\Wireshark`。不存在时应根据目标机器实际情况适配，不能只改显示文字。
- 希望采集直连场景时，使用者先关闭系统代理、代理软件 TUN 和浏览器自身代理，确认元宝和豆包仍能正常使用。**抓 WLAN 不足以证明直连**：VPN、代理规则、浏览器配置等都可能影响真实路径。应实际核查目标流目的地址、接口与网络配置。
- `capture.pcapng` 和每个 `elements` 小包包含所选活动时间窗内的 WLAN 流量，并可能混有其他程序的背景流量。`pure.pcap` 通过可见 HTTP Host/TLS SNI 域名匹配初筛，连接复用、QUIC、CDN、加密 SNI 等可能导致漏检或误归属；不要将其视为纯净训练数据。
- 提示词和回答是脚本通过输入内容及浏览器页面另行记录；不是从加密网络包解密得到。不要在提示词和抓包中放入真实账号、敏感信息。抓包与浏览器 profile 可能含隐私，交接或发布前应检查。
- 不同应用、活动、图片、提示词与采集批次会影响流量。做实验时应考虑按应用、提示词组、图片或批次划分训练/测试，避免同源样本泄漏。完整设备与网络环境元数据尚未全面实现。

## 3. 交付文件和运行原理

必须保留下面的相对路径：

```text
项目根目录/
├─ README.md                         本文
├─ 使用说明.md                       面向使用者的操作指南
├─ auto_collect.py                   dumpcap Capture、网页状态等共用代码
├─ package_dataset.py                整理和打包
├─ prompt_groups.json                100 组提示词及图片路径
├─ fixtures/coco2017/                100 张照片和 sources.json
└─ automation_comparison/
   ├─ 运行采集.cmd                   交互式入口
   ├─ batch_collect.py               选择应用、活动、数量和起始组；按组执行
   ├─ collect.py                     控制浏览器、抓包、记录单组
   ├─ package.json / package-lock.json
   └─ node_modules/                  npm ci 生成，无需随交付复制
```

`batch_collect.py` 为每组调用一次 `collect.py`；后者用 agent-browser 获取现有会话的 CDP 地址，用 Python Playwright 操作已有网页；`auto_collect.Capture` 启动和停止 `dumpcap`；`package_dataset.py` 按所选应用和活动整理。脚本控制流程本身不调用大模型，也不需要 Codex token。网页与 AI 服务仍可能有使用额度或验证限制。

不要把 `automation_comparison/browser_profile/` 作为交付内容：它可能包含当前用户的 Cookie 和登录信息。学长应在自己的电脑和自己的专用 profile 中自行登录。`runs/` 是历史采集数据，不是运行依赖；是否交付由数据所有者决定。照片的来源和 SHA-256 在 `fixtures/coco2017/sources.json`，COCO 原图授权不一定一致，对外公开分享前逐张核查。

## 4. 新电脑准备（Windows）

需要 Chrome、Node.js、Python、Wireshark 和 Npcap，且 Python 能导入 `playwright`、`requests`。本机已观察到 Python 3.12.7、Playwright 1.63.0、requests 2.34.2、Node 24.15.0、agent-browser 0.40.0；`package-lock.json` 的 agent-browser 声明 Node >=24。此信息是已安装版本，不代表跨机器已验证。

1. 将以上交付文件放进同一个项目根目录，路径可以与原电脑不同。安装 Wireshark 时安装 Npcap，并确保抓包权限；默认路径应包含 `dumpcap.exe`、`tshark.exe`、`capinfos.exe`、`mergecap.exe`。
2. 在 PowerShell 中进入项目根目录，并在**运行采集程序所用的 Python 环境**安装依赖：

```powershell
python --version
node --version
python -m pip install playwright==1.63.0 requests==2.34.2
Set-Location .\automation_comparison
npm ci
Set-Location ..
```

`运行采集.cmd` 优先使用 `%USERPROFILE%\anaconda3\python.exe`，若不存在才用 PATH 上的 `python`。如果机器有 Anaconda，安装依赖时应显式使用同一个解释器，例如 `& "$env:USERPROFILE\anaconda3\python.exe" -m pip install playwright==1.63.0 requests==2.34.2`。没有 Anaconda 时，确保 `python`、`node` 在 PATH。

3. 确认 Wireshark 能看到 `WLAN` 网卡：

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

如果目标电脑网卡叫其他名称，需调整 `collect.py` 中 `wlan_interfaces()` 的匹配和其他 `WLAN` 元数据；同时在实际网络路径中验证该网卡是正确接口。

## 5. 创建专用浏览器会话与登录

`traffic-sites` 是 agent-browser 的**会话名称**。程序通过该会话获取 CDP 地址，因此仅在普通 Chrome 打开并登录元宝和豆包，并不保证程序能找到页面。采集程序本身不会启动浏览器。

新机器上可以尝试如下启动流程；命令假定当前 PowerShell 位于项目根目录，且 Chrome 安装路径正确。它会使用项目内独立 `browser_profile`，而不是拷贝原用户的 profile。首次建立会话时人工操作登录：

```powershell
Set-Location .\automation_comparison
node .\node_modules\agent-browser\bin\agent-browser.js --session traffic-sites --headed --profile .\browser_profile --executable-path 'C:\Program Files\Google\Chrome\Application\chrome.exe' open https://yuanbao.tencent.com/
node .\node_modules\agent-browser\bin\agent-browser.js --session traffic-sites tab new https://www.doubao.com/chat/
Set-Location ..
```

1. 在这个专用 Chrome 窗口分别登录所选应用。豆包需为普通对话页（URL 包含 `/chat`），不要进入“豆包工作”。如果页面要求验证码，人工完成。
2. 每个所选应用仅保留一个匹配的标签页：`collect.py` 的 `find_pages()` 对匹配结果要求恰好一个；重复或没有匹配会失败。未选择的应用不必打开。
3. 保持专用浏览器和会话运行，不要拷贝或泄露 `browser_profile`。已有 `traffic-sites` 会话时不要贸然启动另一个以免冲突。
4. 下例仅检查会话、网页及 WLAN，不采集或发送提示词：

```powershell
python .\automation_comparison\collect.py --group 1 --apps yuanbao doubao --activities A1 --check
```

若启动器使用 Anaconda Python，这里也应换成同一解释器。`--check` 成功仅证明连接和接口可见，并不能证明未使用代理或抓到目标流量。以上新机器启动流程尚未独立实测；若失败先检查会话、Chrome 路径和程序版本，不要为了通过而覆盖用户浏览器数据或反复触发验证。

## 6. 交互采集和命令行采集

确保目标站点直接联网并登录专用浏览器后，双击 `automation_comparison/运行采集.cmd`：

- 应用：`1` 元宝、`2` 豆包、`3` 两者。
- 活动：`1`、`2`、`3`、`4` 分别对应 A1～A4；例如 `1,4` 选两项，`5` 全部。
- 数量：要采集的提示词组数 1～100；每组对所选应用的所选活动各执行一次。
- 起始组：直接回车为 1；也可指定其他组，使 `起始组 + 数量 - 1 <= 100`。重复运行默认从 1 开始，不自动排除过去批次已采的组。

例如：选两家、A1 和 A4、10 组、起始 1，会依次执行 2 × 2 × 10 = 40 次采集。程序不同时执行活动。批次有 `batch_config.json`，每个组有独立目录。

也可使用命令行（PowerShell、项目根目录）：

```powershell
python .\automation_comparison\batch_collect.py --apps yuanbao doubao --activities A1 A4 --count 10 --start 1
```

命令行模式必须同时提供 `--apps`、`--activities`、`--count`；应用和活动不允许重复，`--start` 可省略且默认为 1。活动顺序以输入顺序为准；脚本先遍历应用、再遍历活动。

## 7. 输出结构与失败恢复

```text
runs/batch_时间/
├─ batch_config.json
└─ group_001/
   ├─ prompt_group.json          当前组提示词及照片路径快照
   ├─ capture_config.json        记录 WLAN 配置
   ├─ staging/<应用_活动_attemptNN>/
   │  ├─ capture.pcapng          单次活动原始抓包
   │  ├─ operation.json          成功/失败、提示词、回答、时间等
   │  └─ dumpcap_stderr.log
   ├─ 大模型/<应用>/             所选活动均成功后生成
   └─ 大模型.zip
```

整理目录包含 `capture.pcapng`、`pure.pcap`、`elements/`、`events.jsonl`、`flows_labeled.json`、`pcap_quality.json`、`QUALITY.md`、`MANIFEST.yaml`、`prompts_answers_labeled.json`、`media/`。其中元素包与应用数量由本次选择决定。图片来源和权利说明不自动随每个结果复制，应保留原始 `sources.json`。

遇到验证、控件变化、回答超时、抓包不足或长文不足 500 词，当前组记录失败并停止，后续组不开始；屏幕中的验证也可能未被脚本识别。应人工处理网页并核对失败记录，再用同一个组目录、组号、应用和活动续跑：

```powershell
python .\automation_comparison\collect.py --group 3 --run-dir '.\runs\batch_实际目录\group_003' --apps yuanbao doubao --activities A1 A4
```

此命令只恢复第 3 组，跳过该目录已成功的活动；完成后需要另起一个批次，从第 4 组开始选剩余数量。续跑要求提示词快照与 WLAN 配置一致；旧版回环采集目录不能与 WLAN 续跑混合。避免同时运行两个采集程序，避免同一会话并发操作或包混杂。

## 8. AI 接手排障要点

- 先检查确切的错误和 `operation.json` / `dumpcap_stderr.log`，不要把 HTTP 错误、验证码和超时误判为成功样本。遇验证由用户手动完成，不能自动绕过。
- `没有找到正在运行的 traffic-sites 浏览器会话`：确认专用 agent-browser daemon 与窗口、会话名和 Node 进程；普通 Chrome 登录不够。不要读取或输出 Cookie。
- `需要恰好一个已打开的对话页`：检查所选应用 URL、是否重复标签、豆包是否为普通 `/chat` 页。
- `需要一个 WLAN 网卡` / dumpcap 错误：确认网卡名、Npcap、Wireshark 路径、用户抓包权限。抓包校验要求至少 100 包且接口数量与所选接口数一致；通过不保证目标流存在。
- A2 少于 500 词或页面按钮失效：保留失败记录，按实际网页变化调整；不要伪造回答或将失败标成成功。A1/A2/A3/A4 最大等待分别为 180/360/420/240 秒。
- `pure.pcap` 空或流量归属不全：这是可见域名匹配的限制之一，应结合原始包、连接复用和真实网络路径分析，不要编造归属。
- 修改时保持英文提示词及图片对应，保护旧采集数据，验证子集打包、不同活动、错误停机和续跑；实际网站验收要在人工登录且同意的会话中进行，避免无谓的大批量请求。

## 9. 参考资料

- MIRAGE-GenAI-2025 数据集：https://traffic.comics.unina.it/mirage/mirage-genai-2025
- 论文 From Prompts to Packets：https://arxiv.org/abs/2510.11269
- COCO 数据集：https://cocodataset.org/ ；每张所用图片的原始 URL 和授权编号见 `fixtures/coco2017/sources.json`。

本项目提示词是自行编写并参考公开研究的受控比较思路，并非论文数据集原提示词。COCO 是图像理解数据集，不是 AI 加密流量数据集。
