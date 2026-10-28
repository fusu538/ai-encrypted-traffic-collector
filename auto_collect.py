"""Collect three logged-in AI web apps with bounded human checkpoints.

Run from a Windows terminal. OpenCLI controls the user's existing Chrome tabs;
dumpcap records the Meta and Npcap loopback interfaces. The program never uses
private site APIs or treats a button click as proof of a completed response.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import winreg
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parent
TOOLS = Path(r"C:\Program Files\Wireshark")
APPS = {
    "qwen": {"host": "qianwen.com", "display": "千问"},
    "yuanbao": {"host": "yuanbao.tencent.com", "display": "元宝"},
    "doubao": {"host": "doubao.com", "display": "豆包"},
}
TIMEOUTS = {"A1": 180, "A2": 360, "A3": 420, "A4": 240}
CHALLENGE_RE = re.compile(
    r"人机验证|请完成验证|安全验证|验证码|captcha|操作过于频繁|请求过于频繁|访问受限|BaXia",
    re.IGNORECASE,
)


class CollectionError(RuntimeError):
    pass


class NeedsHuman(CollectionError):
    pass


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cli_command() -> list[str]:
    """Call OpenCLI's Node entry directly so cmd.exe cannot rewrite JS quotes."""
    node = shutil.which("node.exe")
    npm = Path(os.environ.get("APPDATA", "")) / "npm"
    main_js = npm / "node_modules" / "@jackwener" / "opencli" / "dist" / "src" / "main.js"
    return [node, str(main_js)] if node and main_js.is_file() else []


class BrowserBridge:
    def __init__(self) -> None:
        self.command = cli_command()
        if not self.command:
            raise CollectionError("OpenCLI Node entry is unavailable; install/enable OpenCLI Browser Bridge")

    def call(self, *args: str, timeout: int = 35):
        result = subprocess.run(
            [*self.command, "browser", *map(str, args)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
        raw = result.stdout.strip() or result.stderr.strip()
        try:
            envelope, _ = json.JSONDecoder().raw_decode(raw)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"OpenCLI returned non-JSON for {args[:2]}: {raw[:300]}") from exc
        if result.returncode or not envelope.get("ok"):
            error = envelope.get("error") or {}
            raise CollectionError(f"OpenCLI {args[:2]}: {error.get('code')}: {error.get('message')}")
        return envelope.get("data")

    def eval(self, session: str, js: str):
        return self.call("eval", "--session", session, js)

    def find_tabs(self) -> dict[str, dict]:
        tabs = self.call("chrome", "call", "tabs.query", "[{}]")
        found = {}
        for app, info in APPS.items():
            matches = [tab for tab in tabs if (host := urllib.parse.urlparse(tab.get("url", "")).hostname)
                       and (host == info["host"] or host.endswith("." + info["host"]))]
            if len(matches) != 1:
                raise CollectionError(f"Expected one open {app} tab, found {len(matches)}")
            found[app] = matches[0]
        if len({tab["windowId"] for tab in found.values()}) != 1:
            raise CollectionError("Open the three logged-in sites in one Chrome window")
        return found

    def bind(self, app: str, tab: dict) -> str:
        session = f"ai_traffic_{app}_{os.getpid()}"
        self.call("chrome", "call", "windows.update", json.dumps([tab["windowId"], {"focused": True}]))
        self.call("chrome", "call", "tabs.update", json.dumps([tab["id"], {"active": True}]))
        bound = self.call("bind", "--session", session, "--window", "foreground")
        hostname = urllib.parse.urlparse(bound.get("url", "")).hostname or ""
        target_host = APPS[app]["host"]
        if hostname != target_host and not hostname.endswith("." + target_host):
            self.call("unbind", "--session", session)
            raise CollectionError(f"Bound the wrong Chrome tab: {hostname}")
        return session

    def unbind(self, session: str) -> None:
        try:
            self.call("unbind", "--session", session)
        except CollectionError as exc:
            print(f"Warning: could not release browser session: {exc}", file=sys.stderr)

    def click(self, session: str, selector: str, nth: int | None = None) -> None:
        args = ["click", "--session", session, selector]
        if nth is not None:
            args.extend(["--nth", str(nth)])
        self.call(*args)

    def fill(self, session: str, selector: str, value: str) -> None:
        response = self.call("fill", "--session", session, selector, value)
        if not response.get("filled") or not response.get("verified"):
            raise CollectionError(f"Input was not verified: {selector}")


class Capture:
    def __init__(self, folder: Path, interface_ids: list[str], duration: int):
        self.folder = folder
        self.path = folder / "capture.pcapng"
        self.log_path = folder / "dumpcap_stderr.log"
        self.interface_ids = interface_ids
        self.duration = duration
        self.process: subprocess.Popen | None = None
        self.log = None
        self.started_at: str | None = None
        self.ended_at: str | None = None

    def start(self) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        self.log = self.log_path.open("wb")
        argv = [str(TOOLS / "dumpcap.exe"), "-q"]
        for interface_id in self.interface_ids:
            argv.extend(["-i", interface_id])
        argv.extend(["-a", f"duration:{self.duration}", "-w", str(self.path)])
        self.started_at = now()
        self.process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise CollectionError(f"dumpcap exited early; see {self.log_path}")
            if self.path.exists() and self.path.stat().st_size > 0:
                time.sleep(0.7)
                return
            time.sleep(0.2)
        raise CollectionError(f"dumpcap did not create {self.path}; see {self.log_path}")

    def stop(self) -> None:
        if not self.process:
            return
        if self.process.poll() is None:
            try:
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
                self.process.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        self.ended_at = now()
        if self.log:
            self.log.close()
        self.process = None

    def verify(self) -> dict:
        if not self.path.exists() or self.path.stat().st_size < 100:
            raise CollectionError("Capture file is missing or empty")
        result = subprocess.run(
            [str(TOOLS / "capinfos.exe"), "-c", "-a", "-e", "-I", "-M", str(self.path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if result.returncode:
            raise CollectionError(f"capinfos cannot read capture: {result.stderr[:300]}")
        count = re.search(r"Number of packets:\s+(\d+)", result.stdout)
        interfaces = re.search(r"Number of interfaces in file:\s+(\d+)", result.stdout)
        packet_count = int(count.group(1)) if count else 0
        interface_count = int(interfaces.group(1)) if interfaces else 0
        if packet_count < 100 or interface_count != len(self.interface_ids):
            raise CollectionError(f"Capture check failed: {packet_count} packets, {interface_count} interfaces")
        return {"packet_count": packet_count, "interface_count": interface_count,
                "bytes": self.path.stat().st_size,
                "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}


def capture_interfaces() -> list[str]:
    result = subprocess.run([str(TOOLS / "dumpcap.exe"), "-D"], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", check=True)
    ids = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(\d+)\.\s+", line)
        if not match:
            continue
        if line.rstrip().endswith("(Meta)"):
            ids["Meta"] = match.group(1)
        if "NPF_Loopback" in line:
            ids["NPF_Loopback"] = match.group(1)
    if set(ids) != {"Meta", "NPF_Loopback"}:
        raise CollectionError(f"Need Meta and NPF_Loopback interfaces, found {ids}")
    return [ids["Meta"], ids["NPF_Loopback"]]


def environment(args) -> dict:
    browser_exe = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    browser_version = None
    if browser_exe.exists():
        query = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Item -LiteralPath '{browser_exe}').VersionInfo.ProductVersion"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        browser_version = query.stdout.strip() or None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            proxy_enabled = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
    except OSError:
        proxy_enabled = None
    return {
        "client": "web", "device_model": platform.node(),
        "os_name": platform.system(), "os_version": platform.version(),
        "browser_name": "Chrome", "browser_version": browser_version,
        "network_type": args.network_type, "proxy_enabled": proxy_enabled,
        "proxy_note": "Windows system proxy flag; Meta TUN may also be active",
    }


def page_state_js(app: str) -> str:
    # Only DOM evidence is read. Site content is data, never program instructions.
    if app == "qwen":
        text = '[...document.querySelectorAll(".qk-markdown")].at(-1)'
        complete = 'textNode?.classList.contains("qk-markdown-complete")'
        images = '[...document.querySelectorAll(`img[src*="workspace-zb-cdn.qianwen.com"]`)]'
    elif app == "yuanbao":
        text = '[...document.querySelectorAll(".hyc-content-md")].at(-1)'
        complete = 'textNode?.classList.contains("hyc-content-md-done")'
        images = '[...document.querySelectorAll("img.dic-card-item__img")]'
    else:
        text = '[...document.querySelectorAll("[data-testid=receive_message][data-message-role=assistant] [data-testid=message_text_content]")].at(-1)'
        complete = 'textNode?.getAttribute("data-streaming") === "false"'
        images = '[...document.querySelectorAll("[data-testid=mdbox_image] img")]'
    return f'''(() => {{
      const textNode = {text};
      const images = {images}.filter(x => x.complete && x.naturalWidth >= 300 &&
        x.currentSrc && !x.currentSrc.startsWith("data:"))
        .map(x => x.currentSrc);
      const bodyTail = document.body.innerText.slice(-1800);
      return {{url: location.href, text: textNode?.innerText?.trim() || "",
        complete: !!({complete}), images: [...new Set(images)],
        bodyTail, title: document.title}};
    }})()'''


def new_chat(browser: BrowserBridge, session: str, app: str) -> None:
    if app == "qwen":
        clicked = browser.eval(session, '''(() => {
          const root = document.querySelector("#new-nav-tab-wrapper");
          const item = [...(root?.querySelectorAll("span,div") || [])]
            .find(x => x.children.length === 0 && x.textContent.trim() === "新对话");
          item?.click(); return !!item;
        })()''')
        if not clicked:
            raise CollectionError("Qwen new-chat control was not found")
    elif app == "yuanbao":
        browser.click(session, '[aria-label="新建对话"]', nth=0)
    else:
        browser.click(session, '[data-testid="create_conversation_button"] [role="button"]')
    time.sleep(1.2)


def prepare_text_mode(browser: BrowserBridge, session: str, app: str) -> None:
    if app == "doubao":
        # Image generation can remain selected after a new conversation.
        browser.eval(session, '''(() => {
          const chip = [...document.querySelectorAll('[data-testid="skill_input_exit_button"]')]
            .find(x => x.textContent.includes('图像生成'));
          chip?.click(); return !!chip;
        })()''')


def focus_editor(browser: BrowserBridge, session: str, app: str) -> str:
    if app != "doubao":
        return editor_selector(app)
    deadline = time.monotonic() + 12
    last_state = None
    while time.monotonic() < deadline:
        last_state = browser.eval(session, '''(() => {
          const candidates = [
            ...document.querySelectorAll('textarea[data-testid="chat_input_input"]'),
            ...document.querySelectorAll('[data-testid="chat_input_input"] [contenteditable="true"]')
          ];
          const editor = candidates.find(x => getComputedStyle(x).visibility === 'visible' &&
            getComputedStyle(x).display !== 'none' && x.getBoundingClientRect().width > 100);
          editor?.focus();
          return {exists: !!editor, focused: document.activeElement === editor,
            active: document.activeElement?.tagName + ':' + document.activeElement?.getAttribute('data-testid'),
            selector: editor?.tagName === 'TEXTAREA'
              ? 'textarea[data-testid="chat_input_input"]'
              : '[data-testid="chat_input_input"] [contenteditable="true"]',
            page: location.pathname};
        })()''')
        if last_state["focused"]:
            return last_state["selector"]
        time.sleep(0.8)
    raise CollectionError(f"Doubao editor could not receive focus within 12 seconds: {last_state}")


def set_image_mode(browser: BrowserBridge, session: str, app: str) -> None:
    if app == "qwen":
        selector = 'button'
        label = 'AI生图'
    elif app == "yuanbao":
        selector = 'button'
        label = 'AI 生图'
    else:
        browser.click(session, '[data-testid="skill_bar_button_3"]')
        return
    clicked = browser.eval(session, f'''(() => {{
      const choices = [...document.querySelectorAll({json.dumps(selector)})].filter(x =>
        x.getClientRects().length && x.innerText.trim() === {json.dumps(label, ensure_ascii=False)});
      choices.at(-1)?.click(); return choices.length > 0;
    }})()''')
    if not clicked:
        raise CollectionError(f"{app} image-generation control was not found")
    time.sleep(0.8)


def editor_selector(app: str) -> str:
    return {"qwen": '[role="textbox"][aria-multiline="true"]',
            "yuanbao": '[contenteditable="true"]',
            "doubao": '[data-testid="chat_input_input"] [contenteditable="true"]'}[app]


def send_selector(app: str) -> str:
    return {"qwen": '[aria-label="发送消息"]',
            "yuanbao": '#yuanbao-send-btn',
            "doubao": '[data-testid="chat_input_send_button"]'}[app]


def wait_for_response(browser: BrowserBridge, session: str, app: str,
                      element: str, timeout: int) -> tuple[dict, str | None]:
    deadline = time.monotonic() + timeout
    previous = None
    stable = 0
    first_response_at = None
    while time.monotonic() < deadline:
        state = browser.eval(session, page_state_js(app))
        if CHALLENGE_RE.search(state.get("title", "") + "\n" + state.get("bodyTail", "")):
            raise NeedsHuman("A human verification or rate-limit page appeared")
        text = state["text"]
        if text or state["images"]:
            first_response_at = first_response_at or now()
        candidate = bool(state["images"]) if element == "A3" else bool(text and state["complete"])
        identity = (text, tuple(state["images"]))
        stable = stable + 1 if candidate and identity == previous else 0
        if stable >= 2:
            return state, first_response_at
        previous = identity
        time.sleep(1.5)
    raise NeedsHuman(f"No completed {app}/{element} response before the activity timeout; inspect the page")


def image_bytes_type(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


def save_images(urls: list[str], folder: Path, interactive: bool) -> list[str]:
    media = folder / "media"
    media.mkdir(exist_ok=True)
    saved = []
    for index, url in enumerate(urls[:4], 1):
        try:
            response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=35)
            response.raise_for_status()
            ext = image_bytes_type(response.content)
            if not ext or len(response.content) < 100:
                raise CollectionError("Image URL returned a non-image or empty body")
            filename = f"generated_{index}{ext}"
            (media / filename).write_bytes(response.content)
            saved.append("media/" + filename)
        except (requests.RequestException, CollectionError) as exc:
            if not interactive:
                raise CollectionError(f"Could not save generated image {index}: {exc}") from exc
            print(f"Could not save generated image {index}: {exc}")
            path = Path(input("Save the generated image manually, then enter its full file path: ").strip())
            if not path.is_file() or not image_bytes_type(path.read_bytes()[:12]):
                raise CollectionError("Manual image file is missing or unsupported")
            target = media / f"generated_{index}{path.suffix.lower()}"
            shutil.copy2(path, target)
            saved.append("media/" + target.name)
    if not saved:
        raise CollectionError("No generated images were saved")
    return saved


def validate_answer(element: str, answer: str, images: list[str]) -> None:
    if element == "A3":
        if not images:
            raise CollectionError("No generated image was observed")
    elif not answer.strip():
        raise CollectionError("The model answer is empty")
    elif element == "A2" and len(answer.split()) < 500:
        raise CollectionError(f"Long-form answer has only {len(answer.split())} words")
    elif element == "A4" and not all(word in answer.lower() for word in ("red", "blue", "circle", "square")):
        raise CollectionError("Image-understanding answer did not identify all target shapes and colors")


def manual_upload(image: Path, interactive: bool) -> None:
    if not interactive:
        raise NeedsHuman("A4 needs a human to upload the fixture image")
    print("\nA4 human step: in the active Chrome tab, upload this image:")
    print(image)
    print("Wait for its preview/upload indicator to finish. Do not send the prompt yet.")
    confirmation = input("Press Enter when the image is attached, or type skip: ").strip().lower()
    if confirmation == "skip":
        raise NeedsHuman("User skipped image upload")


def collect_one(browser: BrowserBridge, session: str, app: str, activity: dict,
                folder: Path, interfaces: list[str], args, env: dict) -> dict:
    element = activity["element"]
    prompt = activity["prompt"]
    if not prompt.isascii():
        raise CollectionError(f"{element} prompt must be English ASCII")
    operation = {
        "app": app, "element": element, "activity": activity["activity"],
        "prompt": prompt, "answer": None, "generated_files": [],
        "input_image": activity.get("input_image"),
        "success": False, "control_mode": "OpenCLI existing Chrome tab",
        "environment": env, "capture_interfaces": ["Meta", "NPF_Loopback"],
        "created_at": now(),
    }
    capture = Capture(folder, interfaces, TIMEOUTS[element] + 60)
    try:
        operation["setup_started_at"] = now()
        new_chat(browser, session, app)
        if element == "A3" and app != "doubao":
            set_image_mode(browser, session, app)
        elif element != "A3":
            prepare_text_mode(browser, session, app)
        editor = None if app == "doubao" and element == "A3" else focus_editor(browser, session, app)
        operation["setup_ended_at"] = now()
        capture.start()
        operation["capture_started_at"] = capture.started_at
        if element == "A4":
            image = ROOT / activity["input_image"]
            if not image.is_file():
                raise CollectionError(f"Fixture image is missing: {image}")
            manual_upload(image, args.interactive)
            operation["manual_upload_confirmed_at"] = now()
            operation["control_mode"] = "OpenCLI + human image upload"
        operation["send_started_at"] = now()
        if editor is None:
            if not args.interactive:
                raise NeedsHuman("Doubao image generation needs a manual send")
            operation["control_mode"] = "OpenCLI + human Doubao image prompt send"
            operation["send_time_semantics"] = "manual send window"
            print("\nDoubao A3 human step: select Image Generation, then enter and send this English prompt in the active tab:", flush=True)
            print(prompt, flush=True)
            if input("Press Enter immediately after clicking Send, or type skip: ").strip().lower() == "skip":
                raise NeedsHuman("User skipped Doubao image prompt send")
        else:
            browser.fill(session, editor, prompt)
            operation["send_started_at"] = now()
            browser.click(session, send_selector(app))
        operation["send_command_ended_at"] = now()
        state, first_response_at = wait_for_response(
            browser, session, app, element, TIMEOUTS[element])
        operation["first_response_observed_at"] = first_response_at
        operation["response_observed_at"] = now()
        operation["chat_url"] = state["url"]
        operation["answer"] = None if element == "A3" else state["text"]
        validate_answer(element, operation["answer"] or "", state["images"])
        capture.stop()
        operation["capture_ended_at"] = capture.ended_at
        operation["capture_quality"] = capture.verify()
        if element == "A3":
            operation["generated_files"] = save_images(state["images"], folder, args.interactive)
        operation["success"] = True
    except Exception as exc:
        operation["error_type"] = type(exc).__name__
        operation["error"] = str(exc)
        if isinstance(exc, NeedsHuman):
            operation["needs_human"] = True
        raise
    finally:
        capture.stop()
        operation["capture_started_at"] = capture.started_at
        operation["capture_ended_at"] = capture.ended_at
        write_json(folder / "operation.json", operation)
    return operation


def next_attempt_folder(stage: Path, app: str, element: str) -> Path:
    attempt = 1
    while True:
        folder = stage / f"{app}_{element}_attempt{attempt:02d}"
        if not folder.exists():
            return folder
        attempt += 1


def success_exists(stage: Path, app: str, element: str) -> bool:
    for path in stage.glob(f"{app}_{element}_attempt*/operation.json"):
        try:
            if json.loads(path.read_text(encoding="utf-8"))["success"] is True:
                return True
        except (OSError, ValueError, KeyError):
            pass
    return False


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, help="Run directory; reuse this path to resume")
    parser.add_argument("--apps", nargs="+", choices=APPS, default=list(APPS))
    parser.add_argument("--activities", nargs="+", choices=TIMEOUTS, default=list(TIMEOUTS))
    parser.add_argument("--preflight", action="store_true", help="Check tabs and tools without sending prompts")
    parser.add_argument("--no-package", action="store_true")
    parser.add_argument("--non-interactive", dest="interactive", action="store_false")
    parser.add_argument("--network-type", choices=["WiFi", "4G", "5G", "Ethernet"], default=None)
    parser.add_argument("--between-seconds", type=int, default=10)
    parser.add_argument("--max-attempts", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for tool in ("dumpcap.exe", "capinfos.exe", "mergecap.exe", "tshark.exe"):
        if not (TOOLS / tool).exists():
            raise CollectionError(f"Missing Wireshark tool: {TOOLS / tool}")
    plan = json.loads((ROOT / "prompt_plan.json").read_text(encoding="utf-8"))
    activities = {item["element"]: item for item in plan["activities"]}
    interfaces = capture_interfaces()
    browser = BrowserBridge()
    tabs = browser.find_tabs()
    print("Found logged-in Chrome tabs:")
    for app in APPS:
        print(f"  {app}: {tabs[app]['url']}")
    print(f"Capture interfaces: {interfaces} (Meta, NPF_Loopback)")
    if args.preflight:
        return 0
    run_dir = args.run_dir or ROOT / "runs" / dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = run_dir.resolve()
    stage = run_dir / "staging"
    stage.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "run_config.json", {
        "created_at": now(), "apps": args.apps, "activities": args.activities,
        "prompt_plan": str(ROOT / "prompt_plan.json"),
        "capture_interfaces": ["Meta", "NPF_Loopback"],
        "environment": environment(args),
    })
    env = environment(args)
    print(f"Run directory: {run_dir}")
    failures = []
    for app in args.apps:
        session = browser.bind(app, tabs[app])
        try:
            for element in args.activities:
                if success_exists(stage, app, element):
                    print(f"SKIP {app}/{element}: already successful")
                    continue
                for attempt in range(args.max_attempts):
                    folder = next_attempt_folder(stage, app, element)
                    print(f"START {app}/{element} attempt {attempt + 1}: {folder}", flush=True)
                    try:
                        collect_one(browser, session, app, activities[element], folder,
                                    interfaces, args, env)
                        print(f"PASS {app}/{element}", flush=True)
                        break
                    except NeedsHuman as exc:
                        print(f"HUMAN STEP {app}/{element}: {exc}", flush=True)
                        if not args.interactive or attempt + 1 >= args.max_attempts:
                            failures.append(f"{app}/{element}: {exc}")
                            break
                        input("Complete the verification in Chrome, then press Enter to retry: ")
                    except (CollectionError, subprocess.SubprocessError, requests.RequestException) as exc:
                        print(f"FAIL {app}/{element}: {exc}", flush=True)
                        failures.append(f"{app}/{element}: {exc}")
                        break
                time.sleep(max(args.between_seconds, 0))
        finally:
            browser.unbind(session)
    complete = all(success_exists(stage, app, element)
                   for app in APPS for element in TIMEOUTS)
    if complete and not args.no_package:
        argv = [sys.executable, str(ROOT / "package_dataset.py"),
                "--staging", str(stage), "--output", str(run_dir / "大模型"),
                "--fixture", str(ROOT / "fixtures" / "red_circle_blue_square.png"),
                "--zip", str(run_dir / "大模型.zip")]
        subprocess.run(argv, check=True)
    elif not complete:
        print("12 successful samples are not yet present; package step skipped.")
    write_json(run_dir / "run_status.json", {"finished_at": now(),
                                              "complete": complete, "failures": failures})
    print(f"Finished. Results: {run_dir}")
    return 0 if complete or (args.apps != list(APPS) or args.activities != list(TIMEOUTS)) and not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CollectionError, KeyboardInterrupt) as error:
        print(f"Stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
