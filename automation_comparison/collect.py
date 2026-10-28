"""Collect AI web traffic using the already-open agent-browser session.

Run in a Windows console. No model is called by this script. Failures stop
the current capture and are recorded; rerun with the same --run-dir to resume.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / 'automation_comparison' / 'node_modules' / 'agent-browser' / 'bin' / 'agent-browser.js'
SESSION = 'traffic-sites'
TOOLS = Path(r'C:\Program Files\Wireshark')
HOSTS = {'qwen': 'qianwen.com', 'yuanbao': 'yuanbao.tencent.com', 'doubao': 'doubao.com'}
TIMEOUTS = {'A1': 180, 'A2': 360, 'A3': 420, 'A4': 240}

spec = importlib.util.spec_from_file_location('capture_support', ROOT / 'auto_collect.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)

def command(*args):
    r = subprocess.run(['node', str(CLI), '--session', SESSION, *args], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=30)
    if r.returncode:
        raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout.strip()

def wlan_interfaces():
    result = subprocess.run([str(TOOLS / 'dumpcap.exe'), '-D'], capture_output=True,
                            text=True, encoding='utf-8', errors='replace', check=True)
    matches = []
    for line in result.stdout.splitlines():
        match = re.match(r'\s*(\d+)\.\s+.*\(WLAN\)\s*$', line)
        if match:
            matches.append(match.group(1))
    if len(matches) != 1:
        raise RuntimeError(f'需要一个 WLAN 网卡，找到 {len(matches)} 个；请检查 Wi-Fi 网卡')
    return matches

def find_pages(browser, apps):
    found = {}
    for app in apps:
        host = HOSTS[app]
        matches = [p for c in browser.contexts for p in c.pages
                   if (h := (urlparse(p.url).hostname or '')) and (h == host or h.endswith('.' + host))]
        if app == 'doubao':
            matches = [p for p in matches if '豆包工作' not in p.title() and '/chat' in p.url]
        if len(matches) != 1:
            raise RuntimeError(f'{app}: 需要恰好一个已打开的对话页，当前找到 {len(matches)} 个')
        found[app] = matches[0]
    return found

def new_chat(page, app):
    if app == 'qwen':
        page.get_by_text('新对话', exact=True).first.click(timeout=10000)
    elif app == 'yuanbao':
        page.locator('[aria-label="新建对话"]').filter(has_text='新建对话').first.click(timeout=10000)
    else:
        page.locator('[data-testid="create_conversation_button"] [role="button"]').first.click(timeout=10000)
    page.wait_for_timeout(1500)

def editor(page, app):
    if app == 'qwen':
        return page.locator('[role="textbox"][aria-multiline="true"]:visible').last
    if app == 'yuanbao':
        return page.locator('[contenteditable="true"]:visible').last
    return page.locator('textarea[data-testid="chat_input_input"]:visible, [data-testid="chat_input_input"] [contenteditable="true"]:visible').last

def upload(page, app, image):
    if app == 'doubao':
        page.locator('input[data-testid="upload-file-input"]').set_input_files(str(image))
        page.get_by_role('button', name=image.name).wait_for(timeout=30000)
    else:
        page.get_by_role('button', name='添加附件' if app == 'qwen' else '添加', exact=True).click()
        with page.expect_file_chooser(timeout=10000) as chooser:
            page.get_by_role('menuitem', name='上传图片').click()
        chooser.value.set_files(str(image))
        if app == 'yuanbao':
            page.locator('[aria-label^="预览图片"] img').first.wait_for(state='visible', timeout=30000)
            page.wait_for_function("() => {const e=document.querySelector('[aria-label^=\"预览图片\"] img');return !!e && e.complete && e.naturalWidth>0}", timeout=30000)
        else:
            page.wait_for_function("() => [...document.images].some(x=>x.src.includes('workspace-zb-cdn.qianwen.com') && x.complete && x.naturalWidth>0)", timeout=30000)

def image_mode(page, app):
    if app == 'qwen':
        page.get_by_role('button', name='AI生图', exact=True).first.click(timeout=10000)
    elif app == 'yuanbao':
        page.get_by_role('button', name='AI 生图', exact=True).first.click(timeout=10000)
    else:
        page.get_by_role('button', name='图像生成', exact=True).first.click(timeout=10000)

def state(page, app):
    return page.evaluate(support.page_state_js(app))

def wait_answer(page, app, element):
    deadline = time.monotonic() + TIMEOUTS[element]
    last, stable = None, 0
    while time.monotonic() < deadline:
        s = state(page, app)
        if support.CHALLENGE_RE.search(s.get('title', '') + '\n' + s.get('bodyTail', '')):
            raise RuntimeError('页面出现验证或访问限制，请人工处理后重采')
        identity = (s['text'], tuple(s['images']))
        ready = bool(s['images']) if element == 'A3' else bool(s['text'] and s['complete'])
        stable = stable + 1 if ready and identity == last else 0
        if stable >= 2:
            return s
        last = identity
        page.wait_for_timeout(1500)
    raise RuntimeError('等待结果超时，请检查页面后重采')

def one(page, app, activity, stage, interfaces):
    element = activity['element']
    folder = support.next_attempt_folder(stage, app, element)
    folder.mkdir(parents=True)
    op = {'app': app, 'element': element, 'activity': activity['activity'],
          'prompt': activity['prompt'], 'prompt_group': activity.get('prompt_group'), 'answer': None, 'generated_files': [],
          'success': False, 'client': 'web', 'capture_interfaces': ['WLAN'],
          'input_image': activity.get('input_image'), 'created_at': support.now()}
    cap = support.Capture(folder, interfaces, TIMEOUTS[element] + 90)
    try:
        page.bring_to_front()
        op['setup_started_at'] = support.now()
        new_chat(page, app)
        if element == 'A3':
            image_mode(page, app)
        op['setup_ended_at'] = support.now()
        cap.start()
        op['capture_started_at'] = cap.started_at
        if element == 'A4':
            op['upload_started_at'] = support.now()
            upload(page, app, ROOT / activity['input_image'])
            op['upload_ended_at'] = support.now()
        editor(page, app).fill(activity['prompt'], timeout=10000)
        op['send_started_at'] = support.now()
        selector = {'qwen':'[aria-label="发送消息"]', 'yuanbao':'#yuanbao-send-btn',
                    'doubao':'[data-testid="chat_input_send_button"]'}[app]
        page.locator(selector).last.click(timeout=10000)
        op['send_command_ended_at'] = support.now()
        result = wait_answer(page, app, element)
        op['response_observed_at'] = support.now()
        op['chat_url'] = result['url']
        op['answer'] = None if element == 'A3' else result['text']
        if element != 'A3' and not op['answer']:
            raise RuntimeError('回答为空')
        if element == 'A2' and len(op['answer'].split()) < 500:
            raise RuntimeError('长文少于 500 词，保留失败记录')
        cap.stop()
        op['capture_ended_at'] = cap.ended_at
        op['capture_quality'] = cap.verify()
        if element == 'A3':
            op['generated_files'] = support.save_images(result['images'], folder, False)
        op['success'] = True
        return op
    except Exception as exc:
        op['error'] = str(exc)
        op['error_type'] = type(exc).__name__
        raise
    finally:
        cap.stop()
        op['capture_started_at'] = cap.started_at
        op['capture_ended_at'] = cap.ended_at
        support.write_json(folder / 'operation.json', op)

def main():
    parser = argparse.ArgumentParser(description='使用已打开的三个网页采集流量')
    parser.add_argument('--run-dir', type=Path, default=ROOT / 'runs' / ('standalone_' + dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')))
    parser.add_argument('--group', type=int, choices=range(1, 101), default=1, help='提示词组号 1-100')
    parser.add_argument('--apps', nargs='+', choices=HOSTS, default=['yuanbao', 'doubao'])
    parser.add_argument('--activities', nargs='+', choices=TIMEOUTS, default=list(TIMEOUTS))
    parser.add_argument('--check', action='store_true', help='只检查连接与网卡')
    parser.add_argument('--no-package', action='store_true')
    args = parser.parse_args()
    bank = json.loads((ROOT / 'prompt_groups.json').read_text(encoding='utf-8'))
    selected = bank['groups'][str(args.group)]
    plan = {x['element']: {**x, 'prompt_group': args.group} for x in selected['activities']}
    print(f'提示词组：{args.group}', flush=True)
    interfaces = wlan_interfaces()
    info = json.loads(command('session', 'info', '--json'))
    if not info.get('success') or not info.get('data', {}).get('active') or not info.get('data', {}).get('runtime', {}).get('browserLaunched'):
        raise RuntimeError('没有找到正在运行的 traffic-sites 浏览器会话；请先打开已登录的采集浏览器')
    endpoint = command('get', 'cdp-url')
    with sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(endpoint, timeout=10000)
        pages = find_pages(browser, args.apps)
        print('已连接网页：' + '、'.join(args.apps) + '；抓包网卡：WLAN（请确认目标网站未使用代理）', flush=True)
        if args.check:
            return 0
        run_dir = args.run_dir.resolve()
        snapshot = run_dir / 'prompt_group.json'
        if snapshot.exists():
            previous = json.loads(snapshot.read_text(encoding='utf-8'))
            if previous != selected:
                raise RuntimeError('续跑目录中的提示词组或内容不一致，请使用原组和原提示词')
        elif (run_dir / 'staging').exists() and any((run_dir / 'staging').iterdir()):
            raise RuntimeError('旧采集目录没有提示词组快照，不能用新版程序续跑；请使用新目录')
        else:
            run_dir.mkdir(parents=True, exist_ok=True)
            snapshot.write_text(json.dumps(selected, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        stage = run_dir / 'staging'
        capture_config = run_dir / 'capture_config.json'
        expected_config = {'capture_interfaces': ['WLAN']}
        if capture_config.exists():
            if json.loads(capture_config.read_text(encoding='utf-8')) != expected_config:
                raise RuntimeError('续跑目录的抓包接口不一致，请使用新的运行目录')
        elif stage.exists() and any(stage.iterdir()):
            raise RuntimeError('已有采集记录没有 WLAN 配置，不能与新版混合；请使用新目录')
        else:
            capture_config.write_text(json.dumps(expected_config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        stage.mkdir(parents=True, exist_ok=True)
        print('运行目录：', args.run_dir.resolve(), flush=True)
        for app in args.apps:
            for element in args.activities:
                if support.success_exists(stage, app, element):
                    print('跳过已成功：', app, element, flush=True)
                    continue
                print('开始：', app, element, flush=True)
                try:
                    one(pages[app], app, plan[element], stage, interfaces)
                except Exception as exc:
                    print(f'暂停：{app}/{element}：{exc}\n请检查网页，处理后用相同 --run-dir 重新运行。', flush=True)
                    return 1
                print('成功：', app, element, flush=True)
        complete = all(support.success_exists(stage, app, e) for app in args.apps for e in args.activities)
        if complete and not args.no_package:
            subprocess.run([sys.executable, str(ROOT / 'package_dataset.py'), '--staging', str(stage),
                '--output', str(args.run_dir / '大模型'), '--fixture', str(ROOT / plan['A4']['input_image']),
                '--zip', str(args.run_dir / '大模型.zip'), '--apps', *args.apps, '--activities', *args.activities], check=True)
        elif not complete:
            print('当前仅完成部分活动；所选应用和活动全部完成后将自动整理。', flush=True)
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('程序停止：', exc, file=sys.stderr)
        raise SystemExit(1)
