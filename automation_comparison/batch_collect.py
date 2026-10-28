"""Interactive batch launcher for existing authenticated traffic-sites browser."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLLECT = ROOT / 'automation_comparison' / 'collect.py'
APP_MENU = {'1': ['yuanbao'], '2': ['doubao'], '3': ['yuanbao', 'doubao']}
ACT_MENU = {'1': 'A1', '2': 'A2', '3': 'A3', '4': 'A4'}


def ask_choice(prompt, valid):
    while True:
        value = input(prompt).strip()
        if value in valid:
            return value
        print('输入无效，请重新输入。', flush=True)


def ask_activities():
    while True:
        value = input('选择活动：1=A1 简单对话  2=A2 长文  3=A3 生图  4=A4 图片理解  5=全部\n可输入多个数字并用逗号隔开，例如 1,4：').strip().replace('，', ',')
        parts = [x.strip() for x in value.split(',')]
        if parts == ['5']:
            return list(ACT_MENU.values())
        if parts and all(x in ACT_MENU for x in parts) and len(set(parts)) == len(parts):
            return [ACT_MENU[x] for x in parts]
        print('输入无效，请输入 1～4、逗号组合，或 5。', flush=True)


def ask_number(prompt, minimum, maximum, default=None):
    while True:
        value = input(prompt).strip()
        if not value and default is not None:
            return default
        if value.isdecimal() and minimum <= int(value) <= maximum:
            return int(value)
        print(f'请输入 {minimum}～{maximum} 的整数。', flush=True)


def main():
    parser = argparse.ArgumentParser(description='批量采集：一个提示词组对应每个所选应用和活动各一次')
    parser.add_argument('--apps', nargs='+', choices=['yuanbao', 'doubao'])
    parser.add_argument('--activities', nargs='+', choices=['A1', 'A2', 'A3', 'A4'])
    parser.add_argument('--count', type=int)
    parser.add_argument('--start', type=int, default=1)
    args = parser.parse_args()
    if args.apps is None and args.activities is None and args.count is None:
        print('请选择本次采集范围（使用已登录的采集浏览器，关闭代理后采集）。')
        apps = APP_MENU[ask_choice('应用：1=元宝  2=豆包  3=两个都采集：', APP_MENU)]
        activities = ask_activities()
        count = ask_number('采集多少组提示词（1～100）：', 1, 100)
        start = ask_number(f'从第几组开始（1～{101-count}，直接回车为 1）：', 1, 101-count, 1)
    else:
        if not args.apps or not args.activities or args.count is None:
            parser.error('命令行模式需同时指定 --apps、--activities 和 --count')
        apps, activities, count, start = args.apps, args.activities, args.count, args.start
    if len(set(apps)) != len(apps) or len(set(activities)) != len(activities):
        parser.error('应用及活动不能重复')
    if not (1 <= count <= 100 and 1 <= start <= 101-count):
        parser.error('组数及起始组超出 1～100 范围')
    batch = ROOT / 'runs' / ('batch_' + dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    batch.mkdir(parents=True)
    config = {'apps': apps, 'activities': activities, 'count': count, 'start_group': start,
              'total_operations': len(apps) * len(activities) * count}
    (batch / 'batch_config.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'批次目录：{batch}\n预计活动次数：{config["total_operations"]}，实际执行到失败时暂停。', flush=True)
    for group in range(start, start+count):
        run_dir = batch / f'group_{group:03d}'
        print(f'\n===== 组 {group} / {start+count-1} =====', flush=True)
        cmd = [sys.executable, str(COLLECT), '--group', str(group), '--run-dir', str(run_dir),
               '--apps', *apps, '--activities', *activities]
        result = subprocess.run(cmd)
        if result.returncode:
            print(f'采集暂停：第 {group} 组；目录：{run_dir}\n处理问题后请按使用说明续跑，尚未开始后续组。', flush=True)
            return result.returncode
    print(f'\n批量采集完成：{batch}', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EOFError, KeyboardInterrupt):
        print('\n已取消；当前正在运行的抓包如未正常关闭，请检查 dumpcap。', file=sys.stderr)
        raise SystemExit(1)
