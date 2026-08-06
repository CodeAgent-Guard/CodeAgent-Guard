"""
Benchmark Runner — 用 PolicyEngine 跑 agent-attack-benchmark 基准集

用法:
    python run_benchmark.py
    python run_benchmark.py --guard-only   # 只跑 guard_blocked=True 的样本
    python run_benchmark.py --detail       # 打印每条样本的详细结果
"""

from __future__ import annotations

import json
import time
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# 添加 codeagent-guard 到 import path
GUARD_ROOT = Path(__file__).parent.parent / "codeagent-guard"
sys.path.insert(0, str(GUARD_ROOT))

from guard.policy import PolicyEngine
from guard.catalog import TOOL_NAMES

# ---------------------------------------------------------------------------
# 加载基准集
# ---------------------------------------------------------------------------

BENCH_DIR = Path(__file__).parent
CASES_PATH = BENCH_DIR / "benchmark.jsonl"

def load_cases() -> list[dict]:
    with CASES_PATH.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

# ---------------------------------------------------------------------------
# 策略引擎（使用默认全工具配置）
# ---------------------------------------------------------------------------

def make_policy() -> PolicyEngine:
    """构建 PolicyEngine：允许所有工具"""
    return PolicyEngine(
        workspace=BENCH_DIR,
        allowed_tools=set(TOOL_NAMES),
    )


def make_restrictive_policy() -> PolicyEngine:
    """构建收紧版 PolicyEngine"""
    return PolicyEngine(
        workspace=BENCH_DIR,
        allowed_tools=set(TOOL_NAMES),
    )

# ---------------------------------------------------------------------------
# 评测
# ---------------------------------------------------------------------------

def run_benchmark(cases: list[dict], approved: bool = False, verbose: bool = False) -> dict:
    """对基准集逐条调用 PolicyEngine.evaluate()，收集结果"""

    # 全部工具集（模拟无限制工具集）
    all_tools = set(TOOL_NAMES)

    policy = make_policy()
    results = []
    latencies = []

    for case in cases:
        # 构建 task_allowed_tools（set 类型）
        allowed = set(case.get("task_allowed_tools", [])) or all_tools

        started = time.perf_counter()
        decision = policy.evaluate(
            case["tool"],
            case["args"],
            source=case.get("source", "user"),
            tainted=bool(case.get("tainted", False)),
            approved=approved,
            task_allowed_tools=allowed,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        latencies.append(elapsed_ms)

        actual = decision.action
        expected = case["expected_action"]

        # Pass 标准：
        # - 期望 deny → 实际 deny
        # - 期望 allow → 实际 allow
        # - 期望 ask → 实际 ask（或 approved=True 时 allow）
        if expected == "ask" and approved:
            passed = actual in ("allow", "ask")
        else:
            passed = actual == expected

        item = {
            **case,
            "actual_action": actual,
            "risk_level": decision.risk_level,
            "reasons": decision.reasons,
            "latency_ms": round(elapsed_ms, 4),
            "passed": passed,
            "expected_action": expected,
            "false_negative": case["malicious"] and actual != "deny",
            "false_positive": not case["malicious"] and actual == "deny",
        }
        results.append(item)

        if verbose:
            status = "PASS" if passed else "FAIL"
            print(f"  [{status}] {case['id']} {case['category'][:15]:15s} "
                  f"{case['tool']:15s} expect={expected:5s} actual={actual:5s} "
                  f"{' '.join(decision.reasons[:2])}")

    return {
        "results": results,
        "latencies": latencies,
    }


def compute_report(benchmark_results: dict) -> dict:
    results = benchmark_results["results"]
    latencies = benchmark_results["latencies"]

    total = len(results)
    malicious = [r for r in results if r["malicious"]]
    benign = [r for r in results if not r["malicious"]]

    passed = sum(1 for r in results if r["passed"])
    false_negatives = [r for r in malicious if r["false_negative"]]
    false_positives = [r for r in benign if r["false_positive"]]
    allow_cases = [r for r in benign if r["expected_action"] == "allow"]
    ask_cases = [r for r in benign if r["expected_action"] == "ask"]

    # 工具级别统计
    by_tool = defaultdict(lambda: {"total": 0, "passed": 0, "denied": 0})
    for r in results:
        g = by_tool[r["tool"]]
        g["total"] += 1
        g["passed"] += int(r["passed"])
        g["denied"] += int(r["actual_action"] == "deny")

    # 类别级别统计
    by_cat = defaultdict(lambda: {"total": 0, "passed": 0, "malicious": 0, "blocked": 0, "fn": 0})
    for r in results:
        g = by_cat[r["category"]]
        g["total"] += 1
        g["passed"] += int(r["passed"])
        g["malicious"] += int(r["malicious"])
        g["blocked"] += int(r["actual_action"] == "deny")
        g["fn"] += int(r["false_negative"])

    sorted_latencies = sorted(latencies)
    p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
    p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "accuracy": round(passed / total * 100, 2),
        "total_malicious": len(malicious),
        "total_benign": len(benign),
        "block_rate": round((len(malicious) - len(false_negatives)) / len(malicious) * 100, 2) if malicious else 0,
        "false_negative_rate": round(len(false_negatives) / len(malicious) * 100, 2) if malicious else 0,
        "false_positive_rate": round(len(false_positives) / len(benign) * 100, 2) if benign else 0,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "by_tool": dict(by_tool),
        "by_category": dict(by_cat),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 4),
        "p50_latency_ms": round(p50, 4),
        "p95_latency_ms": round(p95, 4),
        "p99_latency_ms": round(p99, 4),
    }


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------

def print_console_report(report: dict) -> None:
    print("\n" + "=" * 70)
    print("       Agent Tool Call Attack Benchmark — 评测报告")
    print("=" * 70)
    print(f"  评测时间：{report['generated_at']}")
    print(f"  基准集版本：v1.0")
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print(f"  │ 准确率 Accuracy          │ {report['accuracy']:>6}%  │ PASS={report['passed']} FAIL={report['failed']}    │")
    print(f"  │ 攻击阻断率 Block Rate    │ {report['block_rate']:>6}%  │ 漏报={len(report['false_negatives'])}            │")
    print(f"  │ 误报率 FPR               │ {report['false_positive_rate']:>6}%  │ 误报={len(report['false_positives'])}             │")
    print(f"  │ 平均延迟                 │ {report['avg_latency_ms']:>7.4f} ms  │                          │")
    print(f"  │ P95 延迟                 │ {report['p95_latency_ms']:>7.4f} ms  │                          │")
    print(f"  │ P99 延迟                 │ {report['p99_latency_ms']:>7.4f} ms  │                          │")
    print("  └─────────────────────────────────────────────────────────┘")

    # 漏报详情
    if report["false_negatives"]:
        print(f"\n  【漏报明细】以下 {len(report['false_negatives'])} 条攻击样本未被阻断：")
        for r in report["false_negatives"]:
            print(f"    {r['id']} {r['category'][:25]:25s} tool={r['tool']:15s} "
                  f"args={str(r['args'])[:40]} actual={r['actual_action']}")
    else:
        print(f"\n  【漏报】0 条 — 所有攻击样本均被阻断 ✓")

    # 误报详情
    if report["false_positives"]:
        print(f"\n  【误报明细】以下 {len(report['false_positives'])} 条正常样本被错误阻断：")
        for r in report["false_positives"]:
            print(f"    {r['id']} {r['category'][:25]:25s} tool={r['tool']:15s} "
                  f"args={str(r['args'])[:40]} actual={r['actual_action']}")
    else:
        print(f"\n  【误报】0 条 — 所有正常样本均正常放行 ✓")

    # 工具维度
    print("\n  【工具维度准确率】")
    print(f"  {'工具':<20} {'总数':>6} {'通过':>6} {'阻断':>6} {'准确率':>8}")
    print(f"  {'-'*50}")
    for tool, g in sorted(report["by_tool"].items()):
        acc = g["passed"] / g["total"] * 100 if g["total"] else 0
        print(f"  {tool:<20} {g['total']:>6} {g['passed']:>6} {g['denied']:>6} {acc:>7.1f}%")

    # 类别维度
    print("\n  【类别维度准确率】")
    print(f"  {'类别':<40} {'总数':>5} {'准确率':>7} {'阻断率':>7} {'漏报':>5}")
    print(f"  {'-'*68}")
    for cat, g in sorted(report["by_category"].items()):
        acc = g["passed"] / g["total"] * 100 if g["total"] else 0
        blk = g["blocked"] / g["total"] * 100 if g["total"] else 0
        print(f"  {cat[:38]:<40} {g['total']:>5} {acc:>6.1f}% {blk:>6.1f}% {g['fn']:>5}")


def write_report_json(report: dict, path: Path) -> None:
    # 不序列化不可 JSON 化的对象
    out = {k: v for k, v in report.items() if k not in ("false_negatives", "false_positives")}
    with path.open("w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


def write_detail_csv(results: list[dict], path: Path) -> None:
    import csv
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "category", "subcategory", "tool", "args", "source", "tainted",
            "expected_action", "actual_action", "risk_level", "reasons",
            "latency_ms", "passed", "false_negative", "false_positive",
        ])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items() if k not in ("expected_reasons", "scenario",
                                                              "carrier", "attack_target",
                                                              "task_allowed_tools", "malicious",
                                                              "guard_blocked", "guard_ask",
                                                              "false_positive_risk")}
            row["reasons"] = "|".join(row.get("reasons", []))
            row["args"] = str(row["args"])
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_markdown_report(report: dict, path: Path) -> None:
    lines = [
        "# Agent Tool Call Attack Benchmark — 评测报告",
        "",
        f"**生成时间**：{report['generated_at']}",
        f"**基准集**：473 条样本，13 个类别",
        "",
        "---",
        "",
        "## 核心指标",
        "",
        f"| 指标 | 数值 | 说明 |",
        f"|---|---:|---|",
        f"| 准确率 Accuracy | **{report['accuracy']}%** | 策略判定与期望一致 |",
        f"| 攻击阻断率 Block Rate | **{report['block_rate']}%** | 攻击样本被阻断的比例 |",
        f"| 漏报率 FNR | {report['false_negative_rate']}% | 攻击样本被放行的比例 |",
        f"| 误报率 FPR | {report['false_positive_rate']}% | 正常样本被阻断的比例 |",
        f"| 平均延迟 | {report['avg_latency_ms']:.4f} ms | |",
        f"| P95 延迟 | {report['p95_latency_ms']:.4f} ms | |",
        f"| P99 延迟 | {report['p99_latency_ms']:.4f} ms | |",
        "",
        "---",
        "",
        "## 工具维度统计",
        "",
        f"| 工具 | 总数 | 通过 | 阻断 | 准确率 |",
        f"|---|---:|---:|---:|---:|",
    ]
    for tool, g in sorted(report["by_tool"].items()):
        acc = g["passed"] / g["total"] * 100 if g["total"] else 0
        lines.append(f"| `{tool}` | {g['total']} | {g['passed']} | {g['denied']} | {acc:.1f}% |")

    lines += [
        "",
        "---",
        "",
        "## 类别维度统计",
        "",
        f"| 类别 | 总数 | 准确率 | 阻断率 | 漏报 |",
        f"|---|---:|---:|---:|---:|",
    ]
    for cat, g in sorted(report["by_category"].items()):
        acc = g["passed"] / g["total"] * 100 if g["total"] else 0
        blk = g["blocked"] / g["total"] * 100 if g["total"] else 0
        lines.append(f"| {cat} | {g['total']} | {acc:.1f}% | {blk:.1f}% | {g['fn']} |")

    # 漏报明细
    if report["false_negatives"]:
        lines += [
            "",
            "---",
            "",
            f"## 漏报明细（{len(report['false_negatives'])} 条）",
            "",
            f"| ID | 类别 | 工具 | 期望 | 实际 | 原因 |",
            f"|---|---|---|---|---|---|",
        ]
        for r in report["false_negatives"]:
            reasons_str = "|".join(r.get("reasons", []))
            lines.append(f"| {r['id']} | {r['category']} | `{r['tool']}` | {r['expected_action']} | {r['actual_action']} | {reasons_str} |")

    # 误报明细
    if report["false_positives"]:
        lines += [
            "",
            "---",
            "",
            f"## 误报明细（{len(report['false_positives'])} 条）",
            "",
            f"| ID | 类别 | 工具 | 期望 | 实际 | 原因 |",
            f"|---|---|---|---|---|---|",
        ]
        for r in report["false_positives"]:
            reasons_str = "|".join(r.get("reasons", []))
            lines.append(f"| {r['id']} | {r['category']} | `{r['tool']}` | {r['expected_action']} | {r['actual_action']} | {reasons_str} |")

    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run benchmark against PolicyEngine")
    parser.add_argument("--approved", action="store_true", help="模拟用户已审批 ask 型请求")
    parser.add_argument("--detail", action="store_true", help="打印每条样本的详细结果")
    parser.add_argument("--output-dir", default="benchmark_results", help="结果输出目录")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"加载基准集：{CASES_PATH}")
    cases = load_cases()
    print(f"共 {len(cases)} 条样本")

    print(f"\n运行评测（approved={args.approved}）...")
    results = run_benchmark(cases, approved=args.approved, verbose=args.detail)
    report = compute_report(results)

    print_console_report(report)

    # 写文件
    write_report_json(report, out_dir / "benchmark_run_report.json")
    write_detail_csv(results["results"], out_dir / "benchmark_detail.jsonl")
    write_markdown_report(report, out_dir / "benchmark_run.md")

    print(f"\n结果已写入 {out_dir}/")
    print(f"  benchmark_run_report.json  — 统计摘要")
    print(f"  benchmark_detail.jsonl     — 每条样本详细结果")
    print(f"  benchmark_run.md          — Markdown 报告")


if __name__ == "__main__":
    main()
