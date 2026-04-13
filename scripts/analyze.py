"""
BloodHound Analyzer 快速分析脚本

用法:
    python scripts/analyze.py <数据目录>           # 显示统计信息
    python scripts/analyze.py <数据目录> user <username>    # 查询用户
    python scripts/analyze.py <数据目录> path <source> <target>  # 查找路径
    python scripts/analyze.py <数据目录> pathx <source> <target> [max_hops]  # 任意节点+详细渗透思路
    python scripts/analyze.py <数据目录> agentpath <source> <target> [max_hops] # 生成供AI继续分析的结构化上下文
    python scripts/analyze.py <数据目录> nodes <keyword>  # 搜索节点
    python scripts/analyze.py <数据目录> report    # 生成安全报告
    python scripts/analyze.py <数据目录> visualize <source> <target> [max_hops] # 生成源到目标的路径专用可视化
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.core import BloodHoundAnalyzer
from src.analyzer.visualizer import VisualizationGenerator, ReportGenerator


def _print_chain_detail(chain: dict):
    print(f"路径步数: {chain.get('steps', 0)} | 风险: {chain.get('risk_level', '未知')} | 难度: {chain.get('difficulty', '未知')}")
    print(f"摘要: {chain.get('summary', '')}")
    print("\n详细步骤:")
    for step in chain.get('path', []):
        print(f"  [{step['step']}] {step['from']} --[{step['relation']}]--> {step['to']}")
        print(f"       说明: {step.get('description', '')}")

    plans = chain.get('penetration_plan', [])
    if plans:
        print("\n详细渗透思路:")
        for p in plans:
            print(f"  [{p.get('step', '?')}] {p.get('from', '')} -> {p.get('to', '')} ({p.get('relation', '')})")
            print(f"       思路: {p.get('idea', '')}")
            print(f"       执行: {p.get('action', '')}")
            print(f"       验证: {p.get('verify', '')}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n示例:")
        print("  python scripts/analyze.py C:\\data\\BloodHoundData stats")
        print("  python scripts/analyze.py C:\\data\\BloodHoundData user svc-alfresco")
        print("  python scripts/analyze.py C:\\data\\BloodHoundData path svc-alfresco Domain Admins")
        return

    # 检查第一个参数是否是数据目录
    first_arg = sys.argv[1]
    if Path(first_arg).is_dir():
        DATA_DIR = first_arg
        args = sys.argv[2:]
    else:
        print("[!] 请指定有效的 BloodHound 数据目录路径")
        return

    if not args:
        print(__doc__)
        return

    cmd = args[0].lower()

    # 初始化分析器
    analyzer = BloodHoundAnalyzer(DATA_DIR)
    if not analyzer.load():
        print("[!] 数据加载失败")
        return

    if cmd == "stats" or cmd == "stat":
        # 统计信息
        stats = analyzer.get_statistics()
        domain_info = analyzer.get_domain_info()

        print("\n=== BloodHound 数据统计 ===\n")
        print(f"域: {domain_info['name']} ({domain_info['functional_level']})")
        print(f"用户: {stats['total_users']}")
        print(f"计算机: {stats['total_computers']}")
        print(f"组: {stats['total_groups']}")
        print(f"图节点: {stats['total_nodes']}")
        print(f"图边: {stats['total_edges']}")

    elif cmd == "user" and len(args) >= 2:
        username = " ".join(args[1:])
        user_info = analyzer.query_user(username)

        if "error" in user_info:
            print(f"[!] {user_info['error']}")
            return

        print(f"\n=== 用户: {username} ===\n")
        print(f"SID: {user_info['sid']}")
        print(f"摘要: {user_info['summary']}")
        print(f"\n成员组: {', '.join(user_info['member_of']) if user_info['member_of'] else '无'}")

        priv_acl = [a for a in user_info['outbound_acl'] if a.get('is_privileged', False)]
        print(f"特权 ACL: {len(priv_acl)} 条")

        if priv_acl:
            print("\n出站特权权限:")
            for acl in priv_acl[:10]:
                print(f"  -> {acl['target']} [{acl['right']}]")

    elif cmd == "path" and len(args) >= 3:
        source = args[1]
        target = args[2]

        print(f"\n=== 攻击路径: {source} -> {target} ===\n")

        path = analyzer.find_attack_path(source, target)
        if path.get('found'):
            _print_chain_detail(path)
        else:
            print(f"未找到路径: {path.get('message', '')}")
            if path.get('source_candidates'):
                print("源节点候选:")
                for n in path.get('source_candidates', []):
                    print(f"  - {n}")
            if path.get('target_candidates'):
                print("目标节点候选:")
                for n in path.get('target_candidates', []):
                    print(f"  - {n}")

        print(f"\n查找所有路径 (最多5跳)...")
        all_paths = analyzer.find_all_paths(source, target, max_hops=5)
        if all_paths.get('found'):
            print(f"发现 {all_paths['path_count']} 条路径")
        else:
            print("未找到任何路径")

    elif cmd == "pathx" and len(args) >= 3:
        source = args[1]
        target = args[2]
        max_hops = int(args[3]) if len(args) >= 4 and str(args[3]).isdigit() else 6

        print(f"\n=== 任意节点攻击路径与渗透思路: {source} -> {target} ===\n")

        all_paths = analyzer.find_all_paths(source, target, max_hops=max_hops)
        if not all_paths.get('found'):
            print(f"未找到路径: {all_paths.get('message', '')}")
            if all_paths.get('source_candidates'):
                print("\n源节点候选:")
                for n in all_paths.get('source_candidates', []):
                    print(f"  - {n}")
            if all_paths.get('target_candidates'):
                print("\n目标节点候选:")
                for n in all_paths.get('target_candidates', []):
                    print(f"  - {n}")
            print("\n可先用 nodes 命令搜索节点名，例如:")
            print("  python scripts/analyze.py BloodHoundData nodes Admin")
            return

        print(f"共发现 {all_paths['path_count']} 条路径，展示前 3 条高价值链路:\n")
        for idx, chain in enumerate(all_paths.get('paths', [])[:3], 1):
            print(f"\n--- 路径 {idx} ---")
            _print_chain_detail(chain)

    elif cmd == "agentpath" and len(args) >= 3:
        source = args[1]
        target = args[2]
        max_hops = int(args[3]) if len(args) >= 4 and str(args[3]).isdigit() else 6

        print(f"\n=== Agent Handoff: {source} -> {target} ===\n")
        handoff = analyzer.build_agent_handoff(source, target, max_hops=max_hops)

        if not handoff.get("found"):
            print(f"[!] {handoff.get('message', '未找到路径')}")
            if handoff.get("source_candidates"):
                print("源节点候选:")
                for n in handoff.get("source_candidates", []):
                    print(f"  - {n}")
            if handoff.get("target_candidates"):
                print("目标节点候选:")
                for n in handoff.get("target_candidates", []):
                    print(f"  - {n}")
            return

        print(f"路径总数: {handoff.get('path_count', 0)}")
        rec = handoff.get("recommended_path", {})
        print(f"推荐路径: 风险={rec.get('risk_level', 'Unknown')} | 步数={rec.get('steps', 0)}")
        print("\n推荐路径步骤:")
        for s in rec.get("path", []):
            print(f"  [{s.get('step')}] {s.get('from')} --[{s.get('relation')}]--> {s.get('to')}")

        print("\nAI 连续分析提示词:")
        print(handoff.get("continuation_prompt", ""))

        out_file = "agent_handoff.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(handoff, f, ensure_ascii=False, indent=2)
        print(f"\n[+] 已生成 {out_file}")

    elif cmd == "nodes" and len(args) >= 2:
        keyword = " ".join(args[1:])
        result = analyzer.search_nodes(keyword, limit=15)

        print(f"\n=== 节点搜索: {keyword} ===\n")
        if result.get("count", 0) == 0:
            print("未找到匹配节点")
            return

        print(f"匹配到 {result['count']} 个节点:")
        for i, n in enumerate(result["nodes"], 1):
            print(f"  {i}. {n['name']} ({n['type']})")

    elif cmd == "compromise" and len(args) >= 2:
        username = " ".join(args[1:])
        result = analyzer.analyze_compromise(username)

        print(f"\n=== 被控分析: {username} ===\n")

        if "error" in result:
            print(f"[!] {result['error']}")
            return

        print(f"可利用漏洞: {len(result['vulnerabilities'])}")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln['type']} ({vuln['severity']})")

        print(f"\n可直接控制: {len(result['potential_targets'])}")
        for t in result['potential_targets'][:10]:
            print(f"  - {t['target']} [{t['right']}]")

        print(f"\n攻击路径: {len(result['attack_paths'])} 条")
        for ap in result['attack_paths'][:5]:
            print(f"  -> {ap['target']} ({ap['risk']}, {ap['steps']}步)")

    elif cmd == "privileged" or cmd == "priv":
        priv = analyzer.find_privileged_users()

        print("\n=== 特权用户 ===\n")

        print(f"ASREP Roastable ({len(priv['asrep_roastable'])}):")
        for u in priv['asrep_roastable']:
            print(f"  - {u}")

        print(f"\nKerberoastable ({len(priv['kerberoastable'])}):")
        for u in priv['kerberoastable']:
            print(f"  - {u}")

        print(f"\n无约束委派 ({len(priv['unconstrained_delegation'])}):")
        for u in priv['unconstrained_delegation']:
            print(f"  - {u}")

    elif cmd == "security" or cmd == "issues":
        issues = analyzer.find_security_issues()

        print(f"\n=== 安全问题 ({len(issues)} 个) ===\n")

        by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for issue in issues:
            severity = issue.get('severity', 'Medium')
            by_severity[severity].append(issue)

        icons = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}

        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if by_severity[severity]:
                print(f"\n{icons[severity]} {severity} ({len(by_severity[severity])}):")
                for issue in by_severity[severity][:10]:
                    print(f"  - {issue['type']}: {issue['target']}")

    elif cmd == "report":
        print("\n=== 生成安全报告 ===\n")

        report_gen = ReportGenerator(analyzer)
        report = report_gen.generate_security_report()

        with open("security_report.md", "w", encoding="utf-8") as f:
            f.write(report)
        print("[+] 已生成 security_report.md")

        user_report = report_gen.generate_user_report("svc-alfresco")
        with open("user_report.md", "w", encoding="utf-8") as f:
            f.write(user_report)
        print("[+] 已生成 user_report.md")

    elif cmd == "visualize" or cmd == "viz":
        print("\n=== 生成可视化 ===\n")

        viz_gen = VisualizationGenerator(analyzer)

        if len(args) < 3:
            print("[!] visualize 模式需要 source 和 target")
            print("示例:")
            print("  python scripts/analyze.py BloodHoundData visualize svc-alfresco \"Domain Admins\" 5")
            return

        source = args[1]
        target = args[2]
        max_hops = int(args[3]) if len(args) >= 4 and str(args[3]).isdigit() else 5

        paths = analyzer.find_all_paths(source, target, max_hops=max_hops)
        if not paths.get('found'):
            print(f"[!] 未找到路径: {paths.get('message', '')}")
            if paths.get('source_candidates'):
                print("源节点候选:")
                for n in paths.get('source_candidates', []):
                    print(f"  - {n}")
            if paths.get('target_candidates'):
                print("目标节点候选:")
                for n in paths.get('target_candidates', []):
                    print(f"  - {n}")
            return

        html = viz_gen.generate_path_focus_html(
            source=source,
            target=target,
            paths=paths.get('paths', [])[:12],
            title=f"Path Explorer - {source} -> {target}"
        )
        with open("attack_paths.html", "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] 已生成 attack_paths.html (路径数: {min(paths.get('path_count', 0), 12)})")

        print("[+] 完成")

    else:
        print(f"[!] 未知命令: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
