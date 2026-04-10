"""
BloodHound 可视化生成器
生成交互式攻击路径图和域结构图
"""

import json
from typing import Dict, List, Any, Optional
from pathlib import Path


class VisualizationGenerator:
    """可视化生成器"""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def generate_attack_path_html(self, paths: List[Dict], title: str = "Attack Path Analysis") -> str:
        """
        生成攻击路径的可视化 HTML

        Args:
            paths: 攻击路径列表
            title: 图表标题

        Returns:
            HTML 字符串
        """
        # 构建节点和边的数据
        nodes = []
        edges = []
        node_ids = {}

        for path in paths:
            path_name = f"path_{path.get('target', 'unknown')}"
            path_nodes = path.get('path', [])

            for step in path_nodes:
                from_name = step.get('from', step.get('from_name', ''))
                to_name = step.get('to', step.get('to_name', ''))
                relation = step.get('relation', '')

                # 添加节点
                if from_name not in node_ids:
                    node_ids[from_name] = len(nodes)
                    nodes.append({
                        'id': from_name,
                        'label': from_name,
                        'type': self._get_node_type(from_name),
                        'color': self._get_node_color(self._get_node_type(from_name))
                    })

                if to_name not in node_ids:
                    node_ids[to_name] = len(nodes)
                    nodes.append({
                        'id': to_name,
                        'label': to_name,
                        'type': self._get_node_type(to_name),
                        'color': self._get_node_color(self._get_node_type(to_name))
                    })

                # 添加边
                edges.append({
                    'from': from_name,
                    'to': to_name,
                    'label': relation,
                    'color': self._get_edge_color(relation)
                })

        return self._generate_d3_html(nodes, edges, title)

    def _generate_d3_html(self, nodes: List[Dict], edges: List[Dict], title: str) -> str:
        """生成 D3.js 力导向图 HTML"""
        import random
        nodes_json = json.dumps(nodes, ensure_ascii=False)
        edges_json = json.dumps(edges, ensure_ascii=False)

        # 使用固定布局确保内容显示
        positions = []
        for i, node in enumerate(nodes):
            x = 200 + (i % 4) * 180
            y = 150 + (i // 4) * 150
            positions.append({'x': x, 'y': y})

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #0d0d15 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        header {{
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            padding: 15px 30px;
            border-bottom: 2px solid #00ff88;
        }}
        h1 {{ color: #00ff88; font-size: 22px; margin: 0; }}
        .subtitle {{ color: #888; font-size: 13px; margin-top: 5px; }}
        #container {{
            flex: 1;
            position: relative;
            overflow: hidden;
        }}
        svg {{
            width: 100%;
            height: calc(100vh - 80px);
            display: block;
        }}
        .node circle {{
            fill: #4ecdc4;
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .node.user circle {{ fill: #ff6b6b; }}
        .node.group circle {{ fill: #ffe66d; }}
        .node.domain circle {{ fill: #a29bfe; }}
        .node.target circle {{
            fill: #ff4757;
            stroke: #fff;
            stroke-width: 3px;
            filter: drop-shadow(0 0 10px #ff4757);
        }}
        .node.highlight circle {{
            stroke: #00ff88;
            stroke-width: 3px;
        }}
        .node text {{
            font-size: 12px;
            fill: #fff;
            text-anchor: middle;
            text-shadow: 0 1px 3px rgba(0,0,0,0.9);
        }}
        .link {{
            stroke: #555;
            stroke-width: 2px;
        }}
        .link.high {{
            stroke: #ff4757;
            stroke-width: 3px;
        }}
        .link.medium {{ stroke: #ffa502; }}
        .link-label {{
            font-size: 10px;
            fill: #aaa;
            text-anchor: middle;
            pointer-events: none;
        }}
        .legend {{
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(26, 26, 46, 0.95);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 15px;
        }}
        .legend-title {{ color: #00ff88; margin-bottom: 10px; }}
        .legend-item {{ display: flex; align-items: center; margin: 6px 0; }}
        .legend-dot {{ width: 14px; height: 14px; border-radius: 50%; margin-right: 10px; }}
        .stats {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(26, 26, 46, 0.95);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 15px 20px;
        }}
        .stat-value {{ color: #00ff88; font-weight: bold; }}
        .tooltip {{
            position: absolute;
            background: rgba(26, 26, 46, 0.98);
            border: 1px solid #00ff88;
            border-radius: 6px;
            padding: 10px 14px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 100;
        }}
        .tooltip.visible {{ opacity: 1; }}
        .instructions {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(26, 26, 46, 0.9);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 10px 15px;
            font-size: 11px;
            color: #888;
        }}
    </style>
</head>
<body>
    <header>
        <h1>{title}</h1>
        <div class="subtitle">Active Directory Attack Path Visualization</div>
    </header>

    <div id="container">
        <svg id="graph"></svg>
        <div class="tooltip" id="tooltip"></div>

        <div class="legend">
            <div class="legend-title">Legend</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ff6b6b"></div>User</div>
            <div class="legend-item"><div class="legend-dot" style="background:#4ecdc4"></div>Computer</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ffe66d"></div>Group</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a29bfe"></div>Domain</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ff4757"></div>Target (Domain Admins)</div>
        </div>

        <div class="stats">
            <div>Nodes: <span class="stat-value">{len(nodes)}</span></div>
            <div>Edges: <span class="stat-value">{len(edges)}</span></div>
        </div>

        <div class="instructions">
            Drag nodes to rearrange | Scroll to zoom | Click node for details
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js"></script>
    <script>
        const rawNodes = {nodes_json};
        const rawEdges = {edges_json};

        // 初始化节点位置
        const nodes = rawNodes.map((n, i) => ({{
            ...n,
            x: 150 + (i % 3) * 250,
            y: 100 + Math.floor(i / 3) * 180
        }}));
        const links = rawEdges.map(e => ({{ ...e }}));
        const linkMap = {{}};
        links.forEach((l, i) => {{
            const key = (typeof l.source === 'object' ? l.source.id : l.source) + '-' + (typeof l.target === 'object' ? l.target.id : l.target);
            if (!linkMap[key]) linkMap[key] = i;
        }});

        const svg = d3.select('#graph');
        const container = document.getElementById('container');
        const width = container.clientWidth;
        const height = container.clientHeight;

        const g = svg.append('g');

        // 缩放
        const zoom = d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform));
        svg.call(zoom);

        // 力模拟
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id || d.source).distance(120))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width/2, height/2))
            .force('collision', d3.forceCollide().radius(70));

        // 边
        const link = g.append('g').selectAll('line')
            .data(links)
            .join('line')
            .attr('class', d => {{
                const rel = (d.label || d.relation || '').toLowerCase();
                if (rel.includes('generic') || rel.includes('owns') || rel.includes('all') || rel.includes('shadow')) return 'link high';
                if (rel.includes('write')) return 'link medium';
                return 'link';
            }})
            .attr('stroke-opacity', 0.7);

        // 边标签
        const linkLabel = g.append('g').selectAll('text')
            .data(links)
            .join('text')
            .attr('class', 'link-label')
            .text(d => {{
                const label = d.label || d.relation || '';
                return label.length > 15 ? label.substring(0, 15) : label;
            }});

        // 节点
        const node = g.append('g').selectAll('g')
            .data(nodes)
            .join('g')
            .attr('class', d => {{
                let cls = 'node ';
                if (d.id === 'Domain Admins' || d.id === 'Administrators' || d.id === 'Enterprise Admins') cls += 'target ';
                else if (d.type === 'group' || d.id.includes('Admins') || d.id.includes('Accounts')) cls += 'group ';
                else if (d.type === 'domain' || d.id === 'FOREST') cls += 'domain ';
                else cls += 'user ';
                return cls;
            }});

        node.append('circle').attr('r', 28);
        node.append('text')
            .attr('dy', 42)
            .text(d => d.label.length > 14 ? d.label.substring(0, 14) : d.label);

        // 拖拽
        const drag = d3.drag()
            .on('start', e => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; }})
            .on('drag', e => {{ e.subject.fx = e.x; e.subject.fy = e.y; }})
            .on('end', e => {{ if (!e.active) simulation.alphaTarget(0); e.subject.fx = null; e.subject.fy = null; }});
        node.call(drag);

        // 工具提示
        const tooltip = d3.select('#tooltip');
        node.on('mouseover', (e, d) => {{
            const label = d.label || d.id || '';
            const type = d.type || 'unknown';
            tooltip.classed('visible', true)
                .html('<b>' + label + '</b><br/>Type: ' + type);
            tooltip.style('left', (e.pageX + 15) + 'px').style('top', (e.pageY - 10) + 'px');
        }}).on('mousemove', e => {{
            tooltip.style('left', (e.pageX + 15) + 'px').style('top', (e.pageY - 10) + 'px');
        }}).on('mouseout', () => tooltip.classed('visible', false));

        simulation.on('tick', () => {{
            link
                .attr('x1', d => typeof d.source === 'object' ? d.source.x : d.source)
                .attr('y1', d => typeof d.source === 'object' ? d.source.y : d.source)
                .attr('x2', d => typeof d.target === 'object' ? d.target.x : d.target)
                .attr('y2', d => typeof d.target === 'object' ? d.target.y : d.target);

            linkLabel
                .attr('x', d => ((typeof d.source === 'object' ? d.source.x : d.source) + (typeof d.target === 'object' ? d.target.x : d.target)) / 2)
                .attr('y', d => ((typeof d.source === 'object' ? d.source.y : d.source) + (typeof d.target === 'object' ? d.target.y : d.target)) / 2);

            node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
        }});

        // 初始居中
        svg.call(zoom.transform, d3.zoomIdentity.translate(50, 50));
    </script>
</body>
</html>'''

        return html

    def _get_node_type(self, name: str) -> str:
        """根据名称判断节点类型"""
        name_upper = name.upper()

        if any(kw in name_upper for kw in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'ADMINISTRATORS']):
            return 'group'
        if any(kw in name_upper for kw in ['BUILTIN', 'S-1-5-32']):
            return 'builtin'

        return 'unknown'

    def _get_node_color(self, node_type: str) -> str:
        """获取节点颜色"""
        colors = {
            'user': '#ff6b6b',
            'computer': '#4ecdc4',
            'group': '#ffe66d',
            'domain': '#a29bfe',
            'builtin': '#74b9ff',
            'unknown': '#636e72'
        }
        return colors.get(node_type, '#636e72')

    def _get_edge_color(self, relation: str) -> str:
        """获取边颜色"""
        relation_upper = relation.upper()

        if 'MEMBER' in relation_upper:
            return '#74b9ff'
        if 'OWNS' in relation_upper or 'ALL' in relation_upper:
            return '#ff4757'
        if 'WRITE' in relation_upper:
            return '#ff6348'
        if 'SESSION' in relation_upper or 'ADMIN' in relation_upper:
            return '#ffa502'
        if 'DELEGATION' in relation_upper:
            return '#a29bfe'

        return '#636e72'


class ReportGenerator:
    """报告生成器"""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def generate_attack_path_report(self, source: str, target: str, paths: List[Dict]) -> str:
        """生成攻击路径分析报告 (Markdown)"""
        lines = []
        lines.append(f"# 攻击路径分析报告\n")
        lines.append(f"**源账户:** `{source}`  \n")
        lines.append(f"**目标:** `{target}`  \n")
        lines.append(f"**发现路径数:** {len(paths)}\n")

        if not paths:
            lines.append("> 未找到从源到目标的攻击路径")
            return "\n".join(lines)

        lines.append(f"\n---\n\n")

        risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_paths = sorted(paths, key=lambda x: risk_order.get(x.get('risk_level', 'Medium'), 2))

        for i, path in enumerate(sorted_paths[:10], 1):
            lines.append(f"## 路径 {i}\n")
            lines.append(f"| 属性 | 值 |")
            lines.append(f"|------|-----|")
            lines.append(f"| 步骤数 | {path.get('steps', 'N/A')} |")
            lines.append(f"| 风险等级 | {path.get('risk_level', 'Unknown')} |")
            lines.append(f"| 难度 | {path.get('difficulty', 'Unknown')} |")
            lines.append(f"| 攻击技术 | {', '.join(path.get('attack_methods', []))} |\n")

            lines.append(f"### 详细步骤\n")
            lines.append(f"| 步骤 | 来源 | 目标 | 关系 |")
            lines.append(f"|------|------|------|------|")

            for step in path.get('path', []):
                lines.append(f"| {step.get('step', '')} | {step.get('from', '')} | {step.get('to', '')} | {step.get('relation', '')} |")

            lines.append(f"\n### 摘要\n")
            lines.append(f"{path.get('summary', 'N/A')}\n")
            lines.append(f"\n---\n")

        lines.append(f"\n## 建议\n")
        lines.append(f"1. 优先处理 Critical/High 风险的路径\n")
        lines.append(f"2. 监控高价值账户的活动\n")
        lines.append(f"3. 定期审查 ACL 权限配置\n")

        return "\n".join(lines)

    def generate_security_report(self) -> str:
        """生成安全评估报告"""
        lines = []
        lines.append(f"# Active Directory 安全评估报告\n")

        stats = self.analyzer.get_statistics()
        lines.append(f"## 域概况\n")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 用户数 | {stats['total_users']} |")
        lines.append(f"| 计算机数 | {stats['total_computers']} |")
        lines.append(f"| 组数 | {stats['total_groups']} |")
        lines.append(f"| 图节点 | {stats['total_nodes']} |")
        lines.append(f"| 图边 | {stats['total_edges']} |\n")

        priv_users = self.analyzer.find_privileged_users()
        lines.append(f"\n## 特权用户\n")

        if priv_users['asrep_roastable']:
            lines.append(f"### ASREP Roastable 用户 ({len(priv_users['asrep_roastable'])})\n")
            for user in priv_users['asrep_roastable']:
                lines.append(f"- `{user}` - 可离线破解 AS-REP 响应\n")
            lines.append(f"\n**建议:** 除非业务需要，禁用 '不需要 Kerberos 预认证' 选项\n")

        if priv_users['kerberoastable']:
            lines.append(f"### Kerberoastable 用户 ({len(priv_users['kerberoastable'])})\n")
            for user in priv_users['kerberoastable']:
                lines.append(f"- `{user}` - 可离线破解 SPN 票据\n")
            lines.append(f"\n**建议:** 使用强密码或托管服务账户\n")

        if priv_users['unconstrained_delegation']:
            lines.append(f"### 无约束委派用户 ({len(priv_users['unconstrained_delegation'])})\n")
            for user in priv_users['unconstrained_delegation']:
                lines.append(f"- `{user}` - 可捕获 TGT\n")
            lines.append(f"\n**建议:** 将无约束委派迁移到约束委派或基于资源的约束委派\n")

        issues = self.analyzer.find_security_issues()
        if issues:
            lines.append(f"\n## 安全问题 ({len(issues)} 个)\n")

            by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
            for issue in issues:
                severity = issue.get('severity', 'Medium')
                by_severity[severity].append(issue)

            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if by_severity[severity]:
                    icons = {'Critical': 'CRITICAL', 'High': 'HIGH', 'Medium': 'MEDIUM', 'Low': 'LOW'}
                    lines.append(f"### {icons[severity]} ({len(by_severity[severity])})\n")
                    for issue in by_severity[severity][:20]:
                        lines.append(f"- **{issue['type']}:** {issue['target']}\n")
                        lines.append(f"  - {issue['description']}\n")
                    lines.append(f"\n")

        domain_info = self.analyzer.get_domain_info()
        lines.append(f"\n## 域信息\n")
        lines.append(f"- **域名:** {domain_info['name']}\n")
        lines.append(f"- **SID:** {domain_info['sid']}\n")
        lines.append(f"- **功能级别:** {domain_info['functional_level']}\n")

        return "\n".join(lines)

    def generate_user_report(self, username: str) -> str:
        """生成用户分析报告"""
        user_info = self.analyzer.query_user(username)

        if 'error' in user_info:
            return f"# 错误\n\n{user_info['error']}"

        lines = []
        lines.append(f"# 用户分析报告: {username}\n")
        lines.append(f"\n## 基本信息\n")
        lines.append(f"| 属性 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| SID | `{user_info['sid']}` |")
        lines.append(f"| 摘要 | {user_info['summary']} |\n")

        lines.append(f"\n## 安全属性\n")
        lines.append(f"| 属性 | 状态 | 风险 |")
        lines.append(f"|------|------|------|")

        attrs = [
            ('ASREP Roastable', user_info.get('is_asrep_roastable', False), '可离线破解密码哈希'),
            ('Kerberoastable', user_info.get('is_kerberoastable', False), '可离线破解 SPN 票据'),
            ('无约束委派', user_info.get('is_unconstrained_delegation', False), '可捕获 TGT'),
            ('高价值目标', user_info.get('is_high_value', False), '权限账户需重点保护')
        ]

        for attr, value, risk in attrs:
            status = 'YES' if value else 'NO'
            lines.append(f"| {attr} | {status} | {risk} |")

        if user_info.get('member_of'):
            lines.append(f"\n## 组成员关系 ({len(user_info['member_of'])})\n")
            for group in user_info['member_of']:
                lines.append(f"- {group}\n")

        outbound = user_info.get('outbound_acl', [])
        if outbound:
            lines.append(f"\n## 出站权限 ({len(outbound)})\n")
            privileged = [a for a in outbound if a.get('is_privileged', False)]
            if privileged:
                lines.append(f"### 特权 ACL ({len(privileged)})\n")
                lines.append(f"| 目标 | 权限 | 来源 |")
                lines.append(f"|------|------|------|")
                for acl in privileged[:20]:
                    via = f" (via {acl.get('via', '')})" if acl.get('via') else ''
                    lines.append(f"| {acl.get('target', '')} | {acl.get('right', '')} | {acl.get('via', username)}{via} |")

        inbound = user_info.get('inbound_acl', [])
        if inbound:
            lines.append(f"\n## 入站权限 ({len(inbound)})\n")
            lines.append(f"| 来源 | 权限 | 描述 |")
            lines.append(f"|------|------|------|")
            for acl in inbound[:20]:
                lines.append(f"| {acl.get('source', '')} | {acl.get('right', '')} | {acl.get('description', '')} |")

        return "\n".join(lines)


if __name__ == "__main__":
    from core import BloodHoundAnalyzer

    analyzer = BloodHoundAnalyzer(r"C:\Users\90898\Desktop\htb_forest\BloodHoundData")
    analyzer.load()

    viz_gen = VisualizationGenerator(analyzer)
    report_gen = ReportGenerator(analyzer)

    paths_result = analyzer.find_all_paths("svc-alfresco", "Domain Admins", max_hops=5)
    if paths_result.get('found'):
        html = viz_gen.generate_attack_path_html(paths_result.get('paths', [])[:5], "svc-alfresco Attack Paths")
        with open("attack_paths.html", "w", encoding="utf-8") as f:
            f.write(html)
        print("[+] 生成 attack_paths.html")

    report = report_gen.generate_security_report()
    with open("security_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    print("[+] 生成 security_report.md")

    user_report = report_gen.generate_user_report("svc-alfresco")
    with open("svc-alfresco_report.md", "w", encoding="utf-8") as f:
        f.write(user_report)
    print("[+] 生成 svc-alfresco_report.md")
