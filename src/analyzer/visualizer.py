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

    def generate_full_graph_html(self, title: str = "Attack Graph Explorer") -> str:
        """
        基于已加载的全量图数据生成可视化 HTML（支持任意节点搜索与路径推演）

        Args:
            title: 图表标题

        Returns:
            HTML 字符串
        """
        graph = getattr(self.analyzer, "graph_builder", None)
        if not graph or not getattr(graph, "G", None):
            return self._generate_d3_html([], [], title)

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        for sid, attrs in graph.G.nodes(data=True):
            name = attrs.get("name", sid)
            node_type = attrs.get("node_type", "unknown")

            # 统一映射为前端样式类型
            if node_type not in ["user", "computer", "group", "domain"]:
                node_type = self._get_node_type(name)

            nodes.append({
                "id": name,
                "label": name,
                "type": node_type,
                "color": self._get_node_color(node_type),
                "sid": sid
            })

        for source_sid, target_sid, eattrs in graph.G.edges(data=True):
            source_name = graph.G.nodes[source_sid].get("name", source_sid)
            target_name = graph.G.nodes[target_sid].get("name", target_sid)
            relation = eattrs.get("relation", "Unknown")
            edges.append({
                "from": source_name,
                "to": target_name,
                "label": relation,
                "color": self._get_edge_color(relation)
            })

        # 去重，避免同名重复节点导致前端关系混淆
        unique_nodes = {}
        for n in nodes:
            unique_nodes[n["id"]] = n

        return self._generate_d3_html(list(unique_nodes.values()), edges, title)

    def generate_path_focus_html(self, source: str, target: str, paths: List[Dict],
                                 title: str = "Path Explorer") -> str:
        """生成仅包含源到目标路径节点的专用可视化页面。"""
        path_payload: List[Dict[str, Any]] = []

        for i, p in enumerate(paths):
            steps = p.get("path", [])
            if not steps:
                continue

            path_payload.append({
                "id": i + 1,
                "risk_level": p.get("risk_level", "Unknown"),
                "difficulty": p.get("difficulty", "未知"),
                "summary": p.get("summary", ""),
                "attack_methods": p.get("attack_methods", []),
                "steps": steps,
                "penetration_plan": p.get("penetration_plan", [])
            })

        payload_json = json.dumps(path_payload, ensure_ascii=False)
        source_json = json.dumps(source, ensure_ascii=False)
        target_json = json.dumps(target, ensure_ascii=False)

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <script src="d3.min.js"></script>
    <style>
        :root {{
            --bg0:#090d16; --bg1:#111a29; --panel:rgba(14,22,36,.94);
            --border:#2b3d5d; --text:#e8f1ff; --muted:#93a8cb;
            --accent:#2be6a4; --danger:#ff677f; --warn:#ffc46b;
        }}
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{
            font-family:'Microsoft YaHei','Segoe UI',sans-serif;
            background:
              radial-gradient(1200px 500px at 10% -10%, #243e6a 0%, transparent 45%),
              radial-gradient(900px 600px at 100% 0%, #3b1a56 0%, transparent 45%),
              linear-gradient(135deg,var(--bg0),var(--bg1));
            color:var(--text);
            height:100vh;
            overflow:hidden;
        }}
        .layout {{ display:grid; grid-template-columns: 1.15fr 0.85fr; height:100vh; gap:12px; padding:12px; }}
        .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; box-shadow:0 10px 28px rgba(0,0,0,.35); }}
        .left {{ position:relative; overflow:hidden; }}
        .right {{ padding:12px; overflow:auto; }}
        .head {{ padding:12px 14px; border-bottom:1px solid #2a3c5b; }}
        .title {{ font-size:18px; color:#d9ffe9; }}
        .sub {{ font-size:12px; color:var(--muted); margin-top:4px; }}
        .toolbar {{ display:flex; gap:8px; align-items:center; margin-top:10px; flex-wrap:wrap; }}
        .pill {{ border:1px solid #2d456b; color:#add3ff; border-radius:999px; padding:4px 9px; font-size:11px; }}
        .select {{
            background:#0d1628; color:#e3eeff; border:1px solid #35507b;
            border-radius:8px; padding:7px 9px; font-size:12px; min-width:220px;
        }}
        #graph {{ width:100%; height:calc(100% - 112px); display:block; }}
        .node circle {{ stroke:#ecf4ff; stroke-width:1.8px; }}
        .node text {{ fill:#eff6ff; font-size:11px; text-anchor:middle; pointer-events:none; text-shadow:0 1px 3px rgba(0,0,0,.9); }}
        .link {{ stroke:#6f83a6; stroke-width:2px; stroke-opacity:.6; marker-end:url(#arrow); }}
        .link.high {{ stroke:var(--danger); stroke-width:2.8px; }}
        .link.medium {{ stroke:var(--warn); stroke-width:2.4px; }}
        .link-label {{ fill:#9cb2d9; font-size:10px; text-anchor:middle; pointer-events:none; }}
        .summary {{ margin-bottom:12px; padding:10px; border:1px solid #2d4369; border-radius:10px; background:rgba(11,18,30,.9); }}
        .risk {{ color:#ffd89b; font-weight:700; }}
        .step-card {{ margin-bottom:10px; padding:10px; border:1px solid #2b4168; border-radius:10px; background:rgba(10,17,29,.92); }}
        .step-h {{ font-size:12px; color:#e8f3ff; margin-bottom:4px; }}
        .step-r {{ font-size:11px; color:#8af4c8; margin-bottom:6px; }}
        .k {{ color:#a4d9ff; font-size:11px; margin-top:5px; }}
        .v {{ color:#cedbf7; font-size:11px; line-height:1.45; }}
        ul.v {{ margin-left:16px; }}
        @media (max-width: 1100px) {{ .layout {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="layout">
        <div class="left panel">
            <div class="head">
                <div class="title">{title}</div>
                <div class="sub">仅展示源到目标路径节点 | Source: <b id="src"></b> -> Target: <b id="dst"></b></div>
                <div class="toolbar">
                    <span class="pill" id="count-pill"></span>
                    <select id="path-select" class="select"></select>
                </div>
            </div>
            <svg id="graph"></svg>
        </div>

        <div class="right panel">
            <div id="summary" class="summary"></div>
            <div id="steps"></div>
        </div>
    </div>

    <script>
        const sourceName = {source_json};
        const targetName = {target_json};
        const paths = {payload_json};

        document.getElementById('src').textContent = sourceName;
        document.getElementById('dst').textContent = targetName;
        document.getElementById('count-pill').textContent = '候选路径: ' + paths.length;

        const select = document.getElementById('path-select');
        paths.forEach((p, i) => {{
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = `路径 #${{p.id}} | 风险:${{p.risk_level}} | 步骤:${{p.steps.length}}`;
            select.appendChild(opt);
        }});

        const svg = d3.select('#graph');
        const g = svg.append('g');
        const width = document.getElementById('graph').clientWidth;
        const height = document.getElementById('graph').clientHeight;

        const defs = svg.append('defs');
        defs.append('marker')
            .attr('id', 'arrow')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 22)
            .attr('refY', 0)
            .attr('markerWidth', 5)
            .attr('markerHeight', 5)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#8ea6d1');

        const zoom = d3.zoom().scaleExtent([0.45, 2.8]).on('zoom', e => g.attr('transform', e.transform));
        svg.call(zoom);

        function relationClass(rel) {{
            const r = (rel || '').toLowerCase();
            if (r.includes('all') || r.includes('owns') || r.includes('shadow')) return 'link high';
            if (r.includes('write') || r.includes('session') || r.includes('delegate')) return 'link medium';
            return 'link';
        }}

        function fallbackPlan(step) {{
            return {{
                relation: step.relation,
                idea: '基于该关系评估权限扩展与横向可达性。',
                action: '先验证关系有效，再执行最小化策略推进下一跳。',
                verify: '确认新增可达边或更高权限上下文。'
            }};
        }}

        function drawPath(index) {{
            const p = paths[index];
            if (!p) return;

            g.selectAll('*').remove();

            const nodeMap = new Map();
            p.steps.forEach((s, i) => {{
                if (!nodeMap.has(s.from)) nodeMap.set(s.from, {{ id:s.from, label:s.from, x:120 + i*170, y:height/2 - 60 }});
                if (!nodeMap.has(s.to)) nodeMap.set(s.to, {{ id:s.to, label:s.to, x:260 + i*170, y:height/2 + 70 }});
            }});
            const nodes = Array.from(nodeMap.values());
            const links = p.steps.map(s => ({{ source:s.from, target:s.to, relation:s.relation, description:s.description }}));

            const sim = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(180))
                .force('charge', d3.forceManyBody().strength(-560))
                .force('center', d3.forceCenter(width/2, height/2))
                .force('collision', d3.forceCollide().radius(65));

            const link = g.append('g').selectAll('line').data(links).join('line').attr('class', d => relationClass(d.relation));
            const label = g.append('g').selectAll('text').data(links).join('text').attr('class', 'link-label').text(d => (d.relation || '').slice(0, 28));
            const node = g.append('g').selectAll('g').data(nodes).join('g').attr('class', 'node');

            node.append('circle')
                .attr('r', d => (d.id === sourceName || d.id === targetName) ? 34 : 28)
                .attr('fill', d => {{
                    const n = (d.id || '').toLowerCase();
                    if (d.id === sourceName) return '#3be8a5';
                    if (d.id === targetName) return '#ff5f7a';
                    if (n.includes('admin') || n.includes('domain')) return '#ffd06a';
                    if (n.includes('group')) return '#ffe47f';
                    return '#8fb8ff';
                }});

            node.append('text').attr('dy', 46).text(d => d.label.length > 18 ? d.label.slice(0, 18) + '…' : d.label);

            node.call(d3.drag()
                .on('start', e => {{ if (!e.active) sim.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; }})
                .on('drag', e => {{ e.subject.fx = e.x; e.subject.fy = e.y; }})
                .on('end', e => {{ if (!e.active) sim.alphaTarget(0); e.subject.fx = null; e.subject.fy = null; }}));

            sim.on('tick', () => {{
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                label.attr('x', d => (d.source.x + d.target.x)/2).attr('y', d => (d.source.y + d.target.y)/2 - 6);
                node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
            }});

            document.getElementById('summary').innerHTML = `
                <div><b>路径摘要</b></div>
                <div class="v" style="margin-top:6px;">${{p.summary || '无摘要'}}</div>
                <div class="v" style="margin-top:6px;">风险: <span class="risk">${{p.risk_level}}</span> | 难度: ${{p.difficulty}}</div>
                <div class="v" style="margin-top:4px;">技术: ${{(p.attack_methods || []).join(' / ')}}</div>
            `;

            const stepsBox = document.getElementById('steps');
            const plans = (p.penetration_plan && p.penetration_plan.length > 0) ? p.penetration_plan : [];
            stepsBox.innerHTML = p.steps.map((s, i) => {{
                const plan = plans.find(x => String(x.step) === String(s.step)) || fallbackPlan(s);
                return `
                    <div class="step-card">
                        <div class="step-h">步骤 ${{s.step}}: ${{s.from}} -> ${{s.to}}</div>
                        <div class="step-r">关系: ${{s.relation}}</div>
                        <div class="k">图谱证据</div>
                        <div class="v">${{s.description || '关系存在且可达。'}}</div>
                        <div class="k">思路</div>
                        <div class="v">${{plan.idea || '评估该关系是否可用于权限扩展。'}}</div>
                        <div class="k">执行路径</div>
                        <div class="v">${{plan.action || '先验证再推进下一跳。'}}</div>
                        <div class="k">验证标准</div>
                        <div class="v">${{plan.verify || '确认新权限或可达边已出现。'}}</div>
                    </div>
                `;
            }}).join('');

            svg.transition().duration(380).call(zoom.transform, d3.zoomIdentity.translate(35, 18).scale(0.95));
        }}

        select.addEventListener('change', e => drawPath(Number(e.target.value || 0)));
        drawPath(0);
    </script>
</body>
</html>'''

        return html

    def _generate_d3_html(self, nodes: List[Dict], edges: List[Dict], title: str) -> str:
        """生成 D3.js 力导向图 HTML"""
        nodes_json = json.dumps(nodes, ensure_ascii=False)
        edges_json = json.dumps(edges, ensure_ascii=False)

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <script src="d3.min.js"></script>
    <style>
        :root {{
            --bg-a: #090d14;
            --bg-b: #101928;
            --bg-c: #0b1420;
            --panel: rgba(14, 21, 33, 0.92);
            --panel-border: #24324b;
            --text: #e8f0ff;
            --muted: #90a0c0;
            --accent: #26e29a;
            --accent-2: #27d4ff;
            --danger: #ff5f7a;
            --warn: #ffbd58;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;
            background:
                radial-gradient(1200px 600px at 10% -10%, #1d3358 0%, transparent 45%),
                radial-gradient(900px 700px at 100% 0%, #2d1244 0%, transparent 40%),
                linear-gradient(140deg, var(--bg-a) 0%, var(--bg-b) 55%, var(--bg-c) 100%);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }}
        header {{
            background: rgba(6, 10, 18, 0.76);
            backdrop-filter: blur(8px);
            padding: 14px 24px;
            border-bottom: 1px solid #253655;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        h1 {{ color: #d6ffe8; font-size: 20px; margin: 0; letter-spacing: .2px; }}
        .subtitle {{ color: var(--muted); font-size: 12px; margin-top: 3px; }}
        .head-badge {{
            border: 1px solid #2f4669;
            color: #a8c8ff;
            font-size: 11px;
            border-radius: 999px;
            padding: 6px 10px;
            background: rgba(20, 32, 54, 0.7);
        }}
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
        .node circle {{ stroke: #e6f0ff; stroke-width: 1.8px; cursor: pointer; }}
        .node.user circle {{ fill: #ff758f; }}
        .node.group circle {{ fill: #ffd96a; }}
        .node.domain circle {{ fill: #9f95ff; }}
        .node.target circle {{ fill: #ff4a6c; stroke-width: 2.6px; filter: drop-shadow(0 0 12px rgba(255,74,108,0.65)); }}
        .node text {{
            font-size: 11px;
            fill: #f2f7ff;
            text-anchor: middle;
            text-shadow: 0 1px 4px rgba(0,0,0,0.95);
            pointer-events: none;
        }}
        .link {{ stroke: #5e6c89; stroke-width: 1.7px; stroke-opacity: 0.58; }}
        .link.high {{ stroke: #ff6a7d; stroke-width: 2.9px; }}
        .link.medium {{ stroke: #ffbd58; stroke-width: 2.2px; }}
        .link-label {{
            font-size: 9px;
            fill: #8fa2ca;
            text-anchor: middle;
            pointer-events: none;
        }}

        .glass {{
            background: var(--panel);
            border: 1px solid var(--panel-border);
            box-shadow: 0 8px 28px rgba(0,0,0,0.35);
            border-radius: 12px;
        }}
        .legend {{
            position: absolute;
            bottom: 16px;
            left: 16px;
            padding: 15px;
            z-index: 30;
        }}
        .legend-title {{ color: #b8ffd7; margin-bottom: 10px; font-size: 12px; }}
        .legend-item {{ display: flex; align-items: center; margin: 6px 0; font-size: 12px; color: #dce7ff; }}
        .legend-dot {{ width: 14px; height: 14px; border-radius: 50%; margin-right: 10px; }}
        .stats {{
            position: absolute;
            top: 16px;
            right: 16px;
            padding: 15px 20px;
            z-index: 30;
        }}
        .stats div {{ font-size: 12px; margin: 3px 0; color: #dce6ff; }}
        .stat-value {{ color: #8fffd3; font-weight: bold; }}
        .tooltip {{
            position: absolute;
            background: rgba(11, 18, 29, 0.98);
            border: 1px solid #33507a;
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 120;
            max-width: 280px;
        }}
        .tooltip.visible {{ opacity: 1; }}

        .control-panel {{
            position: absolute;
            top: 16px;
            left: 16px;
            width: 420px;
            padding: 14px;
            z-index: 40;
        }}
        .cp-title {{ font-size: 12px; color: #9edfff; margin-bottom: 8px; letter-spacing: .3px; }}
        .search-row {{ display: flex; gap: 8px; margin-bottom: 8px; }}
        .search-input, .search-select {{
            flex: 1;
            background: rgba(10, 16, 28, 0.9);
            color: #dce9ff;
            border: 1px solid #2f4468;
            border-radius: 8px;
            font-size: 12px;
            padding: 8px 10px;
            outline: none;
        }}
        .search-input:focus, .search-select:focus {{ border-color: var(--accent-2); }}
        .btn {{
            border: 0;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            padding: 8px 10px;
            cursor: pointer;
            color: #071420;
            background: linear-gradient(135deg, #31e9a7, #17c4ff);
            white-space: nowrap;
        }}
        .btn.secondary {{
            color: #cbddff;
            background: linear-gradient(135deg, #2c3d5e, #23334e);
        }}
        .search-result {{ color: #9eb3d8; font-size: 11px; line-height: 1.5; max-height: 70px; overflow: auto; }}
        .suggestions {{
            border: 1px solid #2a3d61;
            border-radius: 8px;
            max-height: 110px;
            overflow: auto;
            background: rgba(9, 15, 25, 0.96);
            margin-top: 6px;
        }}
        .s-item {{
            display: flex;
            justify-content: space-between;
            gap: 8px;
            padding: 7px 9px;
            font-size: 11px;
            color: #d9e6ff;
            cursor: pointer;
            border-bottom: 1px solid rgba(42,61,97,.5);
        }}
        .s-item:hover {{ background: rgba(31, 49, 79, 0.55); }}
        .s-tag {{ color: #88f0c7; font-size: 10px; }}

        .playbook {{
            position: absolute;
            right: 16px;
            bottom: 16px;
            width: 420px;
            max-height: 58vh;
            overflow: auto;
            padding: 12px;
            z-index: 40;
        }}
        .playbook-title {{ font-size: 12px; color: #9fd8ff; margin-bottom: 8px; }}
        .pb-step {{
            margin-bottom: 10px;
            padding: 10px;
            border: 1px solid #2b4066;
            border-radius: 10px;
            background: rgba(11, 19, 31, 0.92);
        }}
        .pb-head {{ color: #ddf6ff; font-size: 12px; margin-bottom: 6px; }}
        .pb-meta {{ color: #8effd2; font-size: 11px; margin-bottom: 5px; }}
        .pb-line {{ color: #c5d5f5; font-size: 11px; line-height: 1.45; }}
        .pb-sub {{
            margin-top: 7px;
            margin-bottom: 3px;
            color: #9fd6ff;
            font-size: 11px;
            font-weight: 600;
        }}
        .pb-ul {{
            margin: 0 0 2px 16px;
            color: #cad8f5;
            font-size: 11px;
            line-height: 1.45;
        }}
        .pb-risk {{ color: #ffd18a; font-weight: 600; }}
        .pb-ul {{ margin: 6px 0 0 18px; color: #d4e2ff; font-size: 11px; line-height: 1.45; }}
        .pb-ul li {{ margin: 3px 0; }}
        .pb-sub {{ color: #8fd1ff; margin-top: 8px; font-size: 11px; }}

        .search-panel {{
            display: none;
        }}
        .path-result {{ color: #b9ffd9; font-size: 11px; margin-top: 8px; line-height: 1.5; }}
        .node.search-match circle {{ stroke: #00e5ff; stroke-width: 4px; }}
        .node.path-match circle {{ stroke: #00ff88; stroke-width: 5px; }}
        .link.path-match {{ stroke: #00ff88 !important; stroke-width: 4px !important; stroke-opacity: 1 !important; }}
        .instructions {{
            position: absolute;
            bottom: 16px;
            right: 452px;
            border-radius: 8px;
            padding: 10px 15px;
            font-size: 11px;
            color: #98a9ca;
            z-index: 25;
        }}
        @media (max-width: 1200px) {{
            .control-panel {{ width: calc(100vw - 32px); }}
            .playbook {{ width: calc(100vw - 32px); right: 16px; left: 16px; bottom: 16px; max-height: 42vh; }}
            .instructions {{ display: none; }}
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>{title}</h1>
            <div class="subtitle">Attack Graph Command Center</div>
        </div>
        <div class="head-badge">BloodHound-Style Interactive Search</div>
    </header>

    <div id="container">
        <svg id="graph"></svg>
        <div class="tooltip" id="tooltip"></div>

        <div class="control-panel glass">
            <div class="cp-title">节点检索与路径定位</div>
            <div class="search-row">
                <input id="node-search" class="search-input" placeholder="搜索节点，例如: admin / svc / exch" />
                <button id="node-search-btn" class="btn">搜索</button>
                <button id="node-clear-btn" class="btn secondary">重置</button>
            </div>
            <div class="search-result" id="search-result"></div>

            <div class="search-row" style="margin-top:8px;">
                <input id="source-search" class="search-input" placeholder="起点" />
                <input id="target-search" class="search-input" placeholder="终点" />
                <button id="path-find-btn" class="btn">查路径</button>
            </div>
            <div class="search-row" style="margin-bottom:0;">
                <select id="source-suggest" class="search-select"></select>
                <select id="target-suggest" class="search-select"></select>
            </div>
            <div class="path-result" id="path-result"></div>
        </div>

        <div class="playbook glass" id="playbook">
            <div class="playbook-title">路径渗透思路（自动生成）</div>
            <div id="playbook-body" class="pb-line">选择起点与终点后，这里会显示每一步的漏洞原理、具体利用流程、验证点、告警痕迹与修复建议。</div>
        </div>

        <div class="legend glass">
            <div class="legend-title">Legend</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ff6b6b"></div>User</div>
            <div class="legend-item"><div class="legend-dot" style="background:#4ecdc4"></div>Computer</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ffe66d"></div>Group</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a29bfe"></div>Domain</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ff4757"></div>Target (Domain Admins)</div>
        </div>

        <div class="stats glass">
            <div>Nodes: <span class="stat-value">{len(nodes)}</span></div>
            <div>Edges: <span class="stat-value">{len(edges)}</span></div>
        </div>

        <div class="instructions glass">
            Drag nodes to rearrange | Scroll to zoom | Click node for details
        </div>
    </div>

    <script>
        const rawNodes = {nodes_json};
        const rawEdges = {edges_json};

        // 初始化节点位置
        const nodes = rawNodes.map((n, i) => ({{
            ...n,
            x: 150 + (i % 3) * 250,
            y: 100 + Math.floor(i / 3) * 180
        }}));
        const links = rawEdges.map(e => ({{ source: e.from, target: e.to, label: e.label }}));

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
            .force('link', d3.forceLink(links).id(d => d.id || d.source).distance(130))
            .force('charge', d3.forceManyBody().strength(-420))
            .force('center', d3.forceCenter(width/2, height/2))
            .force('collision', d3.forceCollide().radius(76));

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
            .attr('stroke-opacity', 0.7)
            .attr('x1', d => nodes.find(n => n.id === d.source)?.x || 0)
            .attr('y1', d => nodes.find(n => n.id === d.source)?.y || 0)
            .attr('x2', d => nodes.find(n => n.id === d.target)?.x || 0)
            .attr('y2', d => nodes.find(n => n.id === d.target)?.y || 0);

        // 边标签
        const linkLabel = g.append('g').selectAll('text')
            .data(links)
            .join('text')
            .attr('class', 'link-label')
            .text(d => {{
                const label = d.label || d.relation || '';
                return label.length > 18 ? label.substring(0, 18) + '…' : label;
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
            }})
            .attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');

        node.append('circle').attr('r', 30);
        node.append('text')
            .attr('dy', 45)
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

        function norm(v) {{
            return (v || '').toString().toLowerCase().trim();
        }}

        function edgeKey(sourceId, targetId) {{
            return sourceId + '->' + targetId;
        }}

        function resolveNodeIdByKeyword(keyword) {{
            const q = norm(keyword);
            if (!q) return null;

            const exact = nodes.find(n => norm(n.id) === q || norm(n.label) === q);
            if (exact) return exact.id;

            const fuzzy = nodes.find(n => norm(n.id).includes(q) || norm(n.label).includes(q));
            return fuzzy ? fuzzy.id : null;
        }}

        function searchCandidates(keyword, limit = 20) {{
            const q = norm(keyword);
            if (!q) return [];
            const arr = nodes.filter(n => norm(n.id).includes(q) || norm(n.label).includes(q));
            arr.sort((a, b) => a.label.localeCompare(b.label));
            return arr.slice(0, limit);
        }}

        function buildRelationMap() {{
            const m = new Map();
            rawEdges.forEach(e => {{
                m.set(e.from + '->' + e.to, e.label || '关系');
            }});
            return m;
        }}
        const relationMap = buildRelationMap();

        function inferPlan(relation) {{
            const r = norm(relation);
            if (r.includes('genericwrite') || (r.includes('write') && !r.includes('dacl') && !r.includes('owner'))) return {{
                risk: 'High',
                vuln: 'GenericWrite：可修改目标对象关键属性（如组成员、脚本路径、委派相关属性等）。',
                impact: '可从“可写”转化为“可控”，常用于跨组提权和建立下一跳访问。',
                precheck: [
                    '确认当前身份对目标对象具备 GenericWrite（可通过 ACL 枚举验证）。',
                    '确认目标对象类型（用户/组/计算机），决定可写属性范围。'
                ],
                steps: [
                    '先做“只读验证”：读取目标对象现有关键属性，记录基线。',
                    '执行最小变更提权：优先组成员或可控属性修改，避免一次性大范围改动。',
                    '立刻测试是否获得下一跳权限（如访问高价值组/主机）。',
                    '若成功，补充低噪声持久化并保存回滚参数。'
                ],
                verify: [
                    '目标对象属性确实变化且可见。',
                    '链路下一跳可达（权限边新增或访问成功）。'
                ],
                ops: [
                    '授权实验模板: 先做目录读取与ACL枚举（BloodHound/PowerView/ldap工具均可）。',
                    '授权实验模板: 执行最小化属性改动（仅保留下一跳所需权限）。',
                    '授权实验模板: 立即验证新身份/新权限是否能访问下一节点。'
                ],
                expected: ['预期结果: 图谱中出现新增可达边或更短路径。', '预期结果: 下一跳节点查询与访问验证通过。'],
                troubleshooting: ['若失败: 复核对象类型与可写属性是否匹配。', '若失败: 检查是否命中受保护组/受控策略导致变更未生效。'],
                detect: ['目录对象修改日志、组成员变更日志、异常 ACL 变更告警。'],
                defense: ['收敛 GenericWrite 到最小集合；高价值对象启用变更审批与实时告警。']
            }};
            if (r.includes('writedacl') || r.includes('writeowner')) return {{
                risk: 'High',
                vuln: 'WriteDacl/WriteOwner：可重写安全描述符，间接拿到更高权限（常见升权跳板）。',
                impact: '可直接塑造权限边，生成新的高危控制链。',
                precheck: [
                    '确认目标是高价值对象或可通向高价值对象。',
                    '确认当前身份可写 DACL/Owner 且变更会生效。'
                ],
                steps: [
                    '导出当前 ACL 作为回滚基线。',
                    '只添加最小化 ACE（例如仅满足下一步所需权限）。',
                    '验证新 ACE 生效后执行下一跳操作。',
                    '完成后按策略恢复或收敛临时权限。'
                ],
                verify: [
                    'ACL 中新增 ACE 可见，且仅包含预期权限。',
                    '下一跳动作（读写/成员变更）成功。'
                ],
                ops: [
                    '授权实验模板: 导出当前 ACL 作为回滚点。',
                    '授权实验模板: 添加最小 ACE，仅满足下一跳（例如目录复制或对象写权限）。',
                    '授权实验模板: 在新权限下执行下一跳验证（如目录复制权限验证）。'
                ],
                expected: ['预期结果: ACL 基线差异可见且最小化。', '预期结果: 下一步高价值操作具备执行条件。'],
                troubleshooting: ['若失败: 检查 ACE 写入目标DN是否正确。', '若失败: 检查复制权限是否同时满足多项前置权限。'],
                detect: ['对象 ACL 变更审计、Owner 变更审计、异常权限扩张告警。'],
                defense: ['限制 ACL 写入权限；高价值对象开启强审计与基线对比。']
            }};
            if (r.includes('genericall') || r.includes('owns') || r.includes('all')) return {{
                risk: 'Critical',
                vuln: 'GenericAll/Owns：对目标拥有几乎完全控制能力，可直接接管。',
                impact: '可对目标对象实施全量控制，通常可快速抵达域级高价值资产。',
                precheck: [
                    '确认目标对象价值和后续路径价值（避免无效接管）。',
                    '确认环境中告警策略，选择低噪声接管路径。'
                ],
                steps: [
                    '建立受控接管点（最小必要持久化）。',
                    '执行身份或权限切换，进入更高权限上下文。',
                    '按攻击链继续横向到下一高价值节点。',
                    '保留最少痕迹，避免重复变更同一对象。'
                ],
                verify: [
                    '可稳定以新权限访问目标资源。',
                    '后续节点可达且关键操作成功。'
                ],
                ops: [
                    '授权实验模板: 先建立临时受控身份，再执行目标对象接管验证。',
                    '授权实验模板: 用受控身份进行关键对象读取/管理操作验证。'
                ],
                expected: ['预期结果: 关键对象控制能力持续稳定。'],
                troubleshooting: ['若失败: 检查接管对象是否受策略保护（如AdminSDHolder类约束）。'],
                detect: ['高权限对象被修改、异常管理员会话、批量权限提升行为。'],
                defense: ['最小权限治理；高权限对象强制双人审批与行为审计。']
            }};
            if (r.includes('addkeycredentiallink') || r.includes('shadow')) return {{
                risk: 'Critical',
                vuln: 'Shadow Credentials：通过密钥凭据链路实现账户伪造认证。',
                impact: '可在不依赖传统口令的情况下建立高权限身份访问路径。',
                precheck: [
                    '确认目标支持相关认证流程且可写 KeyCredentialLink。',
                    '确认时钟同步与证书/密钥材料可用。'
                ],
                steps: [
                    '读取并备份目标现有凭据链路属性。',
                    '添加最小化凭据条目并立刻进行认证测试。',
                    '获得目标上下文后执行下一跳权限操作。',
                    '按作战策略决定清理或保留痕迹。'
                ],
                verify: [
                    '目标身份认证成功。',
                    '后续高价值对象访问成功。'
                ],
                ops: [
                    '授权实验模板: 备份目标KeyCredentialLink后执行最小化条目写入。',
                    '授权实验模板: 立即进行身份验证测试并记录票据行为。'
                ],
                expected: ['预期结果: 可在不使用原口令前提下完成授权身份验证。'],
                troubleshooting: ['若失败: 检查时间同步、证书材料与域控可达性。'],
                detect: ['关键身份对象凭据链路属性变更、异常证书登录行为。'],
                defense: ['限制该属性写权限；对关键对象启用认证与属性变更联动告警。']
            }};
            if (r.includes('forcechangepassword') || r.includes('resetpassword')) return {{
                risk: 'High',
                vuln: '密码重置权限：可直接接管目标账户身份。',
                impact: '能够快速切换身份上下文，形成即时横向访问能力。',
                precheck: [
                    '确认目标账户是否受保护（如管理账户保护策略）。',
                    '确认密码策略与登录限制。'
                ],
                steps: [
                    '执行密码变更前先记录原状态和回滚方案。',
                    '变更后立即验证认证能力并建立受控会话。',
                    '利用新会话继续下一跳高价值目标访问。'
                ],
                verify: [
                    '新凭据可用且会话建立成功。',
                    '目标链路下一节点可达。'
                ],
                ops: [
                    '授权实验模板: 先做账号策略检查，再执行密码重置。',
                    '授权实验模板: 以新身份建立一次最小权限会话并验证关键资源。'
                ],
                expected: ['预期结果: 目标账户身份可控，后续横向能力增加。'],
                troubleshooting: ['若失败: 检查密码策略、登录限制与认证协议兼容性。'],
                detect: ['密码重置审计事件、异常异地登录与短时多次认证失败。'],
                defense: ['对敏感账户启用重置审批与MFA；收敛重置权限委派范围。']
            }};
            if (r.includes('session') || r.includes('localadmin') || r.includes('delegate')) return {{
                risk: 'High',
                vuln: '会话/本地管理员/委派关系：可用于横向移动与身份复用。',
                impact: '能够扩大主机控制面并复用身份，快速连接更多高价值节点。',
                precheck: [
                    '确认会话主机在线与访问链路可达。',
                    '确认可执行最小化主机枚举。'
                ],
                steps: [
                    '优先收集会话上下文与可复用身份材料。',
                    '基于最短路径选择下一跳主机或高价值账户。',
                    '建立新会话后继续推进到目标对象。'
                ],
                verify: [
                    '身份材料可用，横向会话建立成功。',
                    '目标节点权限验证通过。'
                ],
                ops: [
                    '授权实验模板: 主机侧做最小化会话与权限枚举，避免高噪声扫描。',
                    '授权实验模板: 选择最短横向分支进行一次受控访问验证。'
                ],
                expected: ['预期结果: 新主机或新对象可达，图谱路径缩短。'],
                troubleshooting: ['若失败: 检查主机防护策略、远程协议开放状态与委派约束。'],
                detect: ['异常远程登录、委派滥用、主机间非常规横向连接。'],
                defense: ['限制委派配置、会话隔离、关键主机禁用高危远程管理路径。']
            }};
            if (r.includes('member') || r.includes('contains')) return {{
                risk: 'Medium',
                vuln: '组关系/包含关系：通过组嵌套继承实现权限放大。',
                impact: '为后续高危边（Write/All/Delegate）提供可达前置路径。',
                precheck: [
                    '确认组嵌套层级与目标组是否高价值。',
                    '确认当前链路中每层组关系均有效。'
                ],
                steps: [
                    '梳理当前组到目标组的继承路径。',
                    '验证每一层成员关系与有效权限。',
                    '在最短高收益分支执行下一步提权操作。'
                ],
                verify: [
                    '继承权限在目标资源上体现。',
                    '下一跳写权限或管理权限已具备。'
                ],
                ops: [
                    '授权实验模板: 导出组继承链并确认每一层成员关系。',
                    '授权实验模板: 逐层验证到高价值组的可达性。'
                ],
                expected: ['预期结果: 组继承路径连通且进入高危关系边。'],
                troubleshooting: ['若失败: 检查嵌套组解析是否跨域、大小写或命名别名导致误匹配。'],
                detect: ['组成员变更、嵌套组异常扩展、敏感组异常登录。'],
                defense: ['治理嵌套组复杂度；敏感组成员变更实时审计。']
            }};
            return {{
                risk: 'Unknown',
                vuln: '未知关系：需要先进行关系语义识别。',
                impact: '影响范围未知，需结合对象类型和业务上下文评估。',
                precheck: ['确认关系来源与边方向是否正确。'],
                steps: ['先做只读验证，再尝试最小化可利用动作。'],
                verify: ['确认是否产出新权限边。'],
                ops: ['授权实验模板: 保持只读验证优先，避免直接高风险变更。'],
                expected: ['预期结果: 关系语义得到确认并可归类。'],
                troubleshooting: ['若失败: 使用原始SharpHound属性回溯关系来源。'],
                detect: ['关注对象变更与认证异常。'],
                defense: ['建立权限基线与变更审计。']
            }};
        }}

        function updateSelect(id, keyword) {{
            const sel = document.getElementById(id);
            const cands = searchCandidates(keyword, 18);
            sel.innerHTML = '';
            if (cands.length === 0) {{
                const o = document.createElement('option');
                o.textContent = '无候选';
                o.value = '';
                sel.appendChild(o);
                return;
            }}
            cands.forEach((n, idx) => {{
                const o = document.createElement('option');
                o.value = n.id;
                o.textContent = n.label;
                if (idx === 0) o.selected = true;
                sel.appendChild(o);
            }});
        }}

        function runNodeSearch() {{
            const input = document.getElementById('node-search');
            const resultBox = document.getElementById('search-result');
            const q = norm(input.value);

            if (!q) {{
                resultBox.textContent = '请输入搜索关键词';
                node.classed('search-match', false).style('opacity', 1);
                return;
            }}

            const matched = nodes.filter(n => norm(n.id).includes(q) || norm(n.label).includes(q));
            const matchedSet = new Set(matched.map(n => n.id));

            node
                .classed('search-match', d => matchedSet.has(d.id))
                .style('opacity', d => matchedSet.size === 0 ? 1 : (matchedSet.has(d.id) ? 1 : 0.2));

            link.style('opacity', d => {{
                const s = typeof d.source === 'object' ? d.source.id : d.source;
                const t = typeof d.target === 'object' ? d.target.id : d.target;
                return (matchedSet.has(s) || matchedSet.has(t)) ? 0.85 : 0.08;
            }});

            if (matched.length > 0) {{
                const top = matched.slice(0, 8).map(n => n.label).join(' | ');
                resultBox.textContent = `命中 ${{matched.length}} 个节点: ${{top}}`;
                const focus = matched[0];
                const scale = 1.3;
                const tx = width / 2 - focus.x * scale;
                const ty = height / 2 - focus.y * scale;
                svg.transition().duration(360).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
            }} else {{
                resultBox.textContent = '未命中节点';
            }}
        }}

        function clearSearch() {{
            document.getElementById('node-search').value = '';
            document.getElementById('source-search').value = '';
            document.getElementById('target-search').value = '';
            document.getElementById('search-result').textContent = '';
            document.getElementById('path-result').textContent = '';
            document.getElementById('playbook-body').innerHTML = '选择起点与终点后，这里会显示每一步的漏洞原理、具体利用流程、验证点、告警痕迹与修复建议。';
            node.classed('search-match', false).classed('path-match', false).style('opacity', 1);
            link.classed('path-match', false).style('opacity', 0.7);
        }}

        function bfsPath(sourceId, targetId) {{
            const queue = [[sourceId]];
            const visited = new Set([sourceId]);

            const adj = new Map();
            rawEdges.forEach(e => {{
                const s = e.from;
                const t = e.to;
                if (!adj.has(s)) adj.set(s, []);
                adj.get(s).push(t);
            }});

            while (queue.length > 0) {{
                const path = queue.shift();
                const last = path[path.length - 1];
                if (last === targetId) return path;

                const nexts = adj.get(last) || [];
                nexts.forEach(n => {{
                    if (!visited.has(n)) {{
                        visited.add(n);
                        queue.push([...path, n]);
                    }}
                }});
            }}

            return null;
        }}

        function findPathAndHighlight() {{
            const sText = document.getElementById('source-search').value;
            const tText = document.getElementById('target-search').value;
            const out = document.getElementById('path-result');

            const sourceSel = document.getElementById('source-suggest');
            const targetSel = document.getElementById('target-suggest');

            const sId = sourceSel.value || resolveNodeIdByKeyword(sText);
            const tId = targetSel.value || resolveNodeIdByKeyword(tText);

            if (!sId || !tId) {{
                out.textContent = '起点或终点未匹配到节点，请先用上方搜索确认名称';
                return;
            }}

            const path = bfsPath(sId, tId);
            if (!path || path.length < 2) {{
                out.textContent = `未找到从 ${{sId}} 到 ${{tId}} 的可达路径`;
                node.classed('path-match', false);
                link.classed('path-match', false);
                return;
            }}

            const nodeSet = new Set(path);
            const edgeSet = new Set();
            for (let i = 0; i < path.length - 1; i++) {{
                edgeSet.add(edgeKey(path[i], path[i + 1]));
            }}

            node
                .classed('path-match', d => nodeSet.has(d.id))
                .style('opacity', d => nodeSet.has(d.id) ? 1 : 0.2);

            link
                .classed('path-match', d => {{
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return edgeSet.has(edgeKey(s, t));
                }})
                .style('opacity', d => {{
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return edgeSet.has(edgeKey(s, t)) ? 1 : 0.08;
                }});

            const steps = [];
            const playbook = [];
            for (let i = 0; i < path.length - 1; i++) {{
                const rel = rawEdges.find(e => e.from === path[i] && e.to === path[i + 1]);
                const relation = (rel && rel.label) || relationMap.get(path[i] + '->' + path[i + 1]) || '关系';
                steps.push(`${{i + 1}}. ${{path[i]}} --[${{relation}}]--> ${{path[i + 1]}}`);
                const plan = inferPlan(relation);
                playbook.push(`
                    <div class="pb-step">
                        <div class="pb-head">步骤 ${{i + 1}}: ${{path[i]}} → ${{path[i + 1]}}</div>
                        <div class="pb-meta">关系: ${{relation}} | 风险: <span class="pb-risk">${{plan.risk || 'Unknown'}}</span></div>
                        <div class="pb-line"><b>漏洞解析:</b> ${{plan.vuln}}</div>
                        <div class="pb-line"><b>影响分析:</b> ${{plan.impact || '待评估'}}</div>

                        <div class="pb-sub">前置检查</div>
                        <ul class="pb-ul">${{(plan.precheck || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">利用步骤</div>
                        <ul class="pb-ul">${{(plan.steps || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">授权实操模板</div>
                        <ul class="pb-ul">${{(plan.ops || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">成功验证</div>
                        <ul class="pb-ul">${{(plan.verify || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">预期结果</div>
                        <ul class="pb-ul">${{(plan.expected || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">失败排查</div>
                        <ul class="pb-ul">${{(plan.troubleshooting || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">监控痕迹</div>
                        <ul class="pb-ul">${{(plan.detect || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>

                        <div class="pb-sub">防护建议</div>
                        <ul class="pb-ul">${{(plan.defense || []).map(x => `<li>${{x}}</li>`).join('')}}</ul>
                    </div>
                `);
            }}
            out.innerHTML = `已找到路径（${{path.length - 1}} 步）<br>${{steps.join('<br>')}}`;
            document.getElementById('playbook-body').innerHTML = playbook.join('');

            const targetNode = nodes.find(n => n.id === path[0]);
            if (targetNode) {{
                const scale = 1.2;
                const tx = width / 2 - targetNode.x * scale;
                const ty = height / 2 - targetNode.y * scale;
                svg.transition().duration(450).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
            }}
        }}

        document.getElementById('node-search-btn').addEventListener('click', runNodeSearch);
        document.getElementById('node-clear-btn').addEventListener('click', clearSearch);
        document.getElementById('path-find-btn').addEventListener('click', findPathAndHighlight);
        document.getElementById('node-search').addEventListener('keydown', e => {{ if (e.key === 'Enter') runNodeSearch(); }});
        document.getElementById('source-search').addEventListener('input', e => updateSelect('source-suggest', e.target.value));
        document.getElementById('target-search').addEventListener('input', e => updateSelect('target-suggest', e.target.value));
        document.getElementById('source-search').addEventListener('keydown', e => {{ if (e.key === 'Enter') findPathAndHighlight(); }});
        document.getElementById('target-search').addEventListener('keydown', e => {{ if (e.key === 'Enter') findPathAndHighlight(); }});

        updateSelect('source-suggest', '');
        updateSelect('target-suggest', '');

        // 初始居中
        svg.call(zoom.transform, d3.zoomIdentity.translate(60, 35).scale(0.92));
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
