# BloodHound Analyzer Skills Contract (Cross-AI)

本文件用于让任意 AI 代理在该项目中输出一致效果。

## Trigger

当用户询问以下问题时，加载本技能流程：

- 从某个用户/主机/组到域管或域控怎么走
- 任意两点路径如何查找
- 某条路径的详细利用思路与验证
- BloodHound / SharpHound 数据分析与可视化

## Required Workflow

1. 加载数据并确认规模

```bash
python scripts/analyze.py <DATA_DIR> stats
```

2. 搜索并确认节点名（避免歧义）

```bash
python scripts/analyze.py <DATA_DIR> nodes <KEYWORD>
```

3. 查询任意两点路径（详细分析）

```bash
python scripts/analyze.py <DATA_DIR> pathx <SOURCE> <TARGET> [MAX_HOPS]
```

3.1 生成供任意 AI 连续推进的结构化交接包

```bash
python scripts/analyze.py <DATA_DIR> agentpath <SOURCE> <TARGET> [MAX_HOPS]
```

输出文件：`agent_handoff.json`

4. 生成路径专用可视化页面（仅显示 source->target 相关节点）

```bash
python scripts/analyze.py <DATA_DIR> visualize <SOURCE> <TARGET> [MAX_HOPS]
```

输出文件：`attack_paths.html`

## Output Schema (Per Step)

每个路径步骤必须包含：

- 图谱证据（from, relation, to, description）
- 利用目标（本步权限或可达性目标）
- 前置条件
- 利用原理
- 授权实操模板（高层步骤模板，使用变量占位符）
- 成功判据
- 失败排查
- 检测痕迹
- 修复建议

## Formatting Rules

- 使用变量占位符：`<DOMAIN>`, `<DC_IP>`, `<USER>`, `<TARGET_OBJECT>`
- 不硬编码靶场账号、IP、口令
- 不声称“已成功入侵”，必须保持授权评估语气
- 节点歧义时先给候选，不盲选

## Error Handling

- 未找到路径：先提示候选节点并建议缩小范围/提高 max_hops
- 路径过多：优先展示高风险且步数较短路径
- 描述缺字段：回退到关系语义解释，不返回空白卡片

## Agent Handoff Contract

`agent_handoff.json` 至少应包含：

- `recommended_path`
- `alternative_paths`
- `agent_next_actions`
- `continuation_prompt`
- `commands`

任意 AI 读取该文件后，必须优先按 `recommended_path` 推进，失败后才切换备选路径。

## Notes

- 本技能面向任意 SharpHound 数据集，不绑定 HTB Forest。
- 与项目内 `.cursor/skills/bloodhound-analyzer/SKILL.md` 保持一致。