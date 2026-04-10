# 🩸 BloodHound Analyzer

<div align="center">

![BloodHound](https://img.shields.io/badge/BloodHound-AD%20Analysis-red)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![D3.js](https://img.shields.io/badge/D3.js-Force%20Graph-orange)

**专为 AI Agent 设计的 BloodHound AD 数据分析技能 (Skill) | 自动生成真实靶场推演 | D3 可视化图表输出 | 极简集成指南**

[功能](#-功能特性) • [快速开始](#-快速开始) • [使用方法](#-使用方法) • [示例](#-示例) • [截图](#-效果预览)

</div>

---

## 🔥 功能特性

<div align="center">

| 功能 | 描述 |
|:---:|:---|
| 🤖 **作为 AI 技能 (Skill)** | 提供专向 `SKILL.md`，可令 ChatGPT/Cursor 等编程助手直接“学会”分析 AD 渗透路线 |
| 🔍 **自动分析加载** | 利用工具令 AI 快速加载 BloodHound JSON 数据，还原域内资源关系网络 |
| ⚔️ **全景攻击路径推演** | 基于真实域环境（如 **HTB Forest** 等靶场环境实测效果极佳），生成带有风险评级与详细手法的全景攻击链路 |
| 📊 **动态可视化** | D3.js 力导向交互图，节点可拖拽、缩放，并实时对应出具体的横向移动与提权攻击手法（如 `GenericAll`, `Shadow Credentials` 等） |
| 🔐 **安全评估** | 自动识别各类复杂攻击向量并生成安全评级 |
| 📝 **报告生成** | Markdown 安全报告，高度本土化的中文攻击链解析 |

</div>

---

## 🤖 作为 AI Agent 技能使用 (核心玩法)

此项目的**首要目标是整合为一个 AI Skill**，从而极大增强智能助手在红队实战、AD 攻防期间的分析理解能力。告别繁琐的 neo4j 和手动节点拼接工作。

### 怎么让 AI "学会" 本项目？
1. 下载此仓库代码，或者将本仓库中的 `.cursor/skills/bloodhound-analyzer/SKILL.md` 放入你的 AI 代码助手工作区（支持 `Cursor`, `GitHub Copilot` 等代理模式框架）。
2. 在对话框中告诉 AI 加载该 `SKILL`。
3. 随后，你可以**直接使用自然语言**让 AI 进行工作，比如发问：
   > *"请使用 bloodhound-analyzer 技能分析我这里的 BloodHoundData，查出 svc-alfresco 的攻击路径，并给我生成一个可拖拽的动态 HTML 并保存下来。"*
4. 坐和放宽，AI 将直接调用本机环境脚本、解析最短链路、并生成带有中文攻击解析原理（ASREPRoast, GenericAll, Shadow Credentials等）的华丽交互报表。

---

## 🚀 快速开始 (脚本直调)

### 安装

```bash
git clone https://github.com/yourusername/bloodhound-analyzer.git
cd bloodhound-analyzer
pip install -r requirements.txt
```

### 准备数据

将 BloodHound 采集的 JSON 文件放入目录：

```
your_data/
├── users.json
├── groups.json
├── computers.json
└── domains.json
```

### 命令行使用

```bash
# 查看域统计
python scripts/analyze.py C:\data\BloodHoundData stats

# 查询用户
python scripts/analyze.py C:\data\BloodHoundData user svc-alfresco

# 查找攻击路径
python scripts/analyze.py C:\data\BloodHoundData path svc-alfresco "Domain Admins"

# 发现特权账户
python scripts/analyze.py C:\data\BloodHoundData privileged

# 生成可视化
python scripts/analyze.py C:\data\BloodHoundData visualize
```

---

## 📖 使用方法

### Python 模块使用

```python
import sys
sys.path.insert(0, '.')
from src.analyzer.core import BloodHoundAnalyzer

# 初始化
analyzer = BloodHoundAnalyzer(r'C:\data\BloodHoundData')
analyzer.load()

# 查询用户
user_info = analyzer.query_user('svc-alfresco')
print(user_info['sid'])
print(user_info['summary'])

# 查找攻击路径
paths = analyzer.find_all_paths('svc-alfresco', 'Domain Admins', max_hops=5)

# 生成可视化
from src.analyzer.visualizer import VisualizationGenerator
viz = VisualizationGenerator(analyzer)
html = viz.generate_attack_path_html(paths['paths'])
```

### 攻击类型识别

| 图标 | 攻击类型 | 风险 |
|:---:|:---|:---:|
| 💀 | ASREP Roasting | High |
| 🔥 | Kerberoasting | High |
| ⛓️ | GenericWrite/All | Critical |
| 🔑 | 无约束委派 | Critical |

---

## 🎯 示例

### 攻击路径示例

```
svc-alfresco (ASREP Roastable)
    ├── MemberOf → Service Accounts
    │   └── GenericWrite → Enterprise Admins
    │       └── Contains → Domain Admins
    │
    └── GenericWrite → Domain Admins
```

### 生成的安全报告

```markdown
# Active Directory 安全评估报告

## ASREP Roastable 用户
- svc-alfresco (密码永不过期，高风险)

## 高风险路径
- svc-alfresco → Domain Admins (GenericWrite)

## 建议
1. 禁用 ASREP Roasting
2. 审查 Service Accounts 组成员
3. 限制 GenericWrite 权限
```

---

## 🎨 效果预览

### HTB 真实 AD 域环境实测 - 动态全景攻击链路 (Demo)

基于 `svc-alfresco -> Domain Admins` 的真实靶场路径推演。**点击下方链接即可在浏览器中体验完整交互效果（D3.js 渲染，可自由拖拽、缩放及悬浮查看风险详情）**：

:point_right: **👉 [在线查看交互式攻击全景推演报告 (HTML Demo)](https://htmlpreview.github.io/?https://github.com/ktol1/bloodhound-analyzer/blob/main/svc-alfresco-attack-paths.html)** :point_left:

<div align="center">
  <br>
  👉 <a href="https://htmlpreview.github.io/?https://github.com/ktol1/bloodhound-analyzer/blob/main/svc-alfresco-attack-paths.html"><b>点击体验实时可交互图形及攻击原理侧边栏</b></a> 👈
  <br><br>
</div>

*你也可以直接下载项目中的 [`svc-alfresco-attack-paths.html`](./svc-alfresco-attack-paths.html) 并在本地浏览器打开，无需服务器支持，直接拥有动态推演界面。*
---

## 📁 项目结构

```
bloodhound/
├── src/
│   └── analyzer/
│       ├── core.py            # 核心分析引擎
│       ├── data_loader.py     # 数据加载
│       ├── graph_builder.py   # 图构建
│       ├── acl_analyzer.py    # ACL 分析
│       ├── attack_explainer.py # 攻击解释
│       └── visualizer.py      # 可视化生成
├── scripts/
│   └── analyze.py             # 命令行入口
├── d3.min.js                  # D3.js 库
├── requirements.txt
└── README.md
```

---

## ⚙️ 配置

### 修改数据目录

在 `scripts/analyze.py` 中：

```python
DATA_DIR = r"C:\your\data\path"
```

或通过命令行指定：

```bash
python scripts/analyze.py /path/to/data stats
```

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License - 自由使用、修改、分发

---

<div align="center">

**Made with ❤️ for Red Team Operations**

</div>