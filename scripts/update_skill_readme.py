import codecs
with codecs.open('README.md', 'r', 'utf-8') as f:
    text = f.read()

new_text = text.replace(
    '**自动化 BloodHound AD 数据分析工具 | 真实靶场实战验证 (如 HTB Forest) | 攻击路径动态推演 | 自动安全评估**',
    '**专为 AI Agent 设计的 BloodHound AD 数据分析技能 (Skill) | 自动生成真实靶场推演 | D3 可视化图表输出 | 极简集成指南**'
)

new_text = new_text.replace(
    '| 🔍 **自动分析** | 加载 BloodHound JSON 数据，自动构建关系图 |',
    '''| 🤖 **作为 AI 技能 (Skill)** | 提供专向 `SKILL.md`，可令 ChatGPT/Cursor 等编程助手直接“学会”分析 AD 渗透路线 |
| 🔍 **自动分析加载** | 利用工具令 AI 快速加载 BloodHound JSON 数据，还原域内资源关系网络 |'''
)

skill_intro = '''## 🤖 作为 AI Agent 技能使用 (核心玩法)

此项目的**首要目标是整合为一个 AI Skill**，从而极大增强智能助手在红队实战、AD 攻防期间的分析理解能力。告别繁琐的 neo4j 和手动节点拼接工作。

### 怎么让 AI \"学会\" 本项目？
1. 下载此仓库代码，或者将本仓库中的 `.cursor/skills/bloodhound-analyzer/SKILL.md` 放入你的 AI 代码助手工作区（支持 `Cursor`, `GitHub Copilot` 等代理模式框架）。
2. 在对话框中告诉 AI 加载该 `SKILL`。
3. 随后，你可以**直接使用自然语言**让 AI 进行工作，比如发问：
   > *"请使用 bloodhound-analyzer 技能分析我这里的 BloodHoundData，查出 svc-alfresco 的攻击路径，并给我生成一个可拖拽的动态 HTML 并保存下来。"*
4. 坐和放宽，AI 将直接调用本机环境脚本、解析最短链路、并生成带有中文攻击解析原理（ASREPRoast, GenericAll, Shadow Credentials等）的华丽交互报表。

---

## 🚀 快速开始 (脚本直调)'''

new_text = new_text.replace('## 🚀 快速开始', skill_intro)

with codecs.open('README.md', 'w', 'utf-8') as f:
    f.write(new_text)
print("Updated successfully")