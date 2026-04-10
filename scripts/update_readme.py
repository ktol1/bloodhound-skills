import codecs
import re

text = codecs.open('README.md', 'r', 'utf-8').read()

# Replace the specific block of screenshots
new_text = re.sub(
    r'### HTB 真实 AD 域环境实测.*?---.*?### 交互式攻击路径图.*?---',
    '''### HTB 真实 AD 域环境实测 - 动态全景攻击链路 (Demo)

基于 `svc-alfresco -> Domain Admins` 的真实靶场路径推演。**点击下方链接即可在浏览器中体验完整交互效果（D3.js 渲染，可自由拖拽、缩放及悬浮查看风险详情）**：

:point_right: **👉 [在线查看交互式攻击全景推演报告 (HTML Demo)](https://htmlpreview.github.io/?https://github.com/ktol1/bloodhound-analyzer/blob/main/svc-alfresco-attack-paths.html)** :point_left:

<div align="center">
  <br>
  👉 <a href="https://htmlpreview.github.io/?https://github.com/ktol1/bloodhound-analyzer/blob/main/svc-alfresco-attack-paths.html"><b>点击体验实时可交互图形及攻击原理侧边栏</b></a> 👈
  <br><br>
</div>

*你也可以直接下载项目中的 [`svc-alfresco-attack-paths.html`](./svc-alfresco-attack-paths.html) 并在本地浏览器打开，无需服务器支持，直接拥有动态推演界面。*
---''',
    text,
    flags=re.DOTALL
)

with codecs.open('README.md', 'w', 'utf-8') as f:
    f.write(new_text)

print('Success')