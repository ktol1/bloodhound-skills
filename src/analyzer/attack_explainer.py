"""
BloodHound 攻击链解释器
将攻击路径转换为自然语言描述，支持多种攻击方式解释
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .data_loader import BloodHoundDataLoader
from .graph_builder import DomainGraphBuilder, PathFinder


@dataclass
class AttackStep:
    """攻击步骤"""
    step_number: int
    from_name: str
    from_type: str
    to_name: str
    to_type: str
    relation: str
    attack_method: str
    description: str


@dataclass
class AttackChain:
    """完整攻击链"""
    source_name: str
    target_name: str
    steps: List[AttackStep]
    attack_methods: List[str]
    difficulty: str
    risk_level: str
    summary: str


class AttackExploits:
    """攻击技术知识库"""

    # 攻击技术映射
    ATTACK_TECHNIQUES = {
        "MemberOf": {
            "method": "组成员关系",
            "description": "作为目标组的成员，自动获得该组的所有权限"
        },
        "Owns": {
            "method": "完全控制 (Owns)",
            "description": "拥有目标对象的完全控制权，可以修改所有属性和权限"
        },
        "GenericAll": {
            "method": "完全控制 (GenericAll)",
            "description": "拥有对目标对象的完全控制权"
        },
        "GenericWrite": {
            "method": "通用写入 (GenericWrite)",
            "description": "可以修改目标对象的大部分属性"
        },
        "WriteDacl": {
            "method": "修改 ACL (WriteDacl)",
            "description": "可以修改目标对象的安全描述符，添加新的访问权限"
        },
        "WriteOwner": {
            "method": "修改所有者 (WriteOwner)",
            "description": "可以修改目标对象的所有者，然后获得完全控制权"
        },
        "AllExtendedRights": {
            "method": "所有扩展权限",
            "description": "拥有对目标对象的所有扩展权限"
        },
        "AddKeyCredentialLink": {
            "method": "Shadow Credentials (AddKeyCredentialLink)",
            "description": "可以为用户添加密钥凭据，实现无密码认证"
        },
        "ForceChangePassword": {
            "method": "密码强制修改 (ForceChangePassword)",
            "description": "可以强制修改目标用户的密码"
        },
        "HasSession": {
            "method": "会话利用 (HasSession)",
            "description": "在目标计算机上有会话，可以进行票据传递或会话劫持"
        },
        "PrivilegedSession": {
            "method": "特权会话利用",
            "description": "在目标计算机上有特权会话，可以导出凭据或提升权限"
        },
        "RegistrySession": {
            "method": "注册表会话利用",
            "description": "在目标 DC 上有注册表会话，可以访问敏感的注册表项"
        },
        "LocalAdmin": {
            "method": "本地管理员",
            "description": "是目标计算机的本地管理员，可以执行本地权限提升或凭据访问"
        },
        "AllowedToDelegate": {
            "method": "约束/无约束委派",
            "description": "允许委派到目标服务，可以进行委派攻击"
        },
        "UnconstrainedDelegation": {
            "method": "无约束委派",
            "description": "启用了无约束委派，任何用户都可以委派到此服务，可以捕获 TGT"
        }
    }

    # 高价值目标类型
    HIGH_VALUE_TARGETS = [
        "Administrator", "Domain Admins", "Enterprise Admins",
        "Schema Admins", " krbtgt", "DC"
    ]

    # 攻击难度评估
    DIFFICULTY_MAPPING = {
        "MemberOf": "低",
        "Owns": "中",
        "GenericAll": "中",
        "GenericWrite": "中",
        "WriteDacl": "高",
        "WriteOwner": "高",
        "AllExtendedRights": "中",
        "AddKeyCredentialLink": "高",
        "ForceChangePassword": "低",
        "HasSession": "中",
        "PrivilegedSession": "高",
        "RegistrySession": "高",
        "LocalAdmin": "中",
        "AllowedToDelegate": "高"
    }

    # 风险等级映射
    RISK_MAPPING = {
        "MemberOf": "Medium",
        "Owns": "High",
        "GenericAll": "High",
        "GenericWrite": "High",
        "WriteDacl": "Medium",
        "WriteOwner": "Medium",
        "AllExtendedRights": "High",
        "AddKeyCredentialLink": "Critical",
        "ForceChangePassword": "High",
        "HasSession": "High",
        "PrivilegedSession": "Critical",
        "RegistrySession": "Critical",
        "LocalAdmin": "High",
        "AllowedToDelegate": "Critical",
        "UnconstrainedDelegation": "Critical"
    }

    @classmethod
    def get_technique_info(cls, relation: str) -> Dict[str, str]:
        """获取攻击技术信息"""
        return cls.ATTACK_TECHNIQUES.get(relation, {
            "method": relation,
            "description": f"使用 {relation} 关系进行攻击"
        })

    @classmethod
    def get_difficulty(cls, relation: str) -> str:
        """获取攻击难度"""
        return cls.DIFFICULTY_MAPPING.get(relation, "未知")

    @classmethod
    def get_risk_level(cls, relations: List[str]) -> str:
        """根据攻击链中的关系获取整体风险等级"""
        risk_scores = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1
        }

        max_risk = "Low"
        max_score = 0

        for relation in relations:
            risk = cls.RISK_MAPPING.get(relation, "Medium")
            score = risk_scores.get(risk, 2)
            if score > max_score:
                max_score = score
                max_risk = risk

        return max_risk


class AttackChainExplainer:
    """攻击链解释器"""

    def __init__(self, data_loader: BloodHoundDataLoader, 
                 graph_builder: DomainGraphBuilder,
                 path_finder: PathFinder):
        self.data_loader = data_loader
        self.graph_builder = graph_builder
        self.path_finder = path_finder

    def explain_path(self, path: List[Dict]) -> AttackChain:
        """解释攻击路径"""
        if not path:
            return None

        source_name = path[0]["from"]["name"]
        target_name = path[-1]["to"]["name"]

        steps = []
        attack_methods = set()
        all_relations = []

        for step_data in path:
            relation = step_data.get("relation", "Unknown")
            technique_info = AttackExploits.get_technique_info(relation)

            steps.append(AttackStep(
                step_number=step_data.get("step", 0),
                from_name=step_data["from"]["name"],
                from_type=step_data["from"]["type"],
                to_name=step_data["to"]["name"],
                to_type=step_data["to"]["type"],
                relation=relation,
                attack_method=technique_info["method"],
                description=step_data.get("description", technique_info["description"])
            ))

            attack_methods.add(technique_info["method"])
            all_relations.append(relation)

        # 计算整体难度和风险
        difficulties = [AttackExploits.get_difficulty(r) for r in all_relations]
        overall_difficulty = max(difficulties, key=lambda x: ["低", "中", "高", "未知"].index(x) if x in ["低", "中", "高"] else 2)
        
        overall_risk = AttackExploits.get_risk_level(all_relations)

        # 生成摘要
        summary = self._generate_summary(source_name, target_name, steps, list(attack_methods))

        return AttackChain(
            source_name=source_name,
            target_name=target_name,
            steps=steps,
            attack_methods=list(attack_methods),
            difficulty=overall_difficulty,
            risk_level=overall_risk,
            summary=summary
        )

    def explain_paths(self, paths: List[List[Dict]]) -> List[AttackChain]:
        """解释多条攻击路径"""
        return [self.explain_path(path) for path in paths if path]

    def to_natural_language(self, attack_chain: AttackChain) -> str:
        """将攻击链转换为自然语言"""
        if not attack_chain:
            return "未找到攻击路径"

        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"攻击链分析: {attack_chain.source_name} → {attack_chain.target_name}")
        lines.append(f"{'='*60}")
        lines.append(f"")
        lines.append(f"【基本信息】")
        lines.append(f"  源账户: {attack_chain.source_name}")
        lines.append(f"  目标: {attack_chain.target_name}")
        lines.append(f"  攻击步骤: {len(attack_chain.steps)} 步")
        lines.append(f"  攻击技术: {', '.join(attack_chain.attack_methods)}")
        lines.append(f"  难度: {attack_chain.difficulty}")
        lines.append(f"  风险等级: {attack_chain.risk_level}")
        lines.append(f"")
        lines.append(f"【详细步骤】")

        for step in attack_chain.steps:
            lines.append(f"")
            lines.append(f"  第 {step.step_number} 步: {step.from_name} → {step.to_name}")
            lines.append(f"    关系: {step.attack_method}")
            lines.append(f"    描述: {step.description}")

        lines.append(f"")
        lines.append(f"【攻击摘要】")
        lines.append(f"  {attack_chain.summary}")
        lines.append(f"")
        lines.append(f"{'='*60}")

        return "\n".join(lines)

    def to_markdown(self, attack_chain: AttackChain) -> str:
        """将攻击链转换为 Markdown 格式"""
        if not attack_chain:
            return "## 未找到攻击路径\n"

        lines = []
        lines.append(f"## 攻击链: {attack_chain.source_name} → {attack_chain.target_name}\n")
        lines.append(f"| 属性 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 源账户 | {attack_chain.source_name} |")
        lines.append(f"| 目标 | {attack_chain.target_name} |")
        lines.append(f"| 攻击步骤 | {len(attack_chain.steps)} |")
        lines.append(f"| 攻击技术 | {', '.join(attack_chain.attack_methods)} |")
        lines.append(f"| 难度 | {attack_chain.difficulty} |")
        lines.append(f"| 风险等级 | {attack_chain.risk_level} |\n")
        lines.append(f"### 详细步骤\n")
        lines.append(f"| 步骤 | 来源 | 目标 | 关系 | 说明 |")
        lines.append(f"|------|------|------|------|------|")

        for step in attack_chain.steps:
            lines.append(f"| {step.step_number} | {step.from_name} | {step.to_name} | {step.attack_method} | {step.description} |")

        lines.append(f"\n### 摘要\n")
        lines.append(f"{attack_chain.summary}\n")

        return "\n".join(lines)

    def _generate_summary(self, source: str, target: str, 
                        steps: List[AttackStep],
                        attack_methods: List[str]) -> str:
        """生成攻击摘要"""
        summaries = []

        # 检查是否有直接的攻击路径
        if len(steps) == 1:
            step = steps[0]
            if step.relation == "MemberOf":
                summaries.append(f"通过加入 {step.to_name} 组直接获得目标权限")
            elif step.relation in ["Owns", "GenericAll"]:
                summaries.append(f"直接拥有对 {target} 的 {step.attack_method} 权限")
            elif step.relation in ["ForceChangePassword"]:
                summaries.append(f"可以直接修改 {target} 的密码")
            elif "Session" in step.relation:
                summaries.append(f"在 {step.to_name} 上有会话，可进行票据传递")
            else:
                summaries.append(f"通过 {step.attack_method} 获取目标权限")

        # 检查是否包含多个组的关系
        group_steps = [s for s in steps if s.relation == "MemberOf"]
        if len(group_steps) > 1:
            summaries.append(f"需要通过 {len(group_steps)} 个组成员关系逐步提升权限")

        # 检查是否有高危攻击
        high_risk = [s for s in steps if s.relation in 
                    ["AddKeyCredentialLink", "UnconstrainedDelegation", 
                     "PrivilegedSession", "RegistrySession"]]
        if high_risk:
            for step in high_risk:
                summaries.append(f"注意: {step.attack_method} 是高危攻击技术")

        # 攻击建议
        if summaries:
            return summaries[0] + ("。" if not summaries[0].endswith("。") else "")

        return f"通过 {len(steps)} 个步骤从 {source} 提升到 {target} 权限"


class CompromiseAnalyzer:
    """账户被控后的攻击分析"""

    def __init__(self, data_loader: BloodHoundDataLoader,
                 graph_builder: DomainGraphBuilder,
                 path_finder: PathFinder,
                 acl_analyzer):
        self.data_loader = data_loader
        self.graph_builder = graph_builder
        self.path_finder = path_finder
        self.acl_analyzer = acl_analyzer

    def analyze_compromise(self, identifier: str) -> Dict[str, Any]:
        """分析账户被控后的所有攻击可能"""
        # 获取用户信息
        user_sid = self._resolve_user(identifier)
        if not user_sid:
            return {"error": "用户不存在"}

        user = self.data_loader.flattened_data["users"].get(user_sid)
        if not user:
            return {"error": "用户不存在"}

        results = {
            "account": user.name,
            "sid": user_sid,
            "vulnerabilities": [],
            "potential_targets": [],
            "attack_paths": [],
            "recommendations": []
        }

        # 检查可利用的漏洞
        if user.dontreqpreauth:
            results["vulnerabilities"].append({
                "type": "ASREP_Roastable",
                "severity": "High",
                "description": "该账户不需要 Kerberos 预认证，可以离线破解 AS-REP 响应的加密部分获取密码哈希"
            })

        if user.hasspn:
            results["vulnerabilities"].append({
                "type": "Kerberoastable",
                "severity": "High",
                "description": "该账户有 SPN，可以请求 TGS 票据并离线破解"
            })

        if user.unconstraineddelegation:
            results["vulnerabilities"].append({
                "type": "UnconstrainedDelegation",
                "severity": "Critical",
                "description": "启用了无约束委派，任何用户都可以委派到此服务并捕获 TGT"
            })

        # 分析 ACL 权限
        acl_analysis = self.acl_analyzer.analyze_user(identifier)
        if acl_analysis:
            # 特权 ACL
            privileged_acl = [a for a in acl_analysis.outbound_acl if a.is_privileged]
            for acl in privileged_acl:
                results["potential_targets"].append({
                    "target": acl.target_name,
                    "right": acl.right_name,
                    "description": acl.right_description
                })

        # 查找到高价值目标的所有路径
        paths = self.path_finder.find_paths_to_high_value_targets(identifier, max_hops=5)
        explainer = AttackChainExplainer(self.data_loader, self.graph_builder, self.path_finder)
        
        for path in paths[:10]:  # 限制返回数量
            chain = explainer.explain_path(path)
            if chain:
                results["attack_paths"].append({
                    "target": chain.target_name,
                    "steps": len(chain.steps),
                    "methods": chain.attack_methods,
                    "risk": chain.risk_level,
                    "summary": chain.summary
                })

        # 生成建议
        if results["vulnerabilities"]:
            results["recommendations"].append("利用 ASREP Roasting 或 Kerberoasting 可以获取更多凭据")
        
        if results["potential_targets"]:
            results["recommendations"].append(f"当前账户可以直接控制 {len(results['potential_targets'])} 个目标")
        
        if results["attack_paths"]:
            results["recommendations"].append(f"通过 {len(results['attack_paths'])} 条路径可以到达高价值目标")

        return results

    def _resolve_user(self, identifier: str) -> Optional[str]:
        """解析用户"""
        if identifier in self.data_loader.flattened_data["users"]:
            return identifier

        name_upper = identifier.upper().strip()
        for sid, user in self.data_loader.flattened_data["users"].items():
            if name_upper in user.name.upper():
                return sid

        return None


if __name__ == "__main__":
    # 测试代码
    from .data_loader import BloodHoundDataLoader
    from .graph_builder import DomainGraphBuilder, PathFinder
    from .acl_analyzer import ACLAnalyzer

    loader = BloodHoundDataLoader("C:\\Users\\90898\\Desktop\\htb_forest\\BloodHoundData")
    loader.load()

    graph_builder = DomainGraphBuilder(loader)
    graph_builder.build()

    path_finder = PathFinder(graph_builder)
    acl_analyzer = ACLAnalyzer(loader, graph_builder)
    explainer = AttackChainExplainer(loader, graph_builder, path_finder)

    # 测试攻击链解释
    path = path_finder.find_shortest_path("svc-alfresco", "Administrator")
    if path:
        chain = explainer.explain_path(path)
        print(explainer.to_natural_language(chain))
        print("\n" + explainer.to_markdown(chain))
