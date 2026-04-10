"""
BloodHound ACL 分析模块
分析用户的 ACL 权限，支持正向和反向查询
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field

from .data_loader import BloodHoundDataLoader
from .graph_builder import DomainGraphBuilder


@dataclass
class ACLEntry:
    """ACL 条目数据结构"""
    source_name: str
    source_type: str
    target_name: str
    target_type: str
    right_name: str
    right_description: str
    is_privileged: bool = False


@dataclass
class UserACLAnalysis:
    """用户 ACL 分析结果"""
    user_name: str
    user_sid: str
    
    # 我可以控制谁（出站 ACL）
    outbound_acl: List[ACLEntry] = field(default_factory=list)
    
    # 谁可以控制我（入站 ACL）
    inbound_acl: List[ACLEntry] = field(default_factory=list)
    
    # 组成员关系
    member_of: List[str] = field(default_factory=list)
    
    # 特权信息
    is_asrep_roastable: bool = False
    is_kerberoastable: bool = False
    is_unconstrained_delegation: bool = False
    is_high_value: bool = False
    
    # 分析摘要
    summary: str = ""


class ACLAnalyzer:
    """ACL 分析器"""

    # 权限描述映射
    RIGHT_DESCRIPTIONS = {
        "Owns": "完全控制（所有权）",
        "GenericAll": "完全控制（通用）",
        "WriteDacl": "修改安全描述符中的 DACL",
        "WriteOwner": "修改安全描述符中的所有者",
        "GenericWrite": "通用写入",
        "AllExtendedRights": "所有扩展权限",
        "AddKeyCredentialLink": "添加密钥凭据链接（Shadow Credentials）",
        "ForceChangePassword": "强制修改用户密码",
        "ResetPassword": "重置用户密码",
        "Delete": "删除对象",
        "DeleteTree": "删除树",
        "CreateChild": "创建子对象",
        "ListObject": "列出对象",
        "List": "列出容器",
        "ReadControl": "读取安全描述符",
        "WriteDAC": "写入 DACL",
        "WriteOwner": "写入所有者",
        "DCSync": "DCSync 攻击（复制所有密码哈希）",
        "GetChanges": "复制目录变更",
        "GetChangesAll": "复制所有目录变更"
    }

    # 高危权限
    PRIVILEGED_RIGHTS = {
        "Owns", "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
        "AllExtendedRights", "AddKeyCredentialLink", "ForceChangePassword",
        "ResetPassword", "DCSync", "GetChanges", "GetChangesAll"
    }

    # 高价值组名称关键词
    HIGH_VALUE_KEYWORDS = [
        "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
        "ADMINISTRATORS", "DNS ADMINS", "EXCHANGE",
        "HYPER-V", "VIRTUALIZATION", "BACKUP", "PRINT"
    ]

    def __init__(self, data_loader: BloodHoundDataLoader, graph_builder: DomainGraphBuilder):
        self.data_loader = data_loader
        self.graph_builder = graph_builder

    def analyze_user(self, identifier: str) -> Optional[UserACLAnalysis]:
        """分析指定用户的 ACL 权限"""
        # 解析用户
        user_sid = self._resolve_user(identifier)
        if not user_sid:
            return None

        user = self.data_loader.flattened_data["users"].get(user_sid)
        if not user:
            return None

        analysis = UserACLAnalysis(
            user_name=user.name,
            user_sid=user_sid,
            member_of=user.member_of,
            is_asrep_roastable=user.dontreqpreauth,
            is_kerberoastable=user.hasspn,
            is_unconstrained_delegation=user.unconstraineddelegation
        )

        # 获取出站 ACL（我可以控制谁）
        analysis.outbound_acl = self._get_outbound_acl(user_sid)

        # 获取入站 ACL（谁能控制我）
        analysis.inbound_acl = self._get_inbound_acl(user_sid)

        # 判断是否为高价值目标
        analysis.is_high_value = self._is_high_value(user)

        # 生成摘要
        analysis.summary = self._generate_summary(analysis)

        return analysis

    def _resolve_user(self, identifier: str) -> Optional[str]:
        """解析用户标识符"""
        # 检查是否为 SID
        if identifier in self.data_loader.flattened_data["users"]:
            return identifier

        # 尝试通过名称查找
        name_upper = identifier.upper().strip()
        
        for sid, user in self.data_loader.flattened_data["users"].items():
            if name_upper in user.name.upper():
                return sid

        return None

    def _get_outbound_acl(self, user_sid: str) -> List[ACLEntry]:
        """获取用户的出站 ACL（我可以控制谁）"""
        entries = []
        user = self.data_loader.flattened_data["users"].get(user_sid)
        if not user:
            return entries

        # 直接 ACL
        for target_name, right_name in user.has_acl_on.items():
            target_sid = self.data_loader.get_sid_by_name(target_name)
            target_type = self._get_target_type(target_sid)
            
            entries.append(ACLEntry(
                source_name=user.name,
                source_type="user",
                target_name=target_name,
                target_type=target_type,
                right_name=right_name,
                right_description=self.RIGHT_DESCRIPTIONS.get(right_name, right_name),
                is_privileged=right_name in self.PRIVILEGED_RIGHTS
            ))

        # 通过组成员关系的 ACL
        for group_name in user.member_of:
            group_sid = self.data_loader.get_sid_by_name(group_name)
            if group_sid:
                group = self.data_loader.flattened_data["groups"].get(group_sid)
                if group:
                    for target_name, right_name in group.has_acl_on.items():
                        target_sid = self.data_loader.get_sid_by_name(target_name)
                        target_type = self._get_target_type(target_sid)
                        
                        entries.append(ACLEntry(
                            source_name=f"{user.name} (via {group_name})",
                            source_type="user",
                            target_name=target_name,
                            target_type=target_type,
                            right_name=right_name,
                            right_description=self.RIGHT_DESCRIPTIONS.get(right_name, right_name),
                            is_privileged=right_name in self.PRIVILEGED_RIGHTS
                        ))

        return entries

    def _get_inbound_acl(self, user_sid: str) -> List[ACLEntry]:
        """获取用户的入站 ACL（谁能控制我）"""
        entries = []
        user = self.data_loader.flattened_data["users"].get(user_sid)
        if not user:
            return entries

        user_name = user.name

        # 遍历所有用户/计算机/组，寻找对目标用户的 ACL
        for sid, actor in list(self.data_loader.flattened_data["users"].items()):
            for target_name, right_name in actor.has_acl_on.items():
                if user_name.upper() in target_name.upper() or user_sid in target_name:
                    entries.append(ACLEntry(
                        source_name=actor.name,
                        source_type="user",
                        target_name=user_name,
                        target_type="user",
                        right_name=right_name,
                        right_description=self.RIGHT_DESCRIPTIONS.get(right_name, right_name),
                        is_privileged=right_name in self.PRIVILEGED_RIGHTS
                    ))

        for sid, computer in self.data_loader.flattened_data["computers"].items():
            for target_name, right_name in computer.has_acl_on.items():
                if user_name.upper() in target_name.upper() or user_sid in target_name:
                    entries.append(ACLEntry(
                        source_name=computer.name,
                        source_type="computer",
                        target_name=user_name,
                        target_type="user",
                        right_name=right_name,
                        right_description=self.RIGHT_DESCRIPTIONS.get(right_name, right_name),
                        is_privileged=right_name in self.PRIVILEGED_RIGHTS
                    ))

        for sid, group in self.data_loader.flattened_data["groups"].items():
            for target_name, right_name in group.has_acl_on.items():
                if user_name.upper() in target_name.upper() or user_sid in target_name:
                    entries.append(ACLEntry(
                        source_name=group.name,
                        source_type="group",
                        target_name=user_name,
                        target_type="user",
                        right_name=right_name,
                        right_description=self.RIGHT_DESCRIPTIONS.get(right_name, right_name),
                        is_privileged=right_name in self.PRIVILEGED_RIGHTS
                    ))

        return entries

    def _get_target_type(self, target_sid: str) -> str:
        """获取目标类型"""
        if not target_sid:
            return "unknown"
        
        if target_sid in self.data_loader.flattened_data["users"]:
            return "user"
        elif target_sid in self.data_loader.flattened_data["computers"]:
            return "computer"
        elif target_sid in self.data_loader.flattened_data["groups"]:
            return "group"
        elif target_sid in self.data_loader.flattened_data["domains"]:
            return "domain"
        elif "-544" in target_sid or "-545" in target_sid:
            return "builtin"
        else:
            return "unknown"

    def _is_high_value(self, user) -> bool:
        """判断用户是否为高价值目标"""
        # 检查 admincount
        if user.admincount:
            return True

        # 检查组成员关系
        for group_name in user.member_of:
            for keyword in self.HIGH_VALUE_KEYWORDS:
                if keyword in group_name.upper():
                    return True

        return False

    def _generate_summary(self, analysis: UserACLAnalysis) -> str:
        """生成分析摘要"""
        parts = []

        # 特殊属性
        if analysis.is_asrep_roastable:
            parts.append("ASREP Roastable（可进行 ASREP 攻击）")
        if analysis.is_kerberoastable:
            parts.append("Kerberoastable（可进行 Kerberoast 攻击）")
        if analysis.is_unconstrained_delegation:
            parts.append("无约束委派（可进行 Kerberos 委派攻击）")
        if analysis.is_high_value:
            parts.append("高价值目标")

        # 组成员
        if analysis.member_of:
            privileged_groups = [g for g in analysis.member_of 
                              if any(kw in g.upper() for kw in self.HIGH_VALUE_KEYWORDS)]
            if privileged_groups:
                parts.append(f"是特权组成员: {', '.join(privileged_groups)}")

        # 特权 ACL
        privileged_acl = [a for a in analysis.outbound_acl if a.is_privileged]
        if privileged_acl:
            parts.append(f"拥有 {len(privileged_acl)} 条特权 ACL")

        if not parts:
            return "普通用户，无特殊权限"

        return "; ".join(parts)


class PrivilegeAnalyzer:
    """特权分析器 - 查找域内所有特权账户和权限"""

    # Domain Admins 成员 SID
    DOMAIN_ADMINS_SID = "S-1-5-21-3072663084-364016917-1341370565-512"

    def __init__(self, data_loader: BloodHoundDataLoader, graph_builder: DomainGraphBuilder):
        self.data_loader = data_loader
        self.graph_builder = graph_builder

    def find_all_privileged_users(self) -> Dict[str, List[str]]:
        """查找所有特权用户及其权限来源"""
        results = {
            "domain_admins": [],
            "enterprise_admins": [],
            "schema_admins": [],
            "asrep_roastable": [],
            "kerberoastable": [],
            "unconstrained_delegation": [],
            "has_generic_all": [],
            "local_admins_on_dc": []
        }

        # 查找 Domain Admins
        da_group = self.data_loader.flattened_data["groups"].get(self.DOMAIN_ADMINS_SID)
        if da_group:
            results["domain_admins"] = da_group.members

        # 遍历所有用户
        for sid, user in self.data_loader.flattened_data["users"].items():
            # ASREP Roastable
            if user.dontreqpreauth:
                results["asrep_roastable"].append(user.name)

            # Kerberoastable
            if user.hasspn:
                results["kerberoastable"].append(user.name)

            # 无约束委派
            if user.unconstraineddelegation:
                results["unconstrained_delegation"].append(user.name)

            # GenericAll 权限
            if any(r in ["GenericAll", "Owns"] for r in user.has_acl_on.values()):
                results["has_generic_all"].append(user.name)

        # 查找 DC 上的本地管理员
        for sid, computer in self.data_loader.flattened_data["computers"].items():
            if computer.is_dc:
                results["local_admins_on_dc"] = computer.local_admins

        return results

    def find_security_issues(self) -> List[Dict[str, str]]:
        """查找安全问题"""
        issues = []

        # ASREP Roastable 用户
        for sid, user in self.data_loader.flattened_data["users"].items():
            if user.dontreqpreauth and user.enabled:
                issues.append({
                    "type": "ASREP_Roastable",
                    "severity": "High",
                    "target": user.name,
                    "description": f"用户 {user.name} 启用了 '不需要 Kerberos 预认证'，可被 ASREP Roasting 攻击"
                })

        # 密码永不过期的用户
            if user.pwdneverexpires and user.enabled:
                issues.append({
                    "type": "PasswordNeverExpires",
                    "severity": "Medium",
                    "target": user.name,
                    "description": f"用户 {user.name} 的密码永不过期"
                })

        # 无约束委派
            if user.unconstraineddelegation and user.enabled:
                issues.append({
                    "type": "UnconstrainedDelegation",
                    "severity": "High",
                    "target": user.name,
                    "description": f"用户 {user.name} 启用了无约束委派，可被 Kerberoasting 和票据导出攻击"
                })

        return issues


if __name__ == "__main__":
    # 测试代码
    from .data_loader import BloodHoundDataLoader
    from .graph_builder import DomainGraphBuilder

    loader = BloodHoundDataLoader("C:\\Users\\90898\\Desktop\\htb_forest\\BloodHoundData")
    loader.load()

    graph_builder = DomainGraphBuilder(loader)
    graph_builder.build()

    acl_analyzer = ACLAnalyzer(loader, graph_builder)

    # 测试用户分析
    analysis = acl_analyzer.analyze_user("svc-alfresco")
    if analysis:
        print(f"\n=== ACL 分析: {analysis.user_name} ===")
        print(f"\n摘要: {analysis.summary}")
        print(f"\n组成员: {', '.join(analysis.member_of) if analysis.member_of else '无'}")
        print(f"\n出站 ACL ({len(analysis.outbound_acl)} 条):")
        for acl in analysis.outbound_acl[:10]:
            print(f"  -> {acl.target_name} [{acl.right_name}]")
        print(f"\n入站 ACL ({len(analysis.inbound_acl)} 条):")
        for acl in analysis.inbound_acl[:10]:
            print(f"  <- {acl.source_name} [{acl.right_name}]")

    # 测试特权分析
    priv_analyzer = PrivilegeAnalyzer(loader, graph_builder)
    privileged = priv_analyzer.find_all_privileged_users()
    print(f"\n=== 特权用户统计 ===")
    print(f"ASREP Roastable: {len(privileged['asrep_roastable'])}")
    print(f"Kerberoastable: {len(privileged['kerberoastable'])}")
    print(f"无约束委派: {len(privileged['unconstrained_delegation'])}")
