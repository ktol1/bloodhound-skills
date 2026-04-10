"""
BloodHound 数据加载和预处理模块
将复杂的 BloodHound JSON 数据转换为 AI 友好的扁平化结构
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class FlattenedUser:
    """扁平化的用户数据结构"""
    name: str
    sid: str
    domain: str
    distinguished_name: str
    enabled: bool
    dontreqpreauth: bool
    hasspn: bool
    admincount: bool
    pwdneverexpires: bool
    unconstraineddelegation: bool
    trustedtoauth: bool
    sensitive: bool
    passwordnotreqd: bool
    member_of: List[str] = field(default_factory=list)
    has_acl_on: Dict[str, str] = field(default_factory=dict)
    allowed_to_delegate: List[str] = field(default_factory=list)
    spn_targets: List[Dict] = field(default_factory=list)
    sessions_on: List[str] = field(default_factory=list)


@dataclass
class FlattenedComputer:
    """扁平化的计算机数据结构"""
    name: str
    sid: str
    domain: str
    distinguished_name: str
    enabled: bool
    unconstraineddelegation: bool
    haslaps: bool
    operatingsystem: str
    is_dc: bool
    member_of: List[str] = field(default_factory=list)
    local_admins: List[str] = field(default_factory=list)
    sessions: List[Dict] = field(default_factory=list)
    privileged_sessions: List[Dict] = field(default_factory=list)
    has_acl_on: Dict[str, str] = field(default_factory=dict)


@dataclass
class FlattenedGroup:
    """扁平化的组数据结构"""
    name: str
    sid: str
    domain: str
    distinguished_name: str
    description: str
    admincount: bool
    member_of: List[str] = field(default_factory=list)
    members: List[str] = field(default_factory=list)
    has_acl_on: Dict[str, str] = field(default_factory=dict)


@dataclass
class FlattenedDomain:
    """扁平化的域数据结构"""
    name: str
    sid: str
    distinguished_name: str
    functional_level: str
    member_of: List[str] = field(default_factory=list)
    trusts: List[Dict] = field(default_factory=list)
    has_acl_on: Dict[str, str] = field(default_factory=dict)


class BloodHoundDataLoader:
    """BloodHound JSON 数据加载器"""

    # SID 前缀到名称的映射
    WELL_KNOWN_SIDS = {
        "S-1-5-32-544": "BUILTIN\\Administrators",
        "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-546": "BUILTIN\\Guests",
        "S-1-5-32-547": "BUILTIN\\Power Users",
        "S-1-5-32-548": "BUILTIN\\Account Operators",
        "S-1-5-32-549": "BUILTIN\\Server Operators",
        "S-1-5-32-550": "BUILTIN\\Print Operators",
        "S-1-5-32-551": "BUILTIN\\Backup Operators",
        "S-1-5-32-552": "BUILTIN\\Replicator",
        "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
        "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
        "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
        "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
        "S-1-5-32-559": "BUILTIN\\Performance Log Users",
        "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
        "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
        "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
        "S-1-5-18": "NT AUTHORITY\\SYSTEM",
        "S-1-5-19": "NT AUTHORITY\\Local Service",
        "S-1-5-20": "NT AUTHORITY\\Network Service",
        "S-1-5-9": "NT AUTHORITY\\Enterprise Domain Controllers",
        "S-1-5-10": "NT AUTHORITY\\Principal Self",
        "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
        "S-1-5-12": "NT AUTHORITY\\RESTRICTED",
        "S-1-5-14": "NT AUTHORITY\\Interactive",
        "S-1-5-15": "NT AUTHORITY\\This Organization",
        "S-1-5-17": "NT AUTHORITY\\IUSR",
        "S-1-5-1": "NT AUTHORITY\\Local Account",
        "S-1-5-113": "LOCAL ACCOUNT",
        "S-1-5-114": "NT AUTHORITY\\NetworkAccount",
        "S-1-5-7": "ANONYMOUS LOGON",
        "S-1-5-21": "NT AUTHORITY\\Null Authority",
        "S-1-1-0": "Everyone",
    }

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.raw_data = {
            "users": [],
            "computers": [],
            "groups": [],
            "domains": [],
            "ous": [],
            "gpos": [],
            "containers": []
        }
        self.flattened_data = {
            "users": {},
            "computers": {},
            "groups": {},
            "domains": {}
        }
        self.sid_to_name = {}  # SID 到名称的映射
        self.name_to_sid = {}  # 名称到 SID 的反向映射

    def load(self) -> Dict[str, Any]:
        """加载所有 BloodHound 数据"""
        print("[*] 正在加载 BloodHound 数据...")

        # 查找数据文件
        json_files = list(self.data_dir.glob("*.json"))
        print(f"[*] 找到 {len(json_files)} 个 JSON 文件")

        for json_file in json_files:
            file_name = json_file.stem
            if file_name.endswith("_users") or "_users" in file_name:
                self.raw_data["users"] = self._load_json(json_file)
            elif file_name.endswith("_computers") or "_computers" in file_name:
                self.raw_data["computers"] = self._load_json(json_file)
            elif file_name.endswith("_groups") or "_groups" in file_name:
                self.raw_data["groups"] = self._load_json(json_file)
            elif file_name.endswith("_domains") or "_domains" in file_name:
                self.raw_data["domains"] = self._load_json(json_file)
            elif file_name.endswith("_ous") or "_ous" in file_name:
                self.raw_data["ous"] = self._load_json(json_file)
            elif file_name.endswith("_gpos") or "_gpos" in file_name:
                self.raw_data["gpos"] = self._load_json(json_file)
            elif file_name.endswith("_containers") or "_containers" in file_name:
                self.raw_data["containers"] = self._load_json(json_file)

        print(f"[*] 加载完成:")
        print(f"    - 用户: {len(self.raw_data['users'])}")
        print(f"    - 计算机: {len(self.raw_data['computers'])}")
        print(f"    - 组: {len(self.raw_data['groups'])}")
        print(f"    - 域: {len(self.raw_data['domains'])}")

        # 构建扁平化数据
        self._flatten()

        return self.flattened_data

    def _load_json(self, file_path: Path) -> List[Dict]:
        """加载单个 JSON 文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("data", [])
        except Exception as e:
            print(f"[!] 加载 {file_path.name} 失败: {e}")
            return []

    def _flatten(self):
        """将原始数据扁平化"""
        print("[*] 正在预处理数据...")

        # 先构建 SID 到名称的映射
        self._build_sid_mappings()

        # 扁平化用户
        for user in self.raw_data["users"]:
            flattened = self._flatten_user(user)
            self.flattened_data["users"][flattened.sid] = flattened
            self.sid_to_name[flattened.sid] = flattened.name

        # 扁平化计算机
        for computer in self.raw_data["computers"]:
            flattened = self._flatten_computer(computer)
            self.flattened_data["computers"][flattened.sid] = flattened
            self.sid_to_name[flattened.sid] = flattened.name

        # 扁平化组
        for group in self.raw_data["groups"]:
            flattened = self._flatten_group(group)
            self.flattened_data["groups"][flattened.sid] = flattened
            self.sid_to_name[flattened.sid] = flattened.name

        # 扁平化域
        for domain in self.raw_data["domains"]:
            flattened = self._flatten_domain(domain)
            self.flattened_data["domains"][flattened.sid] = flattened
            self.sid_to_name[flattened.sid] = flattened.name

        # 更新用户的组成员关系（需要先加载所有组）
        self._resolve_group_memberships()

        print("[*] 数据预处理完成")

    def _build_sid_mappings(self):
        """构建 SID 到名称的映射"""
        # 添加内置 SID
        self.sid_to_name.update(self.WELL_KNOWN_SIDS)

        # 从数据中提取 SID
        for user in self.raw_data["users"]:
            sid = user.get("ObjectIdentifier", "")
            name = user.get("Properties", {}).get("samaccountname", "")
            if sid and name:
                self.sid_to_name[sid] = f"{name}@{user.get('Properties', {}).get('domain', '')}"
                self.name_to_sid[name.upper()] = sid

        for computer in self.raw_data["computers"]:
            sid = computer.get("ObjectIdentifier", "")
            name = computer.get("Properties", {}).get("samaccountname", "")
            if sid and name:
                # 移除 $ 后缀
                clean_name = name.rstrip('$')
                self.sid_to_name[sid] = f"{clean_name}.{computer.get('Properties', {}).get('domain', '')}"
                self.name_to_sid[clean_name.upper()] = sid

        for group in self.raw_data["groups"]:
            sid = group.get("ObjectIdentifier", "")
            name = group.get("Properties", {}).get("samaccountname", "")
            if sid and name:
                domain = group.get("Properties", {}).get("domain", "")
                self.sid_to_name[sid] = f"{name}@{domain}"
                self.name_to_sid[name.upper()] = sid

    def _flatten_user(self, user: Dict) -> FlattenedUser:
        """扁平化用户数据"""
        props = user.get("Properties", {})

        # 获取 ACL 信息
        has_acl_on = {}
        for ace in user.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", "")
            right_name = ace.get("RightName", "")
            if principal_sid and right_name:
                target_name = self.sid_to_name.get(principal_sid, principal_sid)
                has_acl_on[target_name] = right_name

        return FlattenedUser(
            name=props.get("samaccountname", "Unknown"),
            sid=user.get("ObjectIdentifier", ""),
            domain=props.get("domain", ""),
            distinguished_name=props.get("distinguishedname", ""),
            enabled=props.get("enabled", True),
            dontreqpreauth=props.get("dontreqpreauth", False),
            hasspn=props.get("hasspn", False),
            admincount=props.get("admincount", False),
            pwdneverexpires=props.get("pwdneverexpires", False),
            unconstraineddelegation=props.get("unconstraineddelegation", False),
            trustedtoauth=props.get("trustedtoauth", False),
            sensitive=props.get("sensitive", False),
            passwordnotreqd=props.get("passwordnotreqd", False),
            has_acl_on=has_acl_on,
            allowed_to_delegate=user.get("AllowedToDelegate", []),
            spn_targets=user.get("SPNTargets", [])
        )

    def _flatten_computer(self, computer: Dict) -> FlattenedComputer:
        """扁平化计算机数据"""
        props = computer.get("Properties", {})

        # 获取本地管理员
        local_admins = []
        for local_group in computer.get("LocalGroups", []):
            if "544" in local_group.get("ObjectIdentifier", ""):  # Administrators 组
                for member in local_group.get("Results", []):
                    member_sid = member.get("ObjectIdentifier", "")
                    member_name = self.sid_to_name.get(member_sid, member_sid)
                    local_admins.append(member_name)

        # 获取会话
        sessions = []
        for session in computer.get("Sessions", {}).get("Results", []):
            sessions.append({
                "user": self.sid_to_name.get(session.get("UserSID", ""), session.get("UserSID", "")),
                "type": "session"
            })

        # 获取特权会话
        privileged_sessions = []
        for session in computer.get("PrivilegedSessions", {}).get("Results", []):
            privileged_sessions.append({
                "user": self.sid_to_name.get(session.get("UserSID", ""), session.get("UserSID", "")),
                "type": "privileged_session"
            })

        # 获取注册表会话
        for session in computer.get("RegistrySessions", {}).get("Results", []):
            privileged_sessions.append({
                "user": self.sid_to_name.get(session.get("UserSID", ""), session.get("UserSID", "")),
                "type": "registry_session"
            })

        # 获取 ACL
        has_acl_on = {}
        for ace in computer.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", "")
            right_name = ace.get("RightName", "")
            if principal_sid and right_name:
                target_name = self.sid_to_name.get(principal_sid, principal_sid)
                has_acl_on[target_name] = right_name

        return FlattenedComputer(
            name=props.get("samaccountname", "Unknown").rstrip('$'),
            sid=computer.get("ObjectIdentifier", ""),
            domain=props.get("domain", ""),
            distinguished_name=props.get("distinguishedname", ""),
            enabled=props.get("enabled", True),
            unconstraineddelegation=props.get("unconstraineddelegation", False),
            haslaps=props.get("haslaps", False),
            operatingsystem=props.get("operatingsystem", "Unknown"),
            is_dc=props.get("isdc", False),
            local_admins=local_admins,
            sessions=sessions,
            privileged_sessions=privileged_sessions,
            has_acl_on=has_acl_on
        )

    def _flatten_group(self, group: Dict) -> FlattenedGroup:
        """扁平化组数据"""
        props = group.get("Properties", {})

        # 获取成员
        members = []
        for member in group.get("Members", []):
            member_sid = member.get("ObjectIdentifier", "")
            member_name = self.sid_to_name.get(member_sid, member_sid)
            members.append(member_name)

        # 获取 ACL
        has_acl_on = {}
        for ace in group.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", "")
            right_name = ace.get("RightName", "")
            if principal_sid and right_name:
                target_name = self.sid_to_name.get(principal_sid, principal_sid)
                has_acl_on[target_name] = right_name

        return FlattenedGroup(
            name=props.get("samaccountname", "Unknown"),
            sid=group.get("ObjectIdentifier", ""),
            domain=props.get("domain", ""),
            distinguished_name=props.get("distinguishedname", ""),
            description=props.get("description", ""),
            admincount=props.get("admincount", False),
            members=members,
            has_acl_on=has_acl_on
        )

    def _flatten_domain(self, domain: Dict) -> FlattenedDomain:
        """扁平化域数据"""
        props = domain.get("Properties", {})

        # 获取信任关系
        trusts = []
        for trust in domain.get("Trusts", []):
            trusts.append({
                "target": trust.get("TargetDomainName", ""),
                "direction": trust.get("TrustDirection", ""),
                "type": trust.get("TrustType", "")
            })

        # 获取 ACL
        has_acl_on = {}
        for ace in domain.get("Aces", []):
            principal_sid = ace.get("PrincipalSID", "")
            right_name = ace.get("RightName", "")
            if principal_sid and right_name:
                target_name = self.sid_to_name.get(principal_sid, principal_sid)
                has_acl_on[target_name] = right_name

        return FlattenedDomain(
            name=props.get("name", ""),
            sid=domain.get("ObjectIdentifier", ""),
            distinguished_name=props.get("distinguishedname", ""),
            functional_level=props.get("functionallevel", ""),
            trusts=trusts,
            has_acl_on=has_acl_on
        )

    def _resolve_group_memberships(self):
        """解析组成员关系"""
        # 遍历组，更新成员的 member_of 列表
        for group in self.raw_data["groups"]:
            group_sid = group.get("ObjectIdentifier", "")
            group_name = self.sid_to_name.get(group_sid, group_sid)

            for member in group.get("Members", []):
                member_sid = member.get("ObjectIdentifier", "")
                member_type = member.get("ObjectType", "")

                if member_type == "User" and member_sid in self.flattened_data["users"]:
                    self.flattened_data["users"][member_sid].member_of.append(group_name)
                elif member_type == "Computer" and member_sid in self.flattened_data["computers"]:
                    self.flattened_data["computers"][member_sid].member_of.append(group_name)
                elif member_type == "Group" and member_sid in self.flattened_data["groups"]:
                    self.flattened_data["groups"][member_sid].member_of.append(group_name)

    def get_name_by_sid(self, sid: str) -> str:
        """根据 SID 获取名称"""
        return self.sid_to_name.get(sid, sid)

    def get_sid_by_name(self, name: str) -> Optional[str]:
        """根据名称获取 SID"""
        # 尝试精确匹配
        name_upper = name.upper().strip()
        name_upper = name_upper.replace("@HTB.LOCAL", "").replace("@HTB", "")
        name_upper = name_upper.replace(".HTB.LOCAL", "").replace(".HTB", "")
        
        for sid, user in self.flattened_data["users"].items():
            if name_upper == user.name.upper():
                return sid

        for sid, computer in self.flattened_data["computers"].items():
            if name_upper == computer.name.upper():
                return sid

        for sid, group in self.flattened_data["groups"].items():
            if name_upper == group.name.upper():
                return sid

        return None

    def get_all_users(self) -> Dict[str, FlattenedUser]:
        """获取所有用户"""
        return self.flattened_data["users"]

    def get_all_computers(self) -> Dict[str, FlattenedComputer]:
        """获取所有计算机"""
        return self.flattened_data["computers"]

    def get_all_groups(self) -> Dict[str, FlattenedGroup]:
        """获取所有组"""
        return self.flattened_data["groups"]

    def get_all_domains(self) -> Dict[str, FlattenedDomain]:
        """获取所有域"""
        return self.flattened_data["domains"]


if __name__ == "__main__":
    # 测试代码
    loader = BloodHoundDataLoader("C:\\Users\\90898\\Desktop\\htb_forest\\BloodHoundData")
    data = loader.load()

    # 打印一些测试数据
    for sid, user in list(data["users"].items())[:3]:
        print(f"\n用户: {user.name}")
        print(f"  SID: {user.sid}")
        print(f"  域: {user.domain}")
        print(f"  组成员: {user.member_of[:5] if user.member_of else '无'}")
        print(f"  ASREP Roastable: {user.dontreqpreauth}")
        print(f"  Kerberoastable: {user.hasspn}")
