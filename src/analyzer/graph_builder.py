"""
BloodHound 图关系构建模块
使用 NetworkX 构建域关系图，支持多种攻击路径查询
"""

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field

from .data_loader import BloodHoundDataLoader


@dataclass
class GraphNode:
    """图节点数据结构"""
    sid: str
    name: str
    node_type: str  # user, computer, group, domain
    properties: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """图边数据结构"""
    source: str
    target: str
    relation: str  # MemberOf, Owns, HasSession, GenericAll 等
    properties: Dict = field(default_factory=dict)


# 攻击相关的 ACL 权限映射
PRIVILEGED_ACES = {
    "Owns": "完全控制",
    "GenericAll": "完全控制",
    "WriteDacl": "修改 ACL",
    "WriteOwner": "修改所有者",
    "GenericWrite": "通用写入",
    "AllExtendedRights": "所有扩展权限",
    "AddKeyCredentialLink": "添加密钥凭据链接",
    "ForceChangePassword": "强制修改密码",
    "ResetPassword": "重置密码",
    " DCSync": "DCSync",
    "GetChanges": "复制目录变更",
    "GetChangesAll": "复制所有目录变更",
}

# 高价值目标组
HIGH_VALUE_GROUPS = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "REMOTE DESKTOP USERS", "DNS ADMINS",
    "EXCHANGE GROUP", "EXCHANGE TRUSTED SUBSYSTEM"
}


class DomainGraphBuilder:
    """域关系图构建器"""

    def __init__(self, data_loader: BloodHoundDataLoader):
        self.data_loader = data_loader
        self.G = nx.DiGraph()
        self.reverse_G = nx.DiGraph()  # 反向图（用于反向查询）
        self.node_sid_map = {}  # SID 到节点的映射
        self.node_name_map = {}  # 名称到节点的映射

    def build(self) -> nx.DiGraph:
        """构建域关系图"""
        print("[*] 正在构建域关系图...")

        # 添加所有节点
        self._add_nodes()

        # 添加边
        self._add_edges()

        # 构建反向图
        self._build_reverse_graph()

        print(f"[*] 图构建完成: {len(self.G.nodes)} 个节点, {len(self.G.edges)} 条边")

        return self.G

    def _add_nodes(self):
        """添加所有节点"""
        # 添加用户节点
        for sid, user in self.data_loader.flattened_data["users"].items():
            self.G.add_node(sid,
                          name=user.name,
                          node_type="user",
                          domain=user.domain,
                          enabled=user.enabled,
                          dontreqpreauth=user.dontreqpreauth,
                          hasspn=user.hasspn,
                          admincount=user.admincount,
                          unconstraineddelegation=user.unconstraineddelegation,
                          member_of=user.member_of)
            self.node_sid_map[sid] = sid
            self.node_name_map[user.name.upper()] = sid

        # 添加计算机节点
        for sid, computer in self.data_loader.flattened_data["computers"].items():
            self.G.add_node(sid,
                          name=computer.name,
                          node_type="computer",
                          domain=computer.domain,
                          enabled=computer.enabled,
                          unconstraineddelegation=computer.unconstraineddelegation,
                          is_dc=computer.is_dc,
                          operatingsystem=computer.operatingsystem)
            self.node_sid_map[sid] = sid
            self.node_name_map[computer.name.upper()] = sid

        # 添加组节点
        for sid, group in self.data_loader.flattened_data["groups"].items():
            self.G.add_node(sid,
                          name=group.name,
                          node_type="group",
                          domain=group.domain,
                          description=group.description,
                          admincount=group.admincount,
                          members=group.members)
            self.node_sid_map[sid] = sid
            self.node_name_map[group.name.upper()] = sid

        # 添加域节点
        for sid, domain in self.data_loader.flattened_data["domains"].items():
            self.G.add_node(sid,
                          name=domain.name,
                          node_type="domain",
                          functional_level=domain.functional_level,
                          trusts=domain.trusts)
            self.node_sid_map[sid] = sid
            self.node_name_map[domain.name.upper()] = sid

    def _add_edges(self):
        """添加所有边"""
        # 添加组成员关系边
        self._add_member_of_edges()

        # 添加 ACL 权限边
        self._add_acl_edges()

        # 添加会话边
        self._add_session_edges()

        # 添加委派关系边
        self._add_delegation_edges()

    def _add_member_of_edges(self):
        """添加组成员关系边"""
        # 遍历用户，更新其所在组的成员列表
        for sid, user in self.data_loader.flattened_data["users"].items():
            if user.sid in self.G.nodes:
                # 用户 -> 组 的边
                for group_name in user.member_of:
                    # 查找对应的组 SID
                    group_sid = self._find_sid_by_name(group_name)
                    if group_sid and group_sid in self.G.nodes:
                        self.G.add_edge(user.sid, group_sid,
                                      relation="MemberOf",
                                      description=f"{user.name} 是 {group_name} 的成员")
                        # 添加反向边（组 -> 成员），表示该组的成员关系
                        self.G.add_edge(group_sid, user.sid,
                                      relation="Contains",
                                      description=f"{group_name} 包含 {user.name}")

        # 遍历组，添加嵌套组关系
        for sid, group in self.data_loader.flattened_data["groups"].items():
            if group.sid in self.G.nodes:
                for member_sid in self._get_group_member_sids(group):
                    if member_sid in self.G.nodes:
                        self.G.add_edge(member_sid, group.sid,
                                      relation="MemberOf",
                                      description=f"是 {group.name} 的成员")
                        # 添加反向边
                        self.G.add_edge(group.sid, member_sid,
                                      relation="Contains",
                                      description=f"{group.name} 包含成员")

    def _add_acl_edges(self):
        """添加 ACL 权限边"""
        # 从用户和计算机获取 ACL 信息
        for sid, user in self.data_loader.flattened_data["users"].items():
            if user.sid in self.G.nodes:
                for target_name, right_name in user.has_acl_on.items():
                    target_sid = self._find_sid_by_name(target_name)
                    if target_sid and target_sid in self.G.nodes:
                        self.G.add_edge(user.sid, target_sid,
                                      relation=right_name,
                                      description=f"拥有 {right_name} 权限 ({target_name})")

        # 从组获取 ACL 信息
        for sid, group in self.data_loader.flattened_data["groups"].items():
            if group.sid in self.G.nodes:
                for target_name, right_name in group.has_acl_on.items():
                    target_sid = self._find_sid_by_name(target_name)
                    if target_sid and target_sid in self.G.nodes:
                        self.G.add_edge(group.sid, target_sid,
                                      relation=right_name,
                                      description=f"拥有 {right_name} 权限")

        # 从计算机获取 ACL 信息
        for sid, computer in self.data_loader.flattened_data["computers"].items():
            if computer.sid in self.G.nodes:
                for target_name, right_name in computer.has_acl_on.items():
                    target_sid = self._find_sid_by_name(target_name)
                    if target_sid and target_sid in self.G.nodes:
                        self.G.add_edge(computer.sid, target_sid,
                                      relation=right_name,
                                      description=f"拥有 {right_name} 权限")

    def _add_session_edges(self):
        """添加会话边"""
        for sid, computer in self.data_loader.flattened_data["computers"].items():
            if computer.sid in self.G.nodes:
                # 添加普通会话
                for session in computer.sessions:
                    user_name = session.get("user", "")
                    user_sid = self._find_sid_by_name(user_name)
                    if user_sid and user_sid in self.G.nodes:
                        self.G.add_edge(user_sid, computer.sid,
                                      relation="HasSession",
                                      description=f"在 {computer.name} 上有会话")

                # 添加特权会话
                for session in computer.privileged_sessions:
                    user_name = session.get("user", "")
                    session_type = session.get("type", "privileged_session")
                    user_sid = self._find_sid_by_name(user_name)
                    if user_sid and user_sid in self.G.nodes:
                        self.G.add_edge(user_sid, computer.sid,
                                      relation=session_type,
                                      description=f"在 {computer.name} 上有特权会话 ({session_type})")

    def _add_delegation_edges(self):
        """添加委派关系边"""
        for sid, user in self.data_loader.flattened_data["users"].items():
            if user.sid in self.G.nodes:
                for target in user.allowed_to_delegate:
                    target_sid = self._find_sid_by_name(target)
                    if target_sid and target_sid in self.G.nodes:
                        self.G.add_edge(user.sid, target_sid,
                                      relation="AllowedToDelegate",
                                      description=f"允许委派到 {target}")

        for sid, computer in self.data_loader.flattened_data["computers"].items():
            if computer.sid in self.G.nodes:
                for target in computer.local_admins:
                    target_sid = self._find_sid_by_name(target)
                    if target_sid and target_sid in self.G.nodes:
                        self.G.add_edge(target_sid, computer.sid,
                                      relation="LocalAdmin",
                                      description=f"是 {computer.name} 的本地管理员")

    def _build_reverse_graph(self):
        """构建反向图"""
        self.reverse_G = self.G.reverse()

    def _get_group_member_sids(self, group) -> List[str]:
        """获取组的成员 SID 列表"""
        sids = []
        for member_name in group.members:
            member_sid = self._find_sid_by_name(member_name)
            if member_sid:
                sids.append(member_sid)
        return sids

    def _find_sid_by_name(self, name: str) -> Optional[str]:
        """根据名称查找 SID"""
        # 清理名称
        clean_name = name.upper().strip()
        clean_name = clean_name.replace("@HTB.LOCAL", "").replace("@HTB", "")
        clean_name = clean_name.replace(".HTB.LOCAL", "").replace(".HTB", "")
        clean_name = clean_name.rstrip('$')

        # 优先查找用户/计算机/组（避免被内置组名覆盖）
        for sid, user_name in self.data_loader.flattened_data["users"].items():
            if clean_name == user_name.name.upper():
                return sid

        for sid, computer_name in self.data_loader.flattened_data["computers"].items():
            if clean_name == computer_name.name.upper():
                return sid

        for sid, group_name in self.data_loader.flattened_data["groups"].items():
            if clean_name == group_name.name.upper():
                return sid

        # 查找内置组 SID（最后检查，避免同名覆盖）
        for sid, well_known_name in self.data_loader.WELL_KNOWN_SIDS.items():
            if clean_name in well_known_name.upper():
                return sid

        return None

    def get_node_by_name(self, name: str) -> Optional[str]:
        """根据名称获取节点 SID"""
        return self._find_sid_by_name(name)

    def search_nodes(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        """按关键字搜索节点（名称包含匹配）"""
        kw = (keyword or "").strip().upper()
        if not kw:
            return []

        matches: List[Dict[str, Any]] = []
        for sid in self.G.nodes:
            node = self.G.nodes[sid]
            name = node.get("name", "")
            if kw in name.upper():
                matches.append({
                    "sid": sid,
                    "name": name,
                    "type": node.get("node_type", "unknown"),
                    "domain": node.get("domain", ""),
                    "is_high_value": self.is_high_value_target(sid)
                })

        # 先按高价值目标排序，再按名称排序
        matches.sort(key=lambda x: (not x["is_high_value"], x["name"]))
        return matches[:limit]

    def resolve_node_candidates(self, identifier: str, limit: int = 10) -> List[str]:
        """解析节点候选（支持 SID、精确名、模糊名）"""
        if not identifier:
            return []

        if identifier in self.G.nodes:
            return [identifier]

        exact = self.get_node_by_name(identifier)
        if exact and exact in self.G.nodes:
            return [exact]

        kw = identifier.strip().upper()
        if not kw:
            return []

        candidates: List[str] = []
        for sid in self.G.nodes:
            name = self.G.nodes[sid].get("name", "")
            if kw in name.upper():
                candidates.append(sid)

        # 去重并限制数量
        seen = set()
        ordered = []
        for sid in candidates:
            if sid not in seen:
                ordered.append(sid)
                seen.add(sid)
            if len(ordered) >= limit:
                break
        return ordered

    def get_node_by_sid(self, sid: str) -> Optional[Dict]:
        """根据 SID 获取节点信息"""
        if sid in self.G.nodes:
            return dict(self.G.nodes[sid])
        return None

    def get_outbound_edges(self, sid: str) -> List[Tuple[str, str, Dict]]:
        """获取某节点的所有出边（我可以做什么）"""
        if sid not in self.G.nodes:
            return []
        return list(self.G.edges(sid, data=True))

    def get_inbound_edges(self, sid: str) -> List[Tuple[str, str, Dict]]:
        """获取某节点的所有入边（谁能控制我）"""
        if sid not in self.reverse_G.nodes:
            return []
        return list(self.reverse_G.edges(sid, data=True))

    def is_high_value_target(self, sid: str) -> bool:
        """判断是否为高价值目标"""
        node = self.get_node_by_sid(sid)
        if not node:
            return False

        name = node.get("name", "").upper()

        # 检查是否为高价值组
        for group_name in HIGH_VALUE_GROUPS:
            if group_name in name:
                return True

        # 检查是否为管理员账户
        if node.get("node_type") == "user" and node.get("admincount", False):
            return True

        # 检查是否为 DC
        if node.get("node_type") == "computer" and node.get("is_dc", False):
            return True

        return False

    def get_privilege_description(self, relation: str) -> str:
        """获取权限描述"""
        return PRIVILEGED_ACES.get(relation, relation)


class PathFinder:
    """攻击路径查找器"""

    def __init__(self, graph_builder: DomainGraphBuilder):
        self.graph_builder = graph_builder
        self.G = graph_builder.G

    def find_shortest_path(self, source: str, target: str, max_hops: int = 10) -> Optional[List[Dict]]:
        """查找从源到目标的最短攻击路径"""
        source_sid = self._resolve_node(source)
        target_sid = self._resolve_node(target)

        if not source_sid or not target_sid:
            return None

        if source_sid not in self.G.nodes or target_sid not in self.G.nodes:
            return None

        try:
            path = nx.shortest_path(self.G, source_sid, target_sid)
            return self._format_path(path)
        except nx.NetworkXNoPath:
            return None
        except nx.NetworkXError:
            return None

    def find_all_paths(self, source: str, target: str, max_hops: int = 5) -> List[List[Dict]]:
        """查找从源到目标的所有路径"""
        source_sid = self._resolve_node(source)
        target_sid = self._resolve_node(target)

        if not source_sid or not target_sid:
            return []

        if source_sid not in self.G.nodes or target_sid not in self.G.nodes:
            return []

        try:
            paths = list(nx.all_simple_paths(self.G, source_sid, target_sid, cutoff=max_hops))
            return [self._format_path(p) for p in paths]
        except (nx.NetworkXError, nx.NetworkXNoPath):
            return []

    def find_paths_to_high_value_targets(self, source: str, max_hops: int = 5) -> List[List[Dict]]:
        """查找从源到所有高价值目标的所有路径"""
        source_sid = self._resolve_node(source)
        if not source_sid or source_sid not in self.G.nodes:
            return []

        all_paths = []

        for node_sid in self.G.nodes:
            if self.graph_builder.is_high_value_target(node_sid) and node_sid != source_sid:
                try:
                    paths = list(nx.all_simple_paths(self.G, source_sid, node_sid, cutoff=max_hops))
                    for path in paths:
                        formatted_path = self._format_path(path)
                        if formatted_path:
                            all_paths.append(formatted_path)
                except (nx.NetworkXError, nx.NetworkXNoPath):
                    continue

        return all_paths

    def _resolve_node(self, identifier: str) -> Optional[str]:
        """解析节点标识符（名称或 SID）"""
        candidates = self.graph_builder.resolve_node_candidates(identifier, limit=2)
        # 仅在唯一匹配时自动解析，避免误判
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _format_path(self, path: List[str]) -> Optional[List[Dict]]:
        """格式化路径为可读的攻击链"""
        if len(path) < 2:
            return None

        formatted = []

        for i in range(len(path) - 1):
            source_sid = path[i]
            target_sid = path[i + 1]

            source_node = self.G.nodes[source_sid]
            target_node = self.G.nodes[target_sid]

            edge_data = self.G[source_sid][target_sid]
            relation = edge_data.get("relation", "Unknown")

            formatted.append({
                "step": i + 1,
                "from": {
                    "sid": source_sid,
                    "name": source_node.get("name", "Unknown"),
                    "type": source_node.get("node_type", "unknown")
                },
                "to": {
                    "sid": target_sid,
                    "name": target_node.get("name", "Unknown"),
                    "type": target_node.get("node_type", "unknown")
                },
                "relation": relation,
                "description": edge_data.get("description", self._get_relation_description(relation))
            })

        return formatted

    def _get_relation_description(self, relation: str) -> str:
        """获取关系描述"""
        descriptions = {
            "MemberOf": "组成员关系",
            "Owns": "拥有完全控制权",
            "GenericAll": "拥有完全控制权",
            "GenericWrite": "拥有通用写入权限",
            "WriteDacl": "可以修改 ACL",
            "WriteOwner": "可以修改所有者",
            "AllExtendedRights": "拥有所有扩展权限",
            "AddKeyCredentialLink": "可以添加密钥凭据链接",
            "ForceChangePassword": "可以强制修改密码",
            "HasSession": "在该计算机上有会话",
            "PrivilegedSession": "在该计算机上有特权会话",
            "RegistrySession": "在该计算机上有注册表会话",
            "LocalAdmin": "是该计算机的本地管理员",
            "AllowedToDelegate": "允许委派到该计算机"
        }
        return descriptions.get(relation, relation)


if __name__ == "__main__":
    # 测试代码
    from .data_loader import BloodHoundDataLoader

    loader = BloodHoundDataLoader("C:\\Users\\90898\\Desktop\\htb_forest\\BloodHoundData")
    loader.load()

    graph_builder = DomainGraphBuilder(loader)
    graph_builder.build()

    path_finder = PathFinder(graph_builder)

    # 测试路径查找
    path = path_finder.find_shortest_path("svc-alfresco", "Administrator")
    print("\n=== 路径测试: svc-alfresco -> Administrator ===")
    if path:
        for step in path:
            print(f"  {step['from']['name']} --[{step['relation']}]--> {step['to']['name']}")
    else:
        print("  未找到路径")
