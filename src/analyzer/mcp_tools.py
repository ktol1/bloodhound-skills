"""
BloodHound Analyzer MCP 工具封装
提供 MCP 工具接口供 AI 调用
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# 添加 src 目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analyzer.core import BloodHoundAnalyzer


# 全局分析器实例
_analyzer = None
_data_dir = None


def get_analyzer(data_dir: str = None) -> BloodHoundAnalyzer:
    """获取或创建分析器实例"""
    global _analyzer, _data_dir

    if _analyzer is None or data_dir != _data_dir:
        if data_dir is None:
            raise ValueError("必须提供 data_dir 参数来初始化分析器")
        _data_dir = data_dir
        _analyzer = BloodHoundAnalyzer(data_dir)
        if not _analyzer.load():
            raise RuntimeError("数据加载失败")

    return _analyzer


def reset_analyzer():
    """重置分析器实例"""
    global _analyzer, _data_dir
    _analyzer = None
    _data_dir = None


class BloodHoundMCPTools:
    """BloodHound MCP 工具类"""

    def __init__(self, data_dir: str):
        self.analyzer = BloodHoundAnalyzer(data_dir)
        if not self.analyzer.load():
            raise RuntimeError("数据加载失败")
        
        # 预加载所有用户/组名称
        self.all_users = list(self.analyzer.data_loader.flattened_data["users"].keys())
        self.all_computers = list(self.analyzer.data_loader.flattened_data["computers"].keys())
        self.all_groups = list(self.analyzer.data_loader.flattened_data["groups"].keys())

    # ===== 基础查询工具 =====

    @staticmethod
    def bh_get_statistics() -> str:
        """
        获取域内统计信息（用户数、计算机数、组数等）
        无需参数。
        """
        try:
            analyzer = get_analyzer()
            stats = analyzer.get_statistics()
            return json.dumps(stats, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_get_domain_info() -> str:
        """
        获取域的基本信息（域名、SID、功能级别、信任关系）
        无需参数。
        """
        try:
            analyzer = get_analyzer()
            info = analyzer.get_domain_info()
            return json.dumps(info, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_query_user(username: str) -> str:
        """
        查询用户详细信息及其权限。
        
        参数:
            username: 用户名（不区分大小写）
        
        返回用户信息，包括:
        - 基本属性（是否ASREP Roastable、Kerberoastable等）
        - 组成员关系
        - 出站ACL（该用户可以控制谁）
        - 入站ACL（谁能控制该用户）
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.query_user(username)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_query_computer(computername: str) -> str:
        """
        查询计算机详细信息。
        
        参数:
            computername: 计算机名（不区分大小写）
        
        返回计算机信息，包括:
        - 基本属性（是否DC、操作系统等）
        - 本地管理员
        - 会话信息
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.query_computer(computername)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_query_group(groupname: str) -> str:
        """
        查询组详细信息。
        
        参数:
            groupname: 组名（不区分大小写）
        
        返回组信息，包括:
        - 基本属性（描述、admincount等）
        - 成员列表
        - 该组对其他对象的ACL权限
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.query_group(groupname)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    # ===== 攻击路径查询工具 =====

    @staticmethod
    def bh_find_attack_path(source: str, target: str) -> str:
        """
        查找从源到目标的最短攻击路径。
        
        参数:
            source: 起始用户名（攻击者）
            target: 目标用户名（受害者）
        
        返回最短攻击路径，包括:
        - 攻击步骤数
        - 攻击技术类型
        - 难度评估
        - 风险等级
        - 详细步骤说明
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.find_attack_path(source, target)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_find_all_paths(source: str, target: str, max_hops: int = 5) -> str:
        """
        查找从源到目标的所有攻击路径（限制最大跳数）。
        
        参数:
            source: 起始用户名
            target: 目标用户名
            max_hops: 最大跳数（默认5）
        
        返回所有找到的攻击路径，按风险等级排序。
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.find_all_paths(source, target, max_hops)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_analyze_compromise(username: str) -> str:
        """
        分析账户被控后的所有攻击可能。
        
        参数:
            username: 被控用户名
        
        返回:
        - 该账户可利用的漏洞（ASREP Roastable、Kerberoastable等）
        - 该账户可以直接控制的目标
        - 可到达高价值目标的攻击路径
        - 攻击建议
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.analyze_compromise(username)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    # ===== 安全分析工具 =====

    @staticmethod
    def bh_find_privileged_users() -> str:
        """
        查找域内所有特权用户。
        
        返回:
        - Domain Admins 成员
        - ASREP Roastable 用户
        - Kerberoastable 用户
        - 无约束委派用户
        - 拥有 GenericAll 权限的用户
        - DC 本地管理员
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.find_privileged_users()
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_find_security_issues() -> str:
        """
        查找域内所有安全问题。
        
        返回问题列表，包括:
        - ASREP Roastable 用户
        - 密码永不过期的用户
        - 无约束委派配置
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.find_security_issues()
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_who_can_own(target: str) -> str:
        """
        查找谁可以完全控制（Owns）指定对象。
        
        参数:
            target: 目标用户名
        
        返回可以控制该目标的用户列表。
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.query_user(target)
            if "error" in result:
                return json.dumps(result, ensure_ascii=False)
            
            # 筛选 Owns 权限
            owners = []
            for acl in result.get("inbound_acl", []):
                if acl["right"] in ["Owns", "GenericAll"]:
                    owners.append(acl)
            
            return json.dumps({
                "target": target,
                "can_own": owners
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    @staticmethod
    def bh_who_can_admin(target: str) -> str:
        """
        查找谁可以管理员权限访问指定计算机。
        
        参数:
            target: 目标计算机名
        
        返回本地管理员列表。
        """
        try:
            analyzer = get_analyzer()
            result = analyzer.query_computer(target)
            if "error" in result:
                return json.dumps(result, ensure_ascii=False)
            
            return json.dumps({
                "computer": target,
                "is_dc": result.get("is_dc", False),
                "local_admins": result.get("local_admins", [])
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)


def initialize_mcp_tools(data_dir: str) -> Dict[str, Any]:
    """
    初始化 MCP 工具
    
    返回工具定义列表，可用于配置 MCP 服务器
    """
    return {
        "name": "bloodhound_analyzer",
        "description": "BloodHound AD 数据分析工具，用于域渗透路径分析",
        "tools": [
            {
                "name": "bh_get_statistics",
                "description": bh_get_statistics.__doc__,
                "parameters": {"type": "object", "properties": {}}
            },
            {
                "name": "bh_get_domain_info",
                "description": bh_get_domain_info.__doc__,
                "parameters": {"type": "object", "properties": {}}
            },
            {
                "name": "bh_query_user",
                "description": bh_query_user.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "用户名"}
                    },
                    "required": ["username"]
                }
            },
            {
                "name": "bh_query_computer",
                "description": bh_query_computer.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "computername": {"type": "string", "description": "计算机名"}
                    },
                    "required": ["computername"]
                }
            },
            {
                "name": "bh_query_group",
                "description": bh_query_group.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "groupname": {"type": "string", "description": "组名"}
                    },
                    "required": ["groupname"]
                }
            },
            {
                "name": "bh_find_attack_path",
                "description": bh_find_attack_path.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "起始用户"},
                        "target": {"type": "string", "description": "目标用户"}
                    },
                    "required": ["source", "target"]
                }
            },
            {
                "name": "bh_find_all_paths",
                "description": bh_find_all_paths.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "起始用户"},
                        "target": {"type": "string", "description": "目标用户"},
                        "max_hops": {"type": "integer", "description": "最大跳数", "default": 5}
                    },
                    "required": ["source", "target"]
                }
            },
            {
                "name": "bh_analyze_compromise",
                "description": bh_analyze_compromise.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "用户名"}
                    },
                    "required": ["username"]
                }
            },
            {
                "name": "bh_find_privileged_users",
                "description": bh_find_privileged_users.__doc__,
                "parameters": {"type": "object", "properties": {}}
            },
            {
                "name": "bh_find_security_issues",
                "description": bh_find_security_issues.__doc__,
                "parameters": {"type": "object", "properties": {}}
            },
            {
                "name": "bh_who_can_own",
                "description": bh_who_can_own.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "目标用户名"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "bh_who_can_admin",
                "description": bh_who_can_admin.__doc__,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "目标计算机名"}
                    },
                    "required": ["target"]
                }
            }
        ]
    }


if __name__ == "__main__":
    # 测试 MCP 工具
    print("=== BloodHound MCP 工具测试 ===\n")
    
    # 初始化工具
    tools = BloodHoundMCPTools("C:\\Users\\90898\\Desktop\\htb_forest\\BloodHoundData")
    
    # 测试统计信息
    print("1. 获取统计信息:")
    print(tools.bh_get_statistics())
    
    # 测试用户查询
    print("\n2. 查询 svc-alfresco 用户:")
    print(tools.bh_query_user("svc-alfresco"))
    
    # 测试攻击路径
    print("\n3. 查找攻击路径 svc-alfresco -> Administrator:")
    print(tools.bh_find_attack_path("svc-alfresco", "Administrator"))
    
    # 测试账户被控分析
    print("\n4. 分析 svc-alfresco 被控后的攻击可能:")
    print(tools.bh_analyze_compromise("svc-alfresco"))
