"""
BloodHound 分析引擎核心模块
整合所有分析功能，提供统一的查询接口
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from .data_loader import BloodHoundDataLoader
from .graph_builder import DomainGraphBuilder, PathFinder
from .acl_analyzer import ACLAnalyzer, PrivilegeAnalyzer, UserACLAnalysis
from .attack_explainer import AttackChainExplainer, CompromiseAnalyzer, AttackChain


class BloodHoundAnalyzer:
    """
    BloodHound 数据分析引擎
    
    提供以下主要功能：
    - 数据加载和预处理
    - 用户/计算机/组查询
    - ACL 权限分析
    - 攻击路径查找
    - 攻击链自然语言生成
    - 账户被控后的攻击分析
    """

    def __init__(self, data_dir: str, domain_sid: str = None):
        """
        初始化分析引擎
        
        Args:
            data_dir: BloodHound JSON 数据文件所在目录
            domain_sid: 域 SID（可选，用于识别高价值目标）
        """
        self.data_dir = data_dir
        self.domain_sid = domain_sid or "S-1-5-21-3072663084-364016917-1341370565"
        
        # 初始化组件
        self.data_loader = BloodHoundDataLoader(data_dir)
        self.graph_builder = None
        self.path_finder = None
        self.acl_analyzer = None
        self.privilege_analyzer = None
        self.explainer = None
        self.compromise_analyzer = None
        
        # 数据状态
        self._is_loaded = False

    def load(self) -> bool:
        """
        加载并预处理 BloodHound 数据
        
        Returns:
            bool: 加载是否成功
        """
        try:
            print(f"[*] 正在加载数据: {self.data_dir}")
            
            # 加载数据
            self.data_loader.load()
            
            # 构建图
            self.graph_builder = DomainGraphBuilder(self.data_loader)
            self.graph_builder.build()
            
            # 初始化查找器
            self.path_finder = PathFinder(self.graph_builder)
            
            # 初始化分析器
            self.acl_analyzer = ACLAnalyzer(self.data_loader, self.graph_builder)
            self.privilege_analyzer = PrivilegeAnalyzer(self.data_loader, self.graph_builder)
            
            # 初始化解释器
            self.explainer = AttackChainExplainer(
                self.data_loader, 
                self.graph_builder, 
                self.path_finder
            )
            self.compromise_analyzer = CompromiseAnalyzer(
                self.data_loader,
                self.graph_builder,
                self.path_finder,
                self.acl_analyzer
            )
            
            self._is_loaded = True
            print("[*] 数据加载完成")
            
            return True
            
        except Exception as e:
            print(f"[!] 数据加载失败: {e}")
            return False

    def query_user(self, identifier: str) -> Optional[Dict]:
        """
        查询用户详细信息
        
        Args:
            identifier: 用户名或 SID
            
        Returns:
            用户信息字典，包含 ACL 分析结果
        """
        if not self._is_loaded:
            return {"error": "数据未加载，请先调用 load() 方法"}

        # 分析 ACL
        analysis = self.acl_analyzer.analyze_user(identifier)
        if not analysis:
            return {"error": f"用户 {identifier} 不存在"}

        return {
            "name": analysis.user_name,
            "sid": analysis.user_sid,
            "summary": analysis.summary,
            "member_of": analysis.member_of,
            "is_asrep_roastable": analysis.is_asrep_roastable,
            "is_kerberoastable": analysis.is_kerberoastable,
            "is_unconstrained_delegation": analysis.is_unconstrained_delegation,
            "is_high_value": analysis.is_high_value,
            "outbound_acl": [
                {
                    "target": acl.target_name,
                    "right": acl.right_name,
                    "description": acl.right_description,
                    "is_privileged": acl.is_privileged,
                    "via": acl.source_name if acl.source_name != analysis.user_name else None
                }
                for acl in analysis.outbound_acl
            ],
            "inbound_acl": [
                {
                    "source": acl.source_name,
                    "right": acl.right_name,
                    "description": acl.right_description,
                    "is_privileged": acl.is_privileged
                }
                for acl in analysis.inbound_acl
            ]
        }

    def query_computer(self, identifier: str) -> Optional[Dict]:
        """
        查询计算机详细信息
        
        Args:
            identifier: 计算机名或 SID
            
        Returns:
            计算机信息字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        # 尝试通过名称查找
        computer_sid = self.data_loader.get_sid_by_name(identifier)
        if not computer_sid:
            # 尝试清理名称
            clean_name = identifier.upper().strip().rstrip('$')
            for sid, computer in self.data_loader.flattened_data["computers"].items():
                if clean_name in computer.name.upper():
                    computer_sid = sid
                    break

        if not computer_sid:
            return {"error": f"计算机 {identifier} 不存在"}

        computer = self.data_loader.flattened_data["computers"].get(computer_sid)
        if not computer:
            return {"error": f"计算机 {identifier} 不存在"}

        return {
            "name": computer.name,
            "sid": computer_sid,
            "domain": computer.domain,
            "enabled": computer.enabled,
            "is_dc": computer.is_dc,
            "operatingsystem": computer.operatingsystem,
            "unconstrained_delegation": computer.unconstraineddelegation,
            "haslaps": computer.haslaps,
            "local_admins": computer.local_admins,
            "sessions": computer.sessions,
            "privileged_sessions": computer.privileged_sessions
        }

    def query_group(self, identifier: str) -> Optional[Dict]:
        """
        查询组详细信息
        
        Args:
            identifier: 组名或 SID
            
        Returns:
            组信息字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        group_sid = self.data_loader.get_sid_by_name(identifier)
        if not group_sid:
            name_upper = identifier.upper().strip()
            for sid, group in self.data_loader.flattened_data["groups"].items():
                if name_upper in group.name.upper():
                    group_sid = sid
                    break

        if not group_sid:
            return {"error": f"组 {identifier} 不存在"}

        group = self.data_loader.flattened_data["groups"].get(group_sid)
        if not group:
            return {"error": f"组 {identifier} 不存在"}

        return {
            "name": group.name,
            "sid": group_sid,
            "domain": group.domain,
            "description": group.description,
            "admincount": group.admincount,
            "members": group.members,
            "member_count": len(group.members),
            "has_acl_on": [
                {"target": target, "right": right}
                for target, right in group.has_acl_on.items()
            ]
        }

    def find_attack_path(self, source: str, target: str) -> Dict[str, Any]:
        """
        查找从源到目标的攻击路径
        
        Args:
            source: 起始用户名
            target: 目标用户名
            
        Returns:
            包含路径信息的字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        source_candidates = self.graph_builder.resolve_node_candidates(source, limit=8)
        target_candidates = self.graph_builder.resolve_node_candidates(target, limit=8)

        if not source_candidates:
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": f"未找到源节点: {source}",
                "source_candidates": []
            }

        if not target_candidates:
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": f"未找到目标节点: {target}",
                "target_candidates": []
            }

        if len(source_candidates) > 1:
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": f"源节点匹配到多个对象，请使用更精确名称: {source}",
                "source_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in source_candidates
                ]
            }

        if len(target_candidates) > 1:
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": f"目标节点匹配到多个对象，请使用更精确名称: {target}",
                "target_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in target_candidates
                ]
            }

        # 查找最短路径
        path = self.path_finder.find_shortest_path(source, target)
        
        if not path:
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": f"未找到从 {source} 到 {target} 的攻击路径"
            }

        # 解释路径
        chain = self.explainer.explain_path(path)

        return {
            "found": True,
            "source": source,
            "target": target,
            "steps": len(chain.steps) if chain else 0,
            "attack_methods": chain.attack_methods if chain else [],
            "difficulty": chain.difficulty if chain else "未知",
            "risk_level": chain.risk_level if chain else "未知",
            "summary": chain.summary if chain else "",
            "penetration_plan": self.explainer.generate_penetration_plan(chain) if chain else [],
            "path": [
                {
                    "step": step.step_number,
                    "from": step.from_name,
                    "to": step.to_name,
                    "relation": step.attack_method,
                    "description": step.description
                }
                for step in chain.steps
            ] if chain else []
        }

    def find_all_paths(self, source: str, target: str, max_hops: int = 5) -> Dict[str, Any]:
        """
        查找从源到目标的所有攻击路径
        
        Args:
            source: 起始用户名
            target: 目标用户名
            max_hops: 最大跳数
            
        Returns:
            包含所有路径的字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        source_candidates = self.graph_builder.resolve_node_candidates(source, limit=8)
        target_candidates = self.graph_builder.resolve_node_candidates(target, limit=8)

        if not source_candidates or not target_candidates:
            return {
                "found": False,
                "source": source,
                "target": target,
                "paths": [],
                "message": "源节点或目标节点不存在",
                "source_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in source_candidates
                ],
                "target_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in target_candidates
                ]
            }

        if len(source_candidates) > 1 or len(target_candidates) > 1:
            return {
                "found": False,
                "source": source,
                "target": target,
                "paths": [],
                "message": "源节点或目标节点匹配不唯一，请用更精确名称",
                "source_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in source_candidates
                ],
                "target_candidates": [
                    self.graph_builder.get_node_by_sid(sid).get("name", sid)
                    for sid in target_candidates
                ]
            }

        paths = self.path_finder.find_all_paths(source, target, max_hops)
        
        if not paths:
            return {
                "found": False,
                "source": source,
                "target": target,
                "paths": [],
                "message": f"未找到从 {source} 到 {target} 的攻击路径"
            }

        # 解释所有路径
        chains = self.explainer.explain_paths(paths)
        
        # 按风险等级排序
        chains.sort(key=lambda x: ["Low", "Medium", "High", "Critical"].index(x.risk_level) 
                             if x.risk_level in ["Low", "Medium", "High", "Critical"] else 2)

        return {
            "found": True,
            "source": source,
            "target": target,
            "path_count": len(chains),
            "paths": [
                {
                    "steps": len(chain.steps),
                    "attack_methods": chain.attack_methods,
                    "difficulty": chain.difficulty,
                    "risk_level": chain.risk_level,
                    "summary": chain.summary,
                    "penetration_plan": self.explainer.generate_penetration_plan(chain),
                    "path": [
                        {
                            "step": step.step_number,
                            "from": step.from_name,
                            "to": step.to_name,
                            "relation": step.attack_method,
                            "description": step.description
                        }
                        for step in chain.steps
                    ]
                }
                for chain in chains
            ]
        }

    def search_nodes(self, keyword: str, limit: int = 20) -> Dict[str, Any]:
        """按关键字搜索图节点"""
        if not self._is_loaded:
            return {"error": "数据未加载", "count": 0, "nodes": []}

        nodes = self.graph_builder.search_nodes(keyword, limit=limit)
        return {
            "keyword": keyword,
            "count": len(nodes),
            "nodes": [
                {
                    "name": n["name"],
                    "sid": n["sid"],
                    "type": n["type"],
                    "domain": n.get("domain", ""),
                    "is_high_value": n.get("is_high_value", False)
                }
                for n in nodes
            ]
        }

    def build_agent_handoff(self, source: str, target: str, max_hops: int = 5) -> Dict[str, Any]:
        """
        生成可直接交给 AI Agent 的结构化上下文。

        该输出用于让任意 Agent 基于图谱结果继续推进分析，而不是重新发明流程。
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        all_paths = self.find_all_paths(source, target, max_hops=max_hops)
        if not all_paths.get("found"):
            return {
                "found": False,
                "source": source,
                "target": target,
                "message": all_paths.get("message", "未找到路径"),
                "source_candidates": all_paths.get("source_candidates", []),
                "target_candidates": all_paths.get("target_candidates", [])
            }

        # 选择推荐路径：高风险优先，其次步数更短
        risk_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ranked = sorted(
            all_paths.get("paths", []),
            key=lambda p: (risk_rank.get(p.get("risk_level", "Medium"), 2), p.get("steps", 99))
        )
        recommended = ranked[0] if ranked else {}

        domain = self.get_domain_info().get("name", "<DOMAIN>")

        continuation_prompt = (
            "你是授权 AD 安全评估代理。"
            "基于以下图谱路径结果，继续输出下一阶段分析，不得臆造未在图谱出现的边。"
            "每一步必须包含：图谱证据、利用目标、前置条件、利用原理、授权实操模板、成功判据、失败排查、检测痕迹、修复建议。"
            f"\n\n当前任务: 从 {source} 到 {target} 的路径推进。"
            f"\n域: {domain}"
            "\n优先处理推荐路径；若失败，按备选路径切换并说明切换依据。"
            "\n所有模板使用占位符: <DOMAIN> <DC_IP> <USER> <TARGET_OBJECT>。"
        )

        next_actions = []
        for step in recommended.get("path", []):
            next_actions.append({
                "step": step.get("step"),
                "objective": f"将权限/可达性从 {step.get('from')} 推进到 {step.get('to')}",
                "graph_evidence": f"{step.get('from')} --[{step.get('relation')}]--> {step.get('to')}",
                "expected_result": "该步完成后出现新权限边或目标对象可访问",
                "fallback": "若该步失败，回滚并切换到下一条候选路径的同阶段步骤"
            })

        return {
            "found": True,
            "source": source,
            "target": target,
            "max_hops": max_hops,
            "path_count": all_paths.get("path_count", 0),
            "recommended_path": recommended,
            "alternative_paths": ranked[1:4],
            "agent_next_actions": next_actions,
            "continuation_prompt": continuation_prompt,
            "commands": {
                "verify_nodes": f"python scripts/analyze.py {self.data_dir} nodes <keyword>",
                "query_paths": f"python scripts/analyze.py {self.data_dir} pathx \"{source}\" \"{target}\" {max_hops}",
                "generate_view": f"python scripts/analyze.py {self.data_dir} visualize \"{source}\" \"{target}\" {max_hops}"
            }
        }

    def analyze_compromise(self, identifier: str) -> Dict[str, Any]:
        """
        分析账户被控后的所有攻击可能
        
        Args:
            identifier: 用户名或 SID
            
        Returns:
            包含攻击可能的字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        return self.compromise_analyzer.analyze_compromise(identifier)

    def find_privileged_users(self) -> Dict[str, List[str]]:
        """
        查找所有特权用户
        
        Returns:
            特权用户字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        return self.privilege_analyzer.find_all_privileged_users()

    def find_security_issues(self) -> List[Dict[str, str]]:
        """
        查找域内安全问题
        
        Returns:
            问题列表
        """
        if not self._is_loaded:
            return [{"error": "数据未加载"}]

        return self.privilege_analyzer.find_security_issues()

    def get_statistics(self) -> Dict[str, int]:
        """
        获取域内统计信息
        
        Returns:
            统计信息字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        return {
            "total_users": len(self.data_loader.flattened_data["users"]),
            "total_computers": len(self.data_loader.flattened_data["computers"]),
            "total_groups": len(self.data_loader.flattened_data["groups"]),
            "total_domains": len(self.data_loader.flattened_data["domains"]),
            "total_nodes": len(self.graph_builder.G.nodes),
            "total_edges": len(self.graph_builder.G.edges)
        }

    def get_domain_info(self) -> Dict[str, Any]:
        """
        获取域的基本信息
        
        Returns:
            域信息字典
        """
        if not self._is_loaded:
            return {"error": "数据未加载"}

        domains = self.data_loader.flattened_data["domains"]
        if not domains:
            return {"error": "未找到域信息"}

        domain = list(domains.values())[0]
        return {
            "name": domain.name,
            "sid": domain.sid,
            "functional_level": domain.functional_level,
            "trusts": domain.trusts
        }

    def export_to_json(self, filepath: str) -> bool:
        """
        导出分析结果到 JSON 文件
        
        Args:
            filepath: 输出文件路径
            
        Returns:
            是否成功
        """
        if not self._is_loaded:
            return False

        try:
            data = {
                "statistics": self.get_statistics(),
                "domain_info": self.get_domain_info(),
                "privileged_users": self.find_privileged_users(),
                "security_issues": self.find_security_issues()
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            return True
        except Exception as e:
            print(f"[!] 导出失败: {e}")
            return False


def analyze(data_dir: str, source: str = None, target: str = None) -> Dict[str, Any]:
    """
    快速分析函数
    
    Args:
        data_dir: BloodHound 数据目录
        source: 起始用户（可选）
        target: 目标用户（可选）
        
    Returns:
        分析结果
    """
    analyzer = BloodHoundAnalyzer(data_dir)
    
    if not analyzer.load():
        return {"error": "数据加载失败"}
    
    result = {
        "statistics": analyzer.get_statistics(),
        "domain_info": analyzer.get_domain_info(),
        "security_issues": analyzer.find_security_issues()
    }
    
    if source and target:
        result["attack_path"] = analyzer.find_attack_path(source, target)
    
    if source:
        result["compromise_analysis"] = analyzer.analyze_compromise(source)
    
    return result


if __name__ == "__main__":
    import sys
    
    # 命令行测试
    if len(sys.argv) > 1:
        data_dir = sys.argv[1]
        
        analyzer = BloodHoundAnalyzer(data_dir)
        if analyzer.load():
            print("\n=== BloodHound 数据分析 ===\n")
            
            # 打印统计信息
            stats = analyzer.get_statistics()
            print(f"统计信息:")
            print(f"  用户: {stats['total_users']}")
            print(f"  计算机: {stats['total_computers']}")
            print(f"  组: {stats['total_groups']}")
            print(f"  节点: {stats['total_nodes']}")
            print(f"  边: {stats['total_edges']}")
            
            # 如果有参数，查找攻击路径
            if len(sys.argv) > 3:
                source = sys.argv[2]
                target = sys.argv[3]
                
                print(f"\n查找攻击路径: {source} -> {target}")
                result = analyzer.find_attack_path(source, target)
                
                if result.get("found"):
                    print(f"\n找到路径 ({result['steps']} 步):")
                    for step in result["path"]:
                        print(f"  {step['from']} --[{step['relation']}]--> {step['to']}")
                else:
                    print(f"\n未找到路径")
            
            # 分析 svc-alfresco
            if "svc-alfresco" in [u.name for u in analyzer.data_loader.flattened_data["users"].values()]:
                print("\n=== svc-alfresco 分析 ===")
                analysis = analyzer.query_user("svc-alfresco")
                print(f"\n摘要: {analysis['summary']}")
                print(f"\n出站 ACL ({len(analysis['outbound_acl'])} 条):")
                for acl in analysis["outbound_acl"][:10]:
                    via = f" (via {acl['via']})" if acl['via'] else ""
                    print(f"  -> {acl['target']} [{acl['right']}]{via}")
        else:
            print("[!] 数据加载失败")
    else:
        print("用法: python core.py <data_dir> [source] [target]")
