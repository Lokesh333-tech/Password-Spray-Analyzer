"""Explicit Bipartite Graph Data Structure and Breadth-First Search (BFS) traversal.

Models relationships between Source IP nodes and Targeted Username nodes.

Time Complexity:
  - Graph construction: O(V + E)
  - BFS traversal: O(V + E) where V = |IPs| + |Users|, E = distinct (IP, User) edges
Space Complexity:
  - O(V + E) for adjacency lists, visited set, and FIFO queue
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple


class BipartiteAuthGraph:
    """Undirected weighted bipartite graph linking IP addresses and usernames."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.adj: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": node_id.split(":", 1)[-1],
                "type": node_type,
                **(metadata or {}),
            }
            self.adj[node_id] = []
        elif metadata:
            self.nodes[node_id].update(metadata)

    def add_edge(self, ip: str, username: str, edge_data: Dict[str, Any]) -> None:
        ip_id = f"ip:{ip}"
        user_id = f"user:{username}"
        self.add_node(ip_id, "ip")
        self.add_node(user_id, "user")

        edge_record = {
            "id": f"{ip_id}->{user_id}",
            "source": ip_id,
            "target": user_id,
            **edge_data,
        }
        self.edges.append(edge_record)
        self.adj[ip_id].append((user_id, edge_record))
        self.adj[user_id].append((ip_id, edge_record))


def build_bipartite_graph(
    events: List[Dict[str, Any]],
    threat_ips: Optional[Dict[str, Dict[str, Any]]] = None,
    max_nodes: int = 180,
) -> BipartiteAuthGraph:
    """Construct a bipartite graph from authentication events and threat metadata."""
    threat_ips = threat_ips or {}
    graph = BipartiteAuthGraph()

    pair_agg: Dict[Tuple[str, str], Dict[str, Any]] = {}
    ip_totals: Dict[str, int] = {}
    user_totals: Dict[str, int] = {}

    for ev in events:
        ip = str(ev.get("source_ip", ""))
        user = str(ev.get("username", ""))
        status = str(ev.get("status", "")).upper()
        if not ip or not user:
            continue

        ip_totals[ip] = ip_totals.get(ip, 0) + 1
        user_totals[user] = user_totals.get(user, 0) + 1

        pair = (ip, user)
        if pair not in pair_agg:
            pair_agg[pair] = {
                "attempts": 0,
                "failures": 0,
                "successes": 0,
                "had_failure": False,
                "success_after_failure": False,
            }
        agg = pair_agg[pair]
        agg["attempts"] += 1
        if status == "SUCCESS":
            agg["successes"] += 1
            if agg["had_failure"]:
                agg["success_after_failure"] = True
        else:
            agg["failures"] += 1
            agg["had_failure"] = True

    # Prioritize suspicious IPs and most active normal IPs to keep network crisp & responsive
    ranked_ips = sorted(
        ip_totals.keys(),
        key=lambda x: (
            1 if x in threat_ips else 0,
            threat_ips[x]["risk_score"] if x in threat_ips else 0,
            ip_totals[x],
        ),
        reverse=True,
    )

    included_ips: Set[str] = set()
    included_users: Set[str] = set()

    for ip in ranked_ips:
        if len(included_ips) + len(included_users) >= max_nodes and ip not in threat_ips:
            continue
        included_ips.add(ip)

    for (ip, user), agg in sorted(pair_agg.items(), key=lambda item: -item[1]["attempts"]):
        if ip not in included_ips:
            continue
        if len(included_ips) + len(included_users) >= max_nodes and user not in included_users:
            if ip not in threat_ips:
                continue
        included_users.add(user)

        t_info = threat_ips.get(ip)
        graph.add_node(
            f"ip:{ip}",
            "ip",
            {
                "suspicious": ip in threat_ips,
                "risk_score": t_info["risk_score"] if t_info else 0,
                "severity": t_info["severity"] if t_info else "Normal",
                "total_attempts": ip_totals.get(ip, 0),
            },
        )
        graph.add_node(
            f"user:{user}",
            "user",
            {
                "total_attempts": user_totals.get(user, 0),
                "compromised": agg["success_after_failure"],
            },
        )
        graph.add_edge(ip, user, agg)

    return graph


def bfs_traverse(
    graph: BipartiteAuthGraph,
    start_node_id: str,
    max_depth: Optional[int] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Execute explicit Breadth-First Search (BFS) from start_node_id.

    Returns (traversal_result, metrics).
    """
    start_ns = time.perf_counter_ns()

    if start_node_id not in graph.adj:
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        return {
            "start_node": start_node_id,
            "traversal_order": [],
            "discovered_ips": [],
            "discovered_accounts": [],
            "levels": {},
            "edges_traversed": [],
        }, {
            "algorithm": "Breadth-First Search (BFS)",
            "vertices_total": len(graph.nodes),
            "edges_total": len(graph.edges),
            "vertices_visited": 0,
            "execution_time_ms": round(elapsed_ms, 4),
            "time_complexity": "O(V + E)",
            "space_complexity": "O(V)",
        }

    visited: Set[str] = {start_node_id}
    queue: deque[Tuple[str, int, Optional[str]]] = deque([(start_node_id, 0, None)])

    traversal_order: List[Dict[str, Any]] = []
    discovered_ips: List[str] = []
    discovered_accounts: List[str] = []
    levels: Dict[str, List[str]] = {}
    edges_traversed: List[str] = []
    step = 0

    while queue:
        current_id, depth, parent_id = queue.popleft()
        step += 1
        node_info = graph.nodes.get(current_id, {})

        traversal_order.append({
            "step": step,
            "node_id": current_id,
            "label": node_info.get("label", current_id),
            "node_type": node_info.get("type", "unknown"),
            "depth": depth,
            "parent": parent_id,
            "suspicious": bool(node_info.get("suspicious", False)),
            "compromised": bool(node_info.get("compromised", False)),
        })

        depth_key = str(depth)
        levels.setdefault(depth_key, []).append(current_id)

        if node_info.get("type") == "ip":
            discovered_ips.append(node_info.get("label", current_id))
        elif node_info.get("type") == "user":
            discovered_accounts.append(node_info.get("label", current_id))

        if max_depth is not None and depth >= max_depth:
            continue

        # Deterministic neighbor ordering by edge attempts descending
        neighbors = sorted(
            graph.adj.get(current_id, []),
            key=lambda pair: (-pair[1].get("attempts", 0), pair[0]),
        )
        for neighbor_id, edge_record in neighbors:
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                edges_traversed.append(edge_record["id"])
                queue.append((neighbor_id, depth + 1, current_id))

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    metrics = {
        "algorithm": "Breadth-First Search (BFS)",
        "vertices_total": len(graph.nodes),
        "edges_total": len(graph.edges),
        "vertices_visited": len(traversal_order),
        "max_depth_reached": max((item["depth"] for item in traversal_order), default=0),
        "execution_time_ms": round(elapsed_ms, 4),
        "time_complexity": "O(V + E)",
        "space_complexity": "O(V)",
    }
    return {
        "start_node": start_node_id,
        "traversal_order": traversal_order,
        "discovered_ips": discovered_ips,
        "discovered_accounts": discovered_accounts,
        "levels": levels,
        "edges_traversed": edges_traversed,
    }, metrics
