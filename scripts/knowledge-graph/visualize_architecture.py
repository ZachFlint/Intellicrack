"""A script to visualize the architecture of the Intellicrack project.

Optimized version with:
- Multiple layout algorithms (sfdp, hierarchical, radial)
- LOD clustering for large graphs
- Search trie with autocomplete
- Edge bundling for visual clarity
- Path finding between nodes
- WebGL rendering via Sigma.js
- Virtual lazy rendering (progressive display)
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import math
import os
import subprocess  # noqa: S404
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, ClassVar


try:
    import networkx as nx
except ImportError as e:
    print(f"Error: Missing required libraries. {e}")
    print("Please run: pip install networkx")
    sys.exit(1)


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ClusterManager:
    """Manages hierarchical clustering of nodes for LOD rendering."""

    def __init__(self, graph: nx.DiGraph) -> None:
        """Initialize the cluster manager with a graph."""
        self.graph = graph
        self.clusters: dict[str, set[str]] = defaultdict(set)
        self.cluster_meta: dict[str, dict[str, Any]] = {}
        self.node_to_cluster: dict[str, str] = {}

    def build_clusters(self, depth: int = 2) -> None:
        """Group nodes by their parent module at specified depth."""
        for node_id in self.graph.nodes:
            parts = node_id.replace("::", ".").split(".")
            if len(parts) >= depth:
                cluster_id = ".".join(parts[:depth])
            else:
                cluster_id = parts[0] if parts else "root"

            self.clusters[cluster_id].add(node_id)
            self.node_to_cluster[node_id] = cluster_id

        for cluster_id, members in self.clusters.items():
            types_count: dict[str, int] = defaultdict(int)
            for node_id in members:
                if node_id in self.graph.nodes:
                    node_type = self.graph.nodes[node_id].get("type", "unknown")
                    types_count[node_type] += 1

            self.cluster_meta[cluster_id] = {
                "size": len(members),
                "modules": types_count.get("module", 0),
                "classes": types_count.get("class", 0),
                "functions": types_count.get("function", 0),
                "structs": types_count.get("struct", 0),
                "children": sorted(members),
            }


class EdgeBundler:
    """Bundles edges by direction and proximity to reduce visual clutter."""

    MIN_BUNDLE_SIZE = 4

    def __init__(self, positions: dict[str, dict[str, float]]) -> None:
        """Initialize the edge bundler with node positions."""
        self.positions = positions

    def bundle_edges(self, edges: list[dict[str, Any]], angle_buckets: int = 24, region_size: float = 300.0) -> list[dict[str, Any]]:
        """Apply edge bundling based on direction and spatial proximity."""
        edge_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for edge in edges:
            from_pos = self.positions.get(edge["from"], {"x": 0, "y": 0})
            to_pos = self.positions.get(edge["to"], {"x": 0, "y": 0})

            dx = to_pos["x"] - from_pos["x"]
            dy = to_pos["y"] - from_pos["y"]

            if dx == 0 and dy == 0:
                edge_groups["zero"].append(edge)
                continue

            angle = math.atan2(dy, dx)
            angle_bucket = int((angle + math.pi) / (2 * math.pi) * angle_buckets)

            mid_x = int((from_pos["x"] + to_pos["x"]) / 2 / region_size)
            mid_y = int((from_pos["y"] + to_pos["y"]) / 2 / region_size)

            key = f"{angle_bucket}_{mid_x}_{mid_y}"
            edge_groups[key].append(edge)

        bundled_edges: list[dict[str, Any]] = []

        for group_edges in edge_groups.values():
            if len(group_edges) < self.MIN_BUNDLE_SIZE:
                bundled_edges.extend(group_edges)
                continue

            for i, edge in enumerate(group_edges):
                offset_factor = (i - len(group_edges) / 2) / len(group_edges)
                roundness = 0.15 + abs(offset_factor) * 0.2

                edge_copy = edge.copy()
                edge_copy["smooth"] = {
                    "enabled": True,
                    "type": "curvedCW" if i % 2 == 0 else "curvedCCW",
                    "roundness": roundness,
                }
                bundled_edges.append(edge_copy)

        return bundled_edges


class KnowledgeGraphGenerator:
    """Generates a comprehensive knowledge graph for Python projects."""

    MAX_LABEL_LENGTH = 30

    TYPE_COLORS: ClassVar[dict[str, str]] = {
        "module": "#4A90D9",
        "class": "#F5A623",
        "function": "#D0021B",
        "variable": "#BD10E0",
        "external": "#9B9B9B",
        "cluster": "#50E3C2",
        "entry": "#FF4444",
    }

    def __init__(self, root_dir: Path) -> None:
        """Initialize the knowledge graph generator."""
        self.root_dir = root_dir.resolve()
        if self.root_dir.name != "src":
            possible_sub = self.root_dir / "src"
            if possible_sub.exists():
                self.root_dir = possible_sub

        self.repo_root = self.root_dir.parent

        self.graph: nx.DiGraph = nx.DiGraph()
        self.module_map: dict[Path, str] = {}
        self.python_entry_points: set[str] = set()
        self.cluster_manager: ClusterManager | None = None

    def build_graph(self) -> None:
        """Builds the complete knowledge graph."""
        logger.info("Starting Python analysis...")
        self._scan_python()

        logger.info(
            "Graph built with %d nodes and %d edges.",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

        self.cluster_manager = ClusterManager(self.graph)
        self.cluster_manager.build_clusters(depth=2)
        logger.info("Built %d clusters.", len(self.cluster_manager.clusters))

    def _scan_python(self) -> None:
        """Scans Python files and parses deep structure."""
        try:
            for root, _, files in os.walk(self.root_dir):
                for file in files:
                    if file.endswith(".py"):
                        path = Path(root) / file
                        if "tests" in path.parts or "__pycache__" in path.parts:
                            continue

                        module_name = self._get_module_name(path)
                        self.module_map[path] = module_name
                        self.graph.add_node(module_name, type="module", lang="python", path=str(path), label=module_name)
                        self._parse_python_file(path, module_name)
        except (PermissionError, OSError):
            logger.exception("Error identifying files in directory %s", self.root_dir)

    def _parse_python_file(self, path: Path, module_name: str) -> None:
        """Deep parses a Python file for classes, functions, and variables."""
        try:
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(path))
        except Exception as e:
            logger.warning("Error parsing %s: %s", path, e)
            return

        imports_map: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = alias.name
                    imports_map[alias.asname or alias.name] = target
                    self.graph.add_edge(module_name, target, type="imports")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_base = node.module
                    if node.level > 0:
                        module_base = self._resolve_relative_import(module_name, node.module, node.level)
                    self.graph.add_edge(module_name, module_base, type="imports")
                    for alias in node.names:
                        full_target = f"{module_base}.{alias.name}"
                        imports_map[alias.asname or alias.name] = full_target

            elif isinstance(node, ast.ClassDef):
                class_id = f"{module_name}.{node.name}"
                self.graph.add_node(class_id, type="class", lang="python", label=node.name)
                self.graph.add_edge(module_name, class_id, type="defines")
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        base_name = imports_map.get(base.id, base.id)
                        self.graph.add_edge(class_id, base_name, type="inherits")

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_id = f"{module_name}.{node.name}"
                args = [a.arg for a in node.args.args]
                self.graph.add_node(func_id, type="function", lang="python", label=node.name, args=str(args))
                self.graph.add_edge(module_name, func_id, type="defines")

                if node.name == "main" and (module_name.endswith("__main__") or "intellicrack.main" in module_name):
                    self.python_entry_points.add(func_id)

    def _get_module_name(self, path: Path) -> str:
        try:
            rel_path = path.relative_to(self.repo_root)
            return str(rel_path.with_suffix("")).replace(os.sep, ".")
        except ValueError:
            return path.stem

    @staticmethod
    def _resolve_relative_import(current_module: str, partial_module: str | None, level: int) -> str:
        parts = current_module.split(".")
        if level >= len(parts):
            return partial_module if partial_module else ""
        base = ".".join(parts[:-level])
        if partial_module:
            return f"{base}.{partial_module}"
        return base

    def export_graphml(self, output_path: Path) -> None:
        """Export the graph to GraphML format."""
        try:
            nx.write_graphml(self.graph, str(output_path))
            logger.info("GraphML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save GraphML file:")

    def _calculate_hierarchical_layout(self, filtered_graph: nx.DiGraph) -> dict[str, dict[str, float]]:
        """Calculate hierarchical layout based on module depth with grid wrapping."""
        logger.info("Calculating hierarchical layout...")
        layout_map: dict[str, dict[str, float]] = {}

        levels: dict[int, list[str]] = defaultdict(list)
        type_offset = {"module": 0, "class": 1, "function": 2, "struct": 1, "external": 3}

        for node_id in filtered_graph.nodes:
            depth = node_id.count(".") + node_id.count("::")
            node_type = filtered_graph.nodes[node_id].get("type", "unknown")
            level = depth * 3 + type_offset.get(node_type, 0)
            levels[level].append(node_id)

        x_spacing = 40
        y_spacing = 40
        max_cols = 150
        level_gap = 80

        current_y = 0
        for level, node_ids in sorted(levels.items()):
            sorted_nodes = sorted(node_ids)
            n_nodes = len(sorted_nodes)
            cols = min(n_nodes, max_cols)
            rows = (n_nodes + cols - 1) // cols
            total_width = cols * x_spacing
            start_x = -total_width / 2

            for i, node_id in enumerate(sorted_nodes):
                row = i // cols
                col = i % cols
                layout_map[node_id] = {"x": start_x + (col * x_spacing), "y": current_y + (row * y_spacing)}

            current_y += rows * y_spacing + level_gap

        logger.info("Hierarchical layout calculated for %d nodes.", len(layout_map))
        return layout_map

    def _calculate_radial_layout(self, filtered_graph: nx.DiGraph) -> dict[str, dict[str, float]]:
        """Calculate radial layout with entry point at center."""
        logger.info("Calculating radial layout...")
        layout_map: dict[str, dict[str, float]] = {}

        center_node = None
        for node_id in filtered_graph.nodes:
            if "intellicrack.main" in node_id and filtered_graph.nodes[node_id].get("type") == "module":
                center_node = node_id
                break

        if not center_node:
            center_node = next(iter(filtered_graph.nodes), None) if filtered_graph.nodes else None

        if not center_node:
            return layout_map

        layout_map[center_node] = {"x": 0, "y": 0}

        try:
            lengths = nx.single_source_shortest_path_length(filtered_graph.to_undirected(), center_node)
        except nx.NetworkXError:
            lengths = {center_node: 0}
            for node in filtered_graph.nodes:
                if node != center_node:
                    lengths[node] = 1

        rings: dict[int, list[str]] = defaultdict(list)
        for node, dist in lengths.items():
            if node != center_node:
                rings[dist].append(node)

        ring_spacing = 200

        for ring_num, nodes_in_ring in sorted(rings.items()):
            radius = ring_num * ring_spacing
            sorted_nodes = sorted(nodes_in_ring)
            angle_step = 2 * math.pi / max(len(sorted_nodes), 1)

            for i, node_id in enumerate(sorted_nodes):
                angle = i * angle_step
                layout_map[node_id] = {"x": radius * math.cos(angle), "y": radius * math.sin(angle)}

        logger.info("Radial layout calculated for %d nodes.", len(layout_map))
        return layout_map

    def _calculate_sfdp_layout(self, dot_file: Path) -> dict[str, dict[str, float]]:
        """Calculates layout using sfdp and returns node positions."""
        logger.info("Calculating pre-loaded layout using sfdp (this may take a while)...")
        layout_map: dict[str, dict[str, float]] = {}

        try:
            json_output = subprocess.check_output(
                ["sfdp", "-K", "sfdp", "-Goverlap=prism", "-Gmaxiter=500", "-Tjson", str(dot_file)],
                text=True,
                stderr=subprocess.PIPE,
            )

            data = json.loads(json_output)

            if "objects" in data:
                for node in data["objects"]:
                    name = node.get("name")
                    pos = node.get("pos")
                    if name and pos:
                        try:
                            x, y = map(float, pos.split(","))
                            layout_map[name] = {"x": x * 5, "y": y * -5}
                        except ValueError:
                            pass

            logger.info("SFDP layout calculated for %d nodes.", len(layout_map))

        except subprocess.CalledProcessError as e:
            logger.exception("Graphviz layout calculation failed: %s", e.stderr)
        except FileNotFoundError:
            logger.warning("sfdp not found. Falling back to hierarchical layout.")
        except Exception:
            logger.exception("Error parsing layout JSON")

        return layout_map

    def _generate_dot_file(self, filtered_graph: nx.DiGraph, dot_path: Path) -> bool:
        """Generate DOT file for external layout tools."""
        try:
            try:
                nx.drawing.nx_pydot.write_dot(filtered_graph, str(dot_path))
            except (ImportError, AttributeError):
                with open(dot_path, "w", encoding="utf-8") as f:
                    f.write('digraph "Intellicrack" {\n')
                    for n in filtered_graph.nodes:
                        safe_n = n.replace('"', '\\"')
                        f.write(f'  "{safe_n}";\n')
                    for u, v in filtered_graph.edges:
                        safe_u = u.replace('"', '\\"')
                        safe_v = v.replace('"', '\\"')
                        f.write(f'  "{safe_u}" -> "{safe_v}";\n')
                    f.write("}\n")
            return True
        except Exception:
            logger.exception("Failed to generate DOT file.")
            return False

    def generate_interactive_html(  # noqa: PLR0914
        self,
        output_path: Path,
        layout_method: str = "sfdp",
        *,
        enable_clustering: bool = True,
        dot_output_dir: Path | None = None,
    ) -> None:
        """Generates a standalone HTML file with all optimizations."""
        logger.info("Filtering graph for visualization...")

        internal_nodes = {n for n in self.graph.nodes if n.startswith("intellicrack.")}

        boundary_nodes: set[str] = set()
        for u in internal_nodes:
            for v in self.graph.successors(u):
                if v not in internal_nodes:
                    boundary_nodes.add(v)

        candidates = internal_nodes.union(boundary_nodes)
        nodes_to_keep = {n for n in candidates if self.graph.nodes[n].get("type") != "variable"}

        filtered_graph = self.graph.subgraph(nodes_to_keep).copy()

        logger.info("Visualization graph: %d nodes (Original: %d)", len(filtered_graph), self.graph.number_of_nodes())

        if dot_output_dir is not None:
            dot_path = dot_output_dir / (output_path.stem + ".dot")
        else:
            dot_path = output_path.with_suffix(".dot")
        positions: dict[str, dict[str, float]] = {}

        self._generate_dot_file(filtered_graph, dot_path)
        logger.info("DOT file saved to: %s", dot_path)

        if layout_method == "hierarchical":
            positions = self._calculate_hierarchical_layout(filtered_graph)
        elif layout_method == "radial":
            positions = self._calculate_radial_layout(filtered_graph)
        else:
            if dot_path.exists():
                positions = self._calculate_sfdp_layout(dot_path)

            if not positions:
                logger.info("Falling back to hierarchical layout...")
                positions = self._calculate_hierarchical_layout(filtered_graph)

        nodes_data: list[dict[str, Any]] = []
        edges_data: list[dict[str, Any]] = []
        clusters_data: dict[str, dict[str, Any]] = {}

        if positions:
            xs = [p["x"] for p in positions.values()]
            ys = [p["y"] for p in positions.values()]
            min_x, max_x = min(xs), max(xs)
            min_y, max_y = min(ys), max(ys)
            width = max_x - min_x if max_x != min_x else 1
            height = max_y - min_y if max_y != min_y else 1
            scale = 800 / max(width, height)
            for node_id in positions:
                positions[node_id]["x"] = (positions[node_id]["x"] - min_x) * scale
                positions[node_id]["y"] = (positions[node_id]["y"] - min_y) * scale

        if enable_clustering and self.cluster_manager:
            for cluster_id, meta in self.cluster_manager.cluster_meta.items():
                if any(child.startswith("intellicrack.") for child in meta["children"]):
                    clusters_data[cluster_id] = {
                        "id": cluster_id,
                        "label": cluster_id.split(".")[-1],
                        "size": meta["size"],
                        "children": meta["children"],
                        "modules": meta["modules"],
                        "classes": meta["classes"],
                        "functions": meta["functions"],
                    }

        entry_point_id: str | None = None

        for node_id, attrs in filtered_graph.nodes(data=True):
            node_type = attrs.get("type", "unknown")

            if node_id in boundary_nodes:
                node_type = "external"

            label = attrs.get("label", node_id.split(".")[-1].split("::")[-1])
            if len(label) > self.MAX_LABEL_LENGTH:
                label = label[: self.MAX_LABEL_LENGTH - 3] + "..."

            color = self.TYPE_COLORS.get(node_type, "#D2E5FF")

            size_map = {"module": 8, "class": 6, "struct": 6, "function": 4, "external": 4}
            size = size_map.get(node_type, 3)

            if not entry_point_id:
                if "intellicrack.main" in node_id and node_type == "module":
                    entry_point_id = node_id

            if node_id == entry_point_id:
                color = "#FF4444"
                size = 12

            cluster_id = self.cluster_manager.node_to_cluster.get(node_id, "") if self.cluster_manager else ""

            node_data: dict[str, Any] = {
                "id": node_id,
                "label": label,
                "color": color,
                "type": node_type,
                "size": size,
                "cluster": cluster_id,
            }

            if node_id in positions:
                node_data["x"] = positions[node_id]["x"]
                node_data["y"] = positions[node_id]["y"]

            nodes_data.append(node_data)

        for u, v, _attrs in filtered_graph.edges(data=True):
            edge_data: dict[str, Any] = {
                "source": u,
                "target": v,
            }
            edges_data.append(edge_data)

        if positions:
            bundler = EdgeBundler(positions)
            vis_edges = [{"from": e["source"], "to": e["target"]} for e in edges_data]
            bundled = bundler.bundle_edges(vis_edges)
            edges_data = [
                {"source": e["from"], "target": e["to"], **{k: v for k, v in e.items() if k not in {"from", "to"}}} for e in bundled
            ]

        json_nodes = json.dumps(nodes_data)
        json_edges = json.dumps(edges_data)
        json_clusters = json.dumps(clusters_data)
        json_entry = json.dumps(entry_point_id) if entry_point_id else "null"
        json_colors = json.dumps(self.TYPE_COLORS)

        html_content = self._generate_html_template(json_nodes, json_edges, json_clusters, json_entry, json_colors)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("Interactive HTML saved to: %s", output_path)
        except Exception:
            logger.exception("Failed to save HTML file:")

    def _generate_html_template(
        self,
        json_nodes: str,
        json_edges: str,
        json_clusters: str,
        json_entry: str,
        json_colors: str,
    ) -> str:
        """Generate the complete HTML template with all JavaScript features."""
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Intellicrack Architecture Graph</title>
  <script src="https://unpkg.com/graphology@0.25.4/dist/graphology.umd.min.js"></script>
  <script src="https://unpkg.com/sigma@2.4.0/build/sigma.min.js"></script>
  <style>
    :root {{
      --bg-primary: #1a1a2e;
      --bg-secondary: rgba(26,26,46,0.95);
      --bg-tertiary: rgba(0,0,0,0.2);
      --text-primary: #eee;
      --text-secondary: #888;
      --accent: #667eea;
      --accent-secondary: #764ba2;
      --border: rgba(255,255,255,0.1);
      --success: #28a745;
      --danger: #dc3545;
      --info: #17a2b8;
    }}
    body.light-theme {{
      --bg-primary: #f5f5f5;
      --bg-secondary: rgba(255,255,255,0.95);
      --bg-tertiary: rgba(0,0,0,0.05);
      --text-primary: #222;
      --text-secondary: #666;
      --border: rgba(0,0,0,0.1);
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-primary); color: var(--text-primary); overflow: hidden; transition: background 0.3s, color 0.3s; }}
    #container {{ width: 100vw; height: 100vh; }}
    #loading {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(0,0,0,0.9); padding: 30px 50px; border-radius: 12px; z-index: 9999; text-align: center; }}
    #loading h2 {{ margin-bottom: 15px; color: var(--accent); }}
    .progress-bar {{ width: 200px; height: 6px; background: #333; border-radius: 3px; overflow: hidden; }}
    .progress-fill {{ height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-secondary)); width: 0%; transition: width 0.3s; }}
    #controls {{ position: fixed; top: 15px; right: 15px; width: 320px; background: var(--bg-secondary); border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); z-index: 1000; backdrop-filter: blur(10px); border: 1px solid var(--border); transition: background 0.3s; }}
    .controls-header {{ padding: 15px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
    .controls-header h3 {{ font-size: 16px; font-weight: 600; }}
    .theme-toggle {{ background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 14px; transition: all 0.2s; }}
    .theme-toggle:hover {{ border-color: var(--accent); }}
    .controls-body {{ padding: 15px 20px; }}
    .search-container {{ position: relative; margin-bottom: 15px; }}
    #search {{ width: 100%; padding: 10px 15px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; }}
    #search:focus {{ outline: none; border-color: var(--accent); }}
    .search-hint {{ font-size: 10px; color: var(--text-secondary); margin-top: 4px; }}
    #search-results {{ position: absolute; top: 100%; left: 0; right: 0; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; max-height: 300px; overflow-y: auto; display: none; z-index: 1001; margin-top: 5px; }}
    .search-result {{ padding: 10px 15px; cursor: pointer; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border); }}
    .search-result:hover, .search-result.selected {{ background: rgba(102,126,234,0.2); }}
    .result-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
    .result-label {{ flex: 1; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .result-type {{ font-size: 11px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 10px; }}
    .legend {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 15px; }}
    .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 12px; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    .view-controls {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
    .view-btn {{ padding: 6px 12px; font-size: 11px; border: 1px solid var(--border); background: transparent; color: var(--text-primary); border-radius: 6px; cursor: pointer; transition: all 0.2s; }}
    .view-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
    .view-btn.active {{ background: var(--accent); border-color: var(--accent); color: white; }}
    .cluster-toggle {{ width: 100%; padding: 8px 12px; margin-top: 10px; font-size: 11px; border: 1px solid var(--border); background: var(--bg-tertiary); color: var(--text-primary); border-radius: 6px; cursor: pointer; transition: all 0.2s; }}
    .cluster-toggle:hover {{ border-color: var(--accent); }}
    .cluster-toggle.active {{ background: #50E3C2; border-color: #50E3C2; color: #000; }}
    #panel {{ position: fixed; top: 15px; left: 15px; width: 380px; max-height: calc(100vh - 30px); background: var(--bg-secondary); border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); z-index: 1000; display: none; overflow: hidden; backdrop-filter: blur(10px); border: 1px solid var(--border); transition: background 0.3s; }}
    #panel.visible {{ display: block; animation: slideIn 0.3s ease; }}
    @keyframes slideIn {{ from {{ opacity: 0; transform: translateX(-20px); }} to {{ opacity: 1; transform: translateX(0); }} }}
    .panel-header {{ padding: 15px 20px; background: linear-gradient(135deg, var(--accent) 0%, var(--accent-secondary) 100%); display: flex; justify-content: space-between; align-items: center; }}
    .panel-title {{ font-weight: 600; font-size: 14px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: white; }}
    .panel-close {{ background: rgba(255,255,255,0.2); border: none; color: white; width: 28px; height: 28px; border-radius: 50%; cursor: pointer; font-size: 18px; }}
    .panel-close:hover {{ background: rgba(255,255,255,0.3); }}
    .node-info {{ padding: 15px 20px; background: var(--bg-tertiary); border-bottom: 1px solid var(--border); }}
    .info-row {{ display: flex; margin-bottom: 8px; font-size: 13px; }}
    .info-label {{ font-weight: 600; color: var(--text-secondary); width: 80px; flex-shrink: 0; }}
    .info-value {{ color: var(--text-primary); word-break: break-all; }}
    .action-bar {{ padding: 12px 20px; background: rgba(255,193,7,0.1); border-bottom: 1px solid rgba(255,193,7,0.2); display: flex; gap: 8px; flex-wrap: wrap; }}
    .action-btn {{ padding: 6px 12px; font-size: 11px; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; transition: transform 0.1s, opacity 0.2s; }}
    .action-btn:hover {{ opacity: 0.9; }}
    .action-btn:active {{ transform: scale(0.95); }}
    .action-btn.incoming {{ background: var(--success); color: white; }}
    .action-btn.outgoing {{ background: var(--danger); color: white; }}
    .action-btn.both {{ background: var(--accent); color: white; }}
    .action-btn.clear {{ background: #6c757d; color: white; }}
    .action-btn.path {{ background: var(--info); color: white; }}
    .panel-content {{ max-height: calc(100vh - 280px); overflow-y: auto; }}
    .section {{ border-bottom: 1px solid var(--border); }}
    .section-header {{ padding: 12px 20px; background: var(--bg-tertiary); font-weight: 600; font-size: 13px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
    .section-header:hover {{ background: rgba(102,126,234,0.1); }}
    .section-badge {{ padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
    .section-badge.out {{ background: var(--danger); }}
    .section-badge.in {{ background: var(--success); }}
    .virtual-list {{ position: relative; }}
    .virtual-list-viewport {{ max-height: 200px; overflow-y: auto; }}
    .virtual-list-spacer {{ width: 100%; }}
    .virtual-list-content {{ position: absolute; left: 0; right: 0; }}
    .connection-list {{ list-style: none; }}
    .connection-list.collapsed {{ display: none; }}
    .connection-item {{ padding: 10px 20px 10px 30px; border-bottom: 1px solid var(--border); cursor: pointer; display: flex; align-items: center; gap: 10px; height: 42px; box-sizing: border-box; }}
    .connection-item:hover, .connection-item.selected {{ background: rgba(102,126,234,0.15); }}
    .conn-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
    .conn-name {{ font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .conn-type {{ font-size: 10px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 6px; border-radius: 4px; }}
    .no-conn {{ padding: 20px; text-align: center; color: var(--text-secondary); font-size: 12px; font-style: italic; }}
    #pathfinder {{ display: none; padding: 15px 20px; background: rgba(23,162,184,0.1); border-bottom: 1px solid rgba(23,162,184,0.2); }}
    #pathfinder.visible {{ display: block; }}
    .pf-row {{ display: flex; gap: 10px; align-items: center; margin-bottom: 10px; }}
    .pf-input {{ flex: 1; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 12px; }}
    .pf-btn {{ padding: 8px 16px; background: var(--info); border: none; color: white; border-radius: 6px; cursor: pointer; font-size: 12px; }}
    #path-result {{ font-size: 12px; }}
    .path-step {{ display: inline-flex; align-items: center; gap: 5px; background: rgba(102,126,234,0.2); padding: 4px 10px; border-radius: 4px; margin: 2px; cursor: pointer; transition: background 0.2s; }}
    .path-step:hover {{ background: rgba(102,126,234,0.4); }}
    .path-arrow {{ color: var(--accent); margin: 0 5px; }}
    #stats {{ position: fixed; bottom: 15px; left: 15px; background: var(--bg-secondary); padding: 12px 20px; border-radius: 8px; font-size: 12px; z-index: 1000; display: flex; gap: 20px; backdrop-filter: blur(10px); border: 1px solid var(--border); transition: background 0.3s; }}
    .stat {{ display: flex; gap: 5px; }}
    .stat-value {{ font-weight: 600; color: var(--accent); }}
    #edge-tooltip {{ position: fixed; background: var(--bg-secondary); border: 1px solid var(--border); padding: 8px 12px; border-radius: 6px; font-size: 11px; pointer-events: none; z-index: 2000; display: none; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
    #keyboard-help {{ position: fixed; bottom: 15px; right: 15px; background: var(--bg-secondary); padding: 8px 12px; border-radius: 6px; font-size: 10px; color: var(--text-secondary); border: 1px solid var(--border); z-index: 999; cursor: pointer; }}
    #keyboard-help:hover {{ border-color: var(--accent); }}
    .kbd {{ background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px; font-family: monospace; margin: 0 2px; }}
    .cluster-node {{ stroke-dasharray: 4,2; }}
    .help-btn {{ background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 14px; transition: all 0.2s; margin-left: 8px; }}
    .help-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
    #shortcuts-modal {{ display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 3000; justify-content: center; align-items: center; backdrop-filter: blur(4px); }}
    #shortcuts-modal.visible {{ display: flex; }}
    .modal-content {{ background: var(--bg-secondary); border-radius: 12px; padding: 24px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; border: 1px solid var(--border); box-shadow: 0 20px 60px rgba(0,0,0,0.4); animation: modalIn 0.2s ease; }}
    @keyframes modalIn {{ from {{ opacity: 0; transform: scale(0.95); }} to {{ opacity: 1; transform: scale(1); }} }}
    .modal-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid var(--border); }}
    .modal-header h2 {{ font-size: 18px; font-weight: 600; }}
    .modal-close {{ background: none; border: none; color: var(--text-secondary); font-size: 24px; cursor: pointer; padding: 0; line-height: 1; }}
    .modal-close:hover {{ color: var(--text-primary); }}
    .shortcut-section {{ margin-bottom: 20px; }}
    .shortcut-section h3 {{ font-size: 12px; text-transform: uppercase; color: var(--accent); margin-bottom: 10px; letter-spacing: 0.5px; }}
    .shortcut-row {{ display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); }}
    .shortcut-row:last-child {{ border-bottom: none; }}
    .shortcut-keys {{ display: flex; gap: 4px; }}
    .shortcut-desc {{ color: var(--text-secondary); font-size: 13px; }}
  </style>
</head>
<body>
  <div id="loading"><h2>Building Graph</h2><div class="progress-bar"><div class="progress-fill" id="progress"></div></div><p id="load-status">Initializing...</p></div>
  <div id="container"></div>
  <div id="controls">
    <div class="controls-header"><h3>Intellicrack Architecture</h3><div style="display:flex;gap:4px"><button class="help-btn" onclick="toggleShortcuts()" title="Keyboard shortcuts">?</button><button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">&#9728;</button></div></div>
    <div class="controls-body">
      <div class="search-container">
        <input type="text" id="search" autocomplete="off" aria-label="Search nodes">
        <div class="search-hint">Press <span class="kbd">Ctrl+F</span> to search, <span class="kbd">&#8593;</span><span class="kbd">&#8595;</span> to navigate, <span class="kbd">Enter</span> to select</div>
        <div id="search-results"></div>
      </div>
      <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:#FF4444"></div>Entry</div>
        <div class="legend-item"><div class="legend-dot" style="background:#4A90D9"></div>Module</div>
        <div class="legend-item"><div class="legend-dot" style="background:#F5A623"></div>Class</div>
        <div class="legend-item"><div class="legend-dot" style="background:#D0021B"></div>Function</div>
        <div class="legend-item"><div class="legend-dot" style="background:#7ED321"></div>Struct</div>
        <div class="legend-item"><div class="legend-dot" style="background:#9B9B9B"></div>External</div>
      </div>
      <div class="view-controls">
        <button class="view-btn active" data-filter="all">All</button>
        <button class="view-btn" data-filter="module">Modules</button>
        <button class="view-btn" data-filter="class">Classes</button>
        <button class="view-btn" data-filter="function">Functions</button>
      </div>
      <button class="cluster-toggle" id="cluster-toggle">&#128448; Toggle Cluster View</button>
    </div>
  </div>
  <div id="panel">
    <div class="panel-header"><span class="panel-title" id="panel-title">Node</span><button class="panel-close" onclick="closePanel()">&times;</button></div>
    <div class="node-info" id="node-info"></div>
    <div class="action-bar">
      <button class="action-btn incoming" onclick="highlight('in')">Incoming</button>
      <button class="action-btn outgoing" onclick="highlight('out')">Outgoing</button>
      <button class="action-btn both" onclick="highlight('both')">Both</button>
      <button class="action-btn clear" onclick="clearHL()">Clear</button>
      <button class="action-btn path" onclick="togglePathfinder()">Find Path</button>
    </div>
    <div id="pathfinder">
      <div class="pf-row"><label for="pf-to" style="font-size:11px;color:var(--text-secondary);margin-right:8px">Target:</label><input type="text" class="pf-input" id="pf-to" aria-label="Target node"><button class="pf-btn" onclick="findPath()">Go</button></div>
      <div id="path-result"></div>
    </div>
    <div class="panel-content">
      <div class="section">
        <div class="section-header" onclick="toggleSec('out')"><span>Outgoing</span><span class="section-badge out" id="out-count">0</span></div>
        <div class="virtual-list" id="out-virtual">
          <div class="virtual-list-viewport" id="out-viewport">
            <div class="virtual-list-spacer" id="out-spacer"></div>
            <ul class="connection-list virtual-list-content" id="out-list"></ul>
          </div>
        </div>
      </div>
      <div class="section">
        <div class="section-header" onclick="toggleSec('in')"><span>Incoming</span><span class="section-badge in" id="in-count">0</span></div>
        <div class="virtual-list" id="in-virtual">
          <div class="virtual-list-viewport" id="in-viewport">
            <div class="virtual-list-spacer" id="in-spacer"></div>
            <ul class="connection-list virtual-list-content" id="in-list"></ul>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div id="stats">
    <div class="stat">Nodes: <span class="stat-value" id="stat-nodes">0</span></div>
    <div class="stat">Edges: <span class="stat-value" id="stat-edges">0</span></div>
    <div class="stat">Visible: <span class="stat-value" id="stat-visible">0</span></div>
  </div>
  <div id="edge-tooltip"></div>
  <div id="keyboard-help" onclick="toggleShortcuts()"><span class="kbd">?</span> Keyboard Shortcuts</div>
  <div id="shortcuts-modal" onclick="if(event.target===this)toggleShortcuts()">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Keyboard Shortcuts</h2>
        <button class="modal-close" onclick="toggleShortcuts()">&times;</button>
      </div>
      <div class="shortcut-section">
        <h3>General</h3>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Ctrl</span><span class="kbd">F</span></div><span class="shortcut-desc">Focus search input</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Esc</span></div><span class="shortcut-desc">Close panel and search</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">T</span></div><span class="shortcut-desc">Toggle dark/light theme</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">?</span></div><span class="shortcut-desc">Show this help dialog</span></div>
      </div>
      <div class="shortcut-section">
        <h3>Search</h3>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">&#8593;</span><span class="kbd">&#8595;</span></div><span class="shortcut-desc">Navigate search results</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Enter</span></div><span class="shortcut-desc">Select highlighted result</span></div>
      </div>
      <div class="shortcut-section">
        <h3>Node Panel</h3>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">&#8592;</span></div><span class="shortcut-desc">Go to first incoming connection</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">&#8594;</span></div><span class="shortcut-desc">Go to first outgoing connection</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">&#8593;</span><span class="kbd">&#8595;</span></div><span class="shortcut-desc">Navigate connection lists</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Enter</span></div><span class="shortcut-desc">Go to selected connection</span></div>
      </div>
      <div class="shortcut-section">
        <h3>Graph</h3>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Scroll</span></div><span class="shortcut-desc">Zoom in/out</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Drag</span></div><span class="shortcut-desc">Pan the graph</span></div>
        <div class="shortcut-row"><div class="shortcut-keys"><span class="kbd">Click</span></div><span class="shortcut-desc">Select node</span></div>
      </div>
    </div>
  </div>
  <script>
const rawNodes={json_nodes};const rawEdges={json_edges};const clusters={json_clusters};const entryPoint={json_entry};const typeColors={json_colors};
let graph,renderer,selectedNode=null,currentFilter='all',clusterMode=false,isDarkTheme=true;
const connIndex={{in:{{}},out:{{}}}};const searchTrie={{}};const nodeMap=new Map();const clusterState={{}};
let searchSelectedIdx=-1,currentSearchResults=[];
const ITEM_HEIGHT=42;const VISIBLE_BUFFER=5;

const workerCode=`
self.onmessage=function(e){{
  const{{type,data}}=e.data;
  if(type==='search'){{
    const{{query,trie,limit}}=data;
    if(!query||query.length<2){{self.postMessage({{type:'searchResult',results:[]}});return;}}
    const ql=query.toLowerCase();
    let c=trie;
    for(const ch of ql)if(!c[ch]){{self.postMessage({{type:'searchResult',results:[]}});return;}}else c=c[ch];
    const ids=Array.from(c.nodes||[]).slice(0,limit);
    self.postMessage({{type:'searchResult',results:ids}});
  }}
  if(type==='findPath'){{
    const{{from,to,connIn,connOut,maxLen}}=data;
    if(from===to){{self.postMessage({{type:'pathResult',path:[from]}});return;}}
    const q=[[from]],v=new Set([from]);
    while(q.length){{
      const p=q.shift();
      if(p.length>maxLen)continue;
      const c=p[p.length-1];
      const nb=[...(connOut[c]||[]),...(connIn[c]||[])];
      for(const n of nb){{
        if(n===to){{self.postMessage({{type:'pathResult',path:[...p,n]}});return;}}
        if(!v.has(n)){{v.add(n);q.push([...p,n]);}}
      }}
    }}
    self.postMessage({{type:'pathResult',path:null}});
  }}
}};`;
let worker=null;
try{{const blob=new Blob([workerCode],{{type:'application/javascript'}});worker=new Worker(URL.createObjectURL(blob));}}catch(e){{console.warn('WebWorker not available, using main thread');}}

function setProgress(p,m){{document.getElementById('progress').style.width=p+'%';document.getElementById('load-status').textContent=m;}}
function chunk(arr,size){{const r=[];for(let i=0;i<arr.length;i+=size)r.push(arr.slice(i,i+size));return r;}}
async function processChunks(chunks,fn,base,range,label){{for(let i=0;i<chunks.length;i++){{chunks[i].forEach(fn);const pct=base+Math.floor((i+1)/chunks.length*range);setProgress(pct,label+' ('+(i+1)+'/'+chunks.length+')');await new Promise(r=>requestAnimationFrame(r));}}}}

function searchNodes(q,l=15){{
  if(!q||q.length<2)return[];
  const ql=q.toLowerCase();
  let c=searchTrie;
  for(const ch of ql)if(!c[ch])return[];else c=c[ch];
  return Array.from(c.nodes||[]).slice(0,l).map(id=>nodeMap.get(id)).filter(Boolean)
    .sort((a,b)=>{{const aE=a.label.toLowerCase()===ql,bE=b.label.toLowerCase()===ql;if(aE&&!bE)return-1;if(bE&&!aE)return 1;return a.label.length-b.label.length;}});
}}

function findShortestPath(f,t,m=15){{
  if(f===t)return[f];
  const q=[[f]],v=new Set([f]);
  while(q.length){{
    const p=q.shift();
    if(p.length>m)continue;
    const c=p[p.length-1],nb=[...(connIndex.out[c]||[]),...(connIndex.in[c]||[])];
    for(const n of nb){{if(n===t)return[...p,n];if(!v.has(n)){{v.add(n);q.push([...p,n]);}}}}
  }}
  return null;
}}

async function init(){{
  setProgress(5,'Initializing...');
  await new Promise(r=>requestAnimationFrame(r));
  graph=new graphology.Graph({{allowSelfLoops:false,multi:false}});
  const CHUNK=2000;
  const nodeChunks=chunk(rawNodes,CHUNK);
  const edgeChunks=chunk(rawEdges,CHUNK);

  await processChunks(nodeChunks,n=>{{
    nodeMap.set(n.id,n);
    graph.addNode(n.id,{{
      x:n.x||Math.random()*1000,y:n.y||Math.random()*1000,
      size:n.size,color:n.color,label:n.label,nodeType:n.type,
      cluster:n.cluster,originalColor:n.color,originalSize:n.size,hidden:false
    }});
  }},5,35,'Adding nodes');

  await processChunks(edgeChunks,e=>{{
    if(e.source!==e.target&&graph.hasNode(e.source)&&graph.hasNode(e.target)&&!graph.hasEdge(e.source,e.target))
      graph.addEdge(e.source,e.target,{{color:'rgba(150,150,150,0.15)',size:0.3,originalColor:'rgba(150,150,150,0.15)'}});
  }},40,25,'Adding edges');

  setProgress(70,'Building search index...');
  await new Promise(r=>requestAnimationFrame(r));
  const trieChunks=chunk(rawNodes,CHUNK);
  for(let i=0;i<trieChunks.length;i++){{
    trieChunks[i].forEach(n=>{{
      [n.id.toLowerCase(),n.label.toLowerCase()].forEach(t=>{{
        let c=searchTrie;
        for(const ch of t){{if(!c[ch])c[ch]={{nodes:new Set()}};c=c[ch];c.nodes.add(n.id);}}
      }});
    }});
    await new Promise(r=>requestAnimationFrame(r));
  }}

  rawEdges.forEach(e=>{{
    if(!connIndex.out[e.source])connIndex.out[e.source]=[];
    connIndex.out[e.source].push(e.target);
    if(!connIndex.in[e.target])connIndex.in[e.target]=[];
    connIndex.in[e.target].push(e.source);
  }});

  Object.keys(clusters).forEach(cid=>{{clusterState[cid]=true;}});

  setProgress(85,'Starting renderer...');
  await new Promise(r=>requestAnimationFrame(r));

  const container=document.getElementById('container');
  renderer=new Sigma(graph,container,{{
    renderLabels:true,labelThreshold:12,labelRenderedSizeThreshold:8,
    labelFont:'Segoe UI',labelSize:11,labelWeight:'normal',
    labelColor:{{color:'#ffffff'}},
    defaultNodeColor:'#4A90D9',defaultEdgeColor:'rgba(150,150,150,0.1)',
    minCameraRatio:0.01,maxCameraRatio:15,
    enableEdgeEvents:true,zIndex:true,renderEdgeLabels:false,
    enableEdgeClickEvents:false,enableEdgeWheelEvents:false,
    enableEdgeHoverEvents:true,stagePadding:50
  }});

  renderer.on('clickNode',({{node}})=>showPanel(node));
  renderer.on('clickStage',()=>closePanel());

  renderer.on('enterEdge',({{edge}})=>{{
    const tooltip=document.getElementById('edge-tooltip');
    const src=graph.source(edge),tgt=graph.target(edge);
    const srcLabel=graph.getNodeAttribute(src,'label');
    const tgtLabel=graph.getNodeAttribute(tgt,'label');
    tooltip.innerHTML=`<strong>${{srcLabel}}</strong> &#8594; <strong>${{tgtLabel}}</strong>`;
    tooltip.style.display='block';
    graph.setEdgeAttribute(edge,'color','rgba(102,126,234,0.9)');
    graph.setEdgeAttribute(edge,'size',2);
    renderer.refresh();
  }});

  renderer.on('leaveEdge',({{edge}})=>{{
    const tooltip=document.getElementById('edge-tooltip');
    tooltip.style.display='none';
    const orig=graph.getEdgeAttribute(edge,'originalColor')||'rgba(150,150,150,0.15)';
    graph.setEdgeAttribute(edge,'color',orig);
    graph.setEdgeAttribute(edge,'size',0.3);
    renderer.refresh();
  }});

  document.addEventListener('mousemove',e=>{{
    const tooltip=document.getElementById('edge-tooltip');
    if(tooltip.style.display==='block'){{
      tooltip.style.left=(e.clientX+15)+'px';
      tooltip.style.top=(e.clientY+15)+'px';
    }}
  }});

  setProgress(100,'Done!');
  await new Promise(r=>setTimeout(r,200));
  document.getElementById('loading').style.display='none';
  updateStats();

  renderer.getCamera().setState({{x:0,y:0,ratio:0.5,angle:0}});
}}

function updateStats(){{
  document.getElementById('stat-nodes').textContent=graph.order;
  document.getElementById('stat-edges').textContent=graph.size;
  let v=0;graph.forEachNode((n,a)=>{{if(!a.hidden)v++;}});
  document.getElementById('stat-visible').textContent=v;
}}

function setFilter(f){{
  currentFilter=f;
  document.querySelectorAll('.view-btn').forEach(b=>{{
    b.classList.toggle('active',b.dataset.filter===f);
  }});
  graph.forEachNode((n,a)=>{{
    const show=f==='all'||a.nodeType===f;
    graph.setNodeAttribute(n,'hidden',!show);
    graph.setNodeAttribute(n,'color',show?a.originalColor:'rgba(100,100,100,0.1)');
  }});
  renderer.refresh();
  updateStats();
}}

function toggleClusterMode(){{
  clusterMode=!clusterMode;
  document.getElementById('cluster-toggle').classList.toggle('active',clusterMode);

  if(clusterMode){{
    Object.entries(clusters).forEach(([cid,meta])=>{{
      if(!clusterState[cid]){{
        meta.children.forEach(childId=>{{
          if(graph.hasNode(childId)&&childId!==cid){{
            graph.setNodeAttribute(childId,'hidden',true);
          }}
        }});
      }}
    }});
  }}else{{
    graph.forEachNode((n,a)=>{{
      const show=currentFilter==='all'||a.nodeType===currentFilter;
      graph.setNodeAttribute(n,'hidden',!show);
      graph.setNodeAttribute(n,'color',show?a.originalColor:'rgba(100,100,100,0.1)');
    }});
  }}
  renderer.refresh();
  updateStats();
}}

function toggleCluster(clusterId){{
  if(!clusters[clusterId])return;
  clusterState[clusterId]=!clusterState[clusterId];
  const expanded=clusterState[clusterId];

  clusters[clusterId].children.forEach(childId=>{{
    if(graph.hasNode(childId)&&childId!==clusterId){{
      const show=expanded&&(currentFilter==='all'||graph.getNodeAttribute(childId,'nodeType')===currentFilter);
      graph.setNodeAttribute(childId,'hidden',!show);
    }}
  }});

  renderer.refresh();
  updateStats();
}}

function showPanel(nodeId){{
  selectedNode=nodeId;
  const a=graph.getNodeAttributes(nodeId);

  document.getElementById('panel-title').textContent=a.label;
  document.getElementById('panel-title').title=nodeId;

  let clusterHtml=a.cluster||'N/A';
  if(clusters[a.cluster]){{
    clusterHtml=`<span style="cursor:pointer;text-decoration:underline" onclick="toggleCluster('${{a.cluster}}')">${{a.cluster}}</span>`;
  }}

  document.getElementById('node-info').innerHTML=
    '<div class="info-row"><span class="info-label">Type:</span><span class="info-value">'+a.nodeType+'</span></div>'+
    '<div class="info-row"><span class="info-label">Full Path:</span><span class="info-value">'+nodeId+'</span></div>'+
    '<div class="info-row"><span class="info-label">Cluster:</span><span class="info-value">'+clusterHtml+'</span></div>';

  const outN=connIndex.out[nodeId]||[],inN=connIndex.in[nodeId]||[];
  document.getElementById('out-count').textContent=outN.length;
  document.getElementById('in-count').textContent=inN.length;

  setupVirtualList('out',outN);
  setupVirtualList('in',inN);

  document.getElementById('pf-to').value='';
  document.getElementById('path-result').innerHTML='';
  document.getElementById('pathfinder').classList.remove('visible');
  document.getElementById('panel').classList.add('visible');

  const pos=graph.getNodeAttributes(nodeId);
  renderer.getCamera().animate({{x:pos.x,y:pos.y,ratio:0.5}},{{duration:400,easing:'quadraticOut'}});
}}

function setupVirtualList(type,nodes){{
  const viewport=document.getElementById(type+'-viewport');
  const spacer=document.getElementById(type+'-spacer');
  const list=document.getElementById(type+'-list');

  if(!nodes.length){{
    spacer.style.height='0px';
    list.innerHTML='<li class="no-conn">None</li>';
    list.style.top='0px';
    return;
  }}

  const sorted=nodes.map(id=>({{id,attrs:graph.hasNode(id)?graph.getNodeAttributes(id):null}}))
    .filter(x=>x.attrs)
    .sort((a,b)=>{{
      const order={{module:0,class:1,function:2,struct:3,external:4}};
      const ao=order[a.attrs.nodeType]??5,bo=order[b.attrs.nodeType]??5;
      return ao!==bo?ao-bo:a.attrs.label.localeCompare(b.attrs.label);
    }});

  const totalHeight=sorted.length*ITEM_HEIGHT;
  spacer.style.height=totalHeight+'px';

  viewport._sortedData=sorted;
  viewport._type=type;
  viewport._selectedIdx=-1;

  const render=()=>{{
    const scrollTop=viewport.scrollTop;
    const viewportHeight=viewport.clientHeight;
    const startIdx=Math.max(0,Math.floor(scrollTop/ITEM_HEIGHT)-VISIBLE_BUFFER);
    const endIdx=Math.min(sorted.length,Math.ceil((scrollTop+viewportHeight)/ITEM_HEIGHT)+VISIBLE_BUFFER);

    list.style.top=(startIdx*ITEM_HEIGHT)+'px';
    list.innerHTML=sorted.slice(startIdx,endIdx).map(({{id,attrs}},i)=>{{
      const realIdx=startIdx+i;
      const selectedClass=viewport._selectedIdx===realIdx?' selected':'';
      return '<li class="connection-item'+selectedClass+'" data-idx="'+realIdx+'" onclick="goToNode(\\''+id.replace(/'/g,"\\\\'")+'\\')">'
        +'<span class="conn-dot" style="background:'+attrs.color+'"></span>'
        +'<span class="conn-name" title="'+id+'">'+attrs.label+'</span>'
        +'<span class="conn-type">'+attrs.nodeType+'</span></li>';
    }}).join('');
  }};

  viewport.onscroll=render;
  render();
}}

function goToNode(nodeId){{
  if(!graph.hasNode(nodeId))return;
  const pos=graph.getNodeAttributes(nodeId);
  renderer.getCamera().animate({{x:pos.x,y:pos.y,ratio:0.8}},{{duration:400,easing:'quadraticOut'}});
  setTimeout(()=>showPanel(nodeId),450);
}}

function closePanel(){{
  document.getElementById('panel').classList.remove('visible');
  clearHL();
  selectedNode=null;
}}

function toggleSec(sec){{
  const viewport=document.getElementById(sec+'-viewport');
  viewport.classList.toggle('collapsed');
}}

function highlight(dir){{
  if(!selectedNode)return;
  const outN=connIndex.out[selectedNode]||[],inN=connIndex.in[selectedNode]||[];
  let hl=[selectedNode];
  if(dir==='out'||dir==='both')hl=hl.concat(outN);
  if(dir==='in'||dir==='both')hl=hl.concat(inN);
  const hlSet=new Set(hl);

  graph.forEachNode((n,a)=>{{
    const isHL=hlSet.has(n);
    graph.setNodeAttribute(n,'color',isHL?a.originalColor:'rgba(100,100,100,0.15)');
    graph.setNodeAttribute(n,'size',isHL?a.originalSize*1.5:a.originalSize*0.5);
  }});

  graph.forEachEdge((e,a,src,tgt)=>{{
    const isRel=(dir==='out'&&src===selectedNode)||(dir==='in'&&tgt===selectedNode)||(dir==='both'&&(src===selectedNode||tgt===selectedNode));
    graph.setEdgeAttribute(e,'color',isRel?'rgba(102,126,234,0.8)':'rgba(100,100,100,0.05)');
    graph.setEdgeAttribute(e,'size',isRel?1.5:0.2);
  }});

  renderer.refresh();
}}

function clearHL(){{
  graph.forEachNode((n,a)=>{{
    graph.setNodeAttribute(n,'color',a.originalColor);
    graph.setNodeAttribute(n,'size',a.originalSize);
  }});
  graph.forEachEdge((e,a)=>{{
    graph.setEdgeAttribute(e,'color',a.originalColor||'rgba(150,150,150,0.15)');
    graph.setEdgeAttribute(e,'size',0.3);
  }});
  renderer.refresh();
}}

function togglePathfinder(){{document.getElementById('pathfinder').classList.toggle('visible');}}

function findPath(){{
  if(!selectedNode)return;
  const to=document.getElementById('pf-to').value.trim();
  if(!to)return;

  let targetId=null;
  graph.forEachNode((n,a)=>{{
    if((n.toLowerCase().includes(to.toLowerCase())||a.label.toLowerCase().includes(to.toLowerCase()))&&!targetId)targetId=n;
  }});

  if(!targetId){{document.getElementById('path-result').innerHTML='<span style="color:var(--danger)">Node not found</span>';return;}}

  const path=findShortestPath(selectedNode,targetId);
  if(!path){{document.getElementById('path-result').innerHTML='<span style="color:var(--danger)">No path found</span>';return;}}

  const pathSet=new Set(path);
  graph.forEachNode((n,a)=>{{
    graph.setNodeAttribute(n,'color',pathSet.has(n)?a.originalColor:'rgba(100,100,100,0.1)');
    graph.setNodeAttribute(n,'size',pathSet.has(n)?a.originalSize*2:a.originalSize*0.3);
  }});

  graph.forEachEdge((e,a,src,tgt)=>{{
    const srcIdx=path.indexOf(src),tgtIdx=path.indexOf(tgt);
    const isPath=srcIdx!==-1&&tgtIdx!==-1&&Math.abs(srcIdx-tgtIdx)===1;
    graph.setEdgeAttribute(e,'color',isPath?'rgba(255,107,107,0.9)':'rgba(100,100,100,0.03)');
    graph.setEdgeAttribute(e,'size',isPath?3:0.1);
  }});

  renderer.refresh();

  document.getElementById('path-result').innerHTML=
    '<div style="margin-bottom:5px;color:var(--success)">Path ('+(path.length-1)+' hops):</div>'+
    path.map((n,i)=>{{
      const a=graph.getNodeAttributes(n);
      return '<span class="path-step" onclick="goToNode(\\''+n.replace(/'/g,"\\\\'")+'\\')">'+a.label+'</span>'+
        (i<path.length-1?'<span class="path-arrow">&#8594;</span>':'');
    }}).join('');
}}

function toggleTheme(){{
  isDarkTheme=!isDarkTheme;
  document.body.classList.toggle('light-theme',!isDarkTheme);
  if(renderer){{
    renderer.setSetting('labelColor',{{color:isDarkTheme?'#ffffff':'#222222'}});
    renderer.refresh();
  }}
}}

function toggleShortcuts(){{
  document.getElementById('shortcuts-modal').classList.toggle('visible');
}}

function updateSearchResults(){{
  const container=document.getElementById('search-results');
  if(!currentSearchResults.length){{
    container.style.display='none';
    return;
  }}
  container.innerHTML=currentSearchResults.map((n,i)=>
    '<div class="search-result'+(i===searchSelectedIdx?' selected':'')+'" data-idx="'+i+'" onclick="selectSearchResult('+i+')">'
    +'<span class="result-dot" style="background:'+n.color+'"></span>'
    +'<span class="result-label">'+n.label+'</span>'
    +'<span class="result-type">'+n.type+'</span></div>'
  ).join('');
  container.style.display='block';
}}

function selectSearchResult(idx){{
  if(idx>=0&&idx<currentSearchResults.length){{
    goToNode(currentSearchResults[idx].id);
    document.getElementById('search-results').style.display='none';
    document.getElementById('search').value='';
    currentSearchResults=[];
    searchSelectedIdx=-1;
  }}
}}

document.getElementById('search').addEventListener('input',function(e){{
  const q=e.target.value;
  currentSearchResults=searchNodes(q);
  searchSelectedIdx=currentSearchResults.length>0?0:-1;
  updateSearchResults();
}});

document.querySelectorAll('.view-btn').forEach(btn=>{{
  btn.addEventListener('click',()=>setFilter(btn.dataset.filter));
}});

document.getElementById('cluster-toggle').addEventListener('click',toggleClusterMode);

document.addEventListener('click',function(e){{
  if(!e.target.closest('.search-container')){{
    document.getElementById('search-results').style.display='none';
  }}
}});

document.addEventListener('keydown',function(e){{
  const searchInput=document.getElementById('search');
  const searchResults=document.getElementById('search-results');
  const isSearchFocused=document.activeElement===searchInput;
  const isSearchOpen=searchResults.style.display==='block';

  if((e.ctrlKey||e.metaKey)&&e.key==='f'){{
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
    return;
  }}

  if(e.key==='Escape'){{
    const modal=document.getElementById('shortcuts-modal');
    if(modal.classList.contains('visible')){{
      modal.classList.remove('visible');
      return;
    }}
    closePanel();
    searchResults.style.display='none';
    searchInput.blur();
    currentSearchResults=[];
    searchSelectedIdx=-1;
    return;
  }}

  if(e.key.toLowerCase()==='t'&&!isSearchFocused){{
    toggleTheme();
    return;
  }}

  if((e.key==='?'||e.key==='/')&&!isSearchFocused){{
    e.preventDefault();
    toggleShortcuts();
    return;
  }}

  if(isSearchOpen&&currentSearchResults.length>0){{
    if(e.key==='ArrowDown'){{
      e.preventDefault();
      searchSelectedIdx=Math.min(searchSelectedIdx+1,currentSearchResults.length-1);
      updateSearchResults();
    }}else if(e.key==='ArrowUp'){{
      e.preventDefault();
      searchSelectedIdx=Math.max(searchSelectedIdx-1,0);
      updateSearchResults();
    }}else if(e.key==='Enter'){{
      e.preventDefault();
      selectSearchResult(searchSelectedIdx);
    }}
  }}

  if(selectedNode&&!isSearchFocused){{
    const outN=connIndex.out[selectedNode]||[];
    const inN=connIndex.in[selectedNode]||[];
    const allConn=[...outN,...inN];

    if(e.key==='ArrowRight'&&outN.length>0){{
      e.preventDefault();
      goToNode(outN[0]);
    }}else if(e.key==='ArrowLeft'&&inN.length>0){{
      e.preventDefault();
      goToNode(inN[0]);
    }}else if(e.key==='ArrowUp'||e.key==='ArrowDown'){{
      const viewport=document.getElementById((e.key==='ArrowUp'?'in':'out')+'-viewport');
      if(viewport&&viewport._sortedData&&viewport._sortedData.length>0){{
        e.preventDefault();
        viewport._selectedIdx=Math.max(0,Math.min(
          (viewport._selectedIdx||0)+(e.key==='ArrowDown'?1:-1),
          viewport._sortedData.length-1
        ));
        viewport.scrollTop=viewport._selectedIdx*ITEM_HEIGHT-viewport.clientHeight/2;
        const render=viewport.onscroll;
        if(render)render();
      }}
    }}else if(e.key==='Enter'){{
      const outViewport=document.getElementById('out-viewport');
      const inViewport=document.getElementById('in-viewport');
      const activeViewport=document.activeElement.closest('.virtual-list-viewport')||
        (outViewport._selectedIdx>=0?outViewport:inViewport._selectedIdx>=0?inViewport:null);
      if(activeViewport&&activeViewport._sortedData&&activeViewport._selectedIdx>=0){{
        e.preventDefault();
        goToNode(activeViewport._sortedData[activeViewport._selectedIdx].id);
      }}
    }}
  }}
}});

init();
  </script>
</body>
</html>"""


def main() -> None:
    """Main function to parse arguments, scan, and visualize the architecture."""
    parser = argparse.ArgumentParser(description="Generate Intellicrack Knowledge Graph")
    parser.add_argument("--root", "-r", default="src", help="Root Python package directory")
    parser.add_argument(
        "--layout",
        "-l",
        choices=["sfdp", "hierarchical", "radial"],
        default="sfdp",
        help="Layout algorithm (default: sfdp)",
    )
    parser.add_argument(
        "--no-clusters",
        action="store_true",
        help="Disable cluster data generation",
    )

    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent
    knowledge_graph_dir = script_dir

    py_root = project_root / args.root

    if not py_root.exists():
        logger.error("Python root directory not found: %s", py_root)
        sys.exit(1)

    try:
        generator = KnowledgeGraphGenerator(py_root)
        generator.build_graph()

        generator.export_graphml(knowledge_graph_dir / "IntellicrackKnowledgeGraph.graphml")
        generator.generate_interactive_html(
            project_root / "IntellicrackKnowledgeGraph.html",
            layout_method=args.layout,
            enable_clustering=not args.no_clusters,
            dot_output_dir=knowledge_graph_dir,
        )

    except Exception:
        logger.exception("An unexpected error occurred during graph generation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
