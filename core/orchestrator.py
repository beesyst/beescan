import asyncio
import json
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")


def build_dependency_graph(plugin_configs):
    enabled_names = {p["name"] for p in plugin_configs if p.get("enabled")}
    graph = {}
    for plugin in plugin_configs:
        name = plugin["name"]
        strict = plugin.get("strict_dependencies", True)
        if strict:
            depends = [
                dep for dep in plugin.get("depends_on", []) if dep in enabled_names
            ]
        else:
            depends = []
        graph[name] = set(depends)
    return graph


def topological_sort(graph):
    from collections import defaultdict, deque

    in_degree = defaultdict(int)
    for node, deps in graph.items():
        for dep in deps:
            in_degree[node] += 1

    queue = deque([node for node in graph if in_degree[node] == 0])
    result = []

    while queue:
        node = queue.popleft()
        result.append(node)
        for neighbor in graph:
            if node in graph[neighbor]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

    if len(result) != len(graph):
        raise RuntimeError("Циклическая зависимость в плагинах!")
    return result


async def orchestrate(config):
    from core.collector import collect
    from core.plugin_runner import run_plugin

    enabled_plugins = [p for p in config.get("plugins", []) if p.get("enabled")]
    graph = build_dependency_graph(enabled_plugins)
    sorted_plugins = topological_sort(graph)
    print(f"\n[SORTED PLUGINS]: {sorted_plugins}\n")

    plugins_by_name = {p["name"]: p for p in enabled_plugins}

    results = {}
    plugin_durations = {}

    executed = set()
    while len(executed) < len(sorted_plugins):
        to_run = []
        for name in sorted_plugins:
            if name in executed:
                continue
            deps = graph[name]
            if deps.issubset(executed):
                to_run.append(name)

        tasks = []
        for name in to_run:
            plugin_conf = plugins_by_name[name]
            merged_config = {
                **plugin_conf,
                "name": name,
                "enabled": True,
            }
            tasks.append(run_plugin(merged_config))
        batch_results = await asyncio.gather(*tasks)

        for i, name in enumerate(to_run):
            plugin_name, (paths, duration) = batch_results[i]
            results[plugin_name] = paths
            plugin_durations[plugin_name] = duration
            executed.add(name)

            if paths:
                collect(temp_files=paths)

    return results, plugin_durations


if __name__ == "__main__":
    import sys

    config_path = sys.argv[1] if len(sys.argv) > 1 else CONFIG_PATH
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    res, durs = asyncio.run(orchestrate(config))
    print(json.dumps({"results": res, "durations": durs}, indent=2, ensure_ascii=False))
