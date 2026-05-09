"""
process_analyzer.py -- Parent-child process relationship analysis (v1.2).

Builds a process tree from pslist/pstree/psscan/cmdline data and
detects suspicious parent-child execution chains.

Produces:
  - Process tree with ancestry
  - Suspicious relationship findings
  - Execution chain visualizations for reports
"""

import re
from dataclasses import dataclass, field
from collections import defaultdict

from rich.table import Table
from rich.tree import Tree as RichTree

from utils import console, load_rules, setup_logging, separator
from whitelist import WHITELISTED_PROCESSES, normalize_process_name

logger = setup_logging()


@dataclass
class ProcessNode:
    """Represents a single process in the process tree."""
    pid: str = ""
    ppid: str = ""
    name: str = ""
    cmdline: str = ""
    children: list = field(default_factory=list)   # list[ProcessNode]
    depth: int = 0
    is_suspicious: bool = False
    suspicion_reasons: list = field(default_factory=list)


@dataclass
class ProcessRelationship:
    """A detected suspicious parent-child relationship."""
    rule_id: str
    parent_name: str
    parent_pid: str
    child_name: str
    child_pid: str
    description: str
    severity: str
    score: int
    mitre_id: str = ""
    mitre_technique: str = ""
    chain: list = field(default_factory=list)  # Full ancestry chain


class ProcessAnalyzer:
    """Build process tree and detect suspicious relationships."""

    def __init__(self) -> None:
        self.rules = load_rules()
        self.relationship_rules = self.rules.get("process_relationship_indicators", {})
        self.process_tree: dict[str, ProcessNode] = {}  # pid -> ProcessNode
        self.relationships: list[ProcessRelationship] = []
        self.attack_chains: list[dict] = []   # Detected end-to-end chains

    # ── Tree building ────────────────────────────────────────────────────

    def _build_tree(self, parsed_data: dict) -> None:
        """Build process tree from available data sources.

        Priority: pslist > pstree > psscan (for PPID accuracy).
        Enriches with cmdline data for argument context.
        """
        # Collect PPID data from best available source
        ppid_records = []
        if parsed_data.get("pslist"):
            ppid_records = parsed_data["pslist"]
            logger.info("Building tree from pslist (%d entries)", len(ppid_records))
        elif parsed_data.get("pstree"):
            ppid_records = parsed_data["pstree"]
            logger.info("Building tree from pstree (%d entries)", len(ppid_records))
        elif parsed_data.get("psscan"):
            ppid_records = parsed_data["psscan"]
            logger.info("Building tree from psscan (%d entries)", len(ppid_records))

        if not ppid_records:
            logger.warning("No PPID data available -- process tree will be empty")
            return

        # Build the node map
        for rec in ppid_records:
            pid = str(rec.get("PID", "")).strip()
            ppid = str(rec.get("PPID", "")).strip()
            name = rec.get("Process", rec.get("ImageFileName", rec.get("Name", "Unknown")))
            if not pid:
                continue

            node = ProcessNode(
                pid=pid, ppid=ppid, name=name,
                depth=rec.get("_tree_depth", 0),
            )
            self.process_tree[pid] = node

        # Enrich with cmdline data
        for rec in parsed_data.get("cmdline", []):
            pid = str(rec.get("PID", "")).strip()
            if pid in self.process_tree:
                self.process_tree[pid].cmdline = rec.get("Args", "")

        # Link parent-child relationships
        for pid, node in self.process_tree.items():
            if node.ppid and node.ppid in self.process_tree:
                parent = self.process_tree[node.ppid]
                parent.children.append(node)

        logger.info("Process tree built: %d nodes", len(self.process_tree))

    # ── Relationship detection ───────────────────────────────────────────

    def _get_ancestry(self, pid: str, max_depth: int = 5) -> list[str]:
        """Walk up the tree to get the process ancestry chain."""
        chain = []
        current = pid
        for _ in range(max_depth):
            if current not in self.process_tree:
                break
            node = self.process_tree[current]
            chain.append(f"{node.name} (PID: {node.pid})")
            current = node.ppid
            if not current or current == "0":
                break
        return list(reversed(chain))

    def _is_system_process(self, name: str) -> bool:
        """Check if a process is a standard Windows system process."""
        norm = normalize_process_name(name)
        return norm in WHITELISTED_PROCESSES

    def _detect_office_child_spawn(self) -> None:
        """Detect Office apps spawning shells/scripts."""
        rule = self.relationship_rules.get("office_child_spawn")
        if not rule:
            return

        parents = {p.lower() for p in rule["parents"]}
        sus_children = {c.lower() for c in rule["suspicious_children"]}

        for pid, node in self.process_tree.items():
            if node.name.lower() not in parents:
                continue
            for child in node.children:
                if child.name.lower() in sus_children:
                    self.relationships.append(ProcessRelationship(
                        rule_id="office_child_spawn",
                        parent_name=node.name, parent_pid=node.pid,
                        child_name=child.name, child_pid=child.pid,
                        description=rule["description"],
                        severity=rule["severity"], score=rule["score"],
                        mitre_id=rule["mitre_id"],
                        mitre_technique=rule["mitre_technique"],
                        chain=self._get_ancestry(child.pid),
                    ))
                    child.is_suspicious = True
                    child.suspicion_reasons.append("Spawned by Office application")

    def _detect_script_child_spawn(self) -> None:
        """Detect scripting engines spawning non-system executables."""
        rule = self.relationship_rules.get("script_child_spawn")
        if not rule:
            return

        parents = {p.lower() for p in rule["parents"]}

        for pid, node in self.process_tree.items():
            if node.name.lower() not in parents:
                continue
            for child in node.children:
                if not self._is_system_process(child.name):
                    self.relationships.append(ProcessRelationship(
                        rule_id="script_child_spawn",
                        parent_name=node.name, parent_pid=node.pid,
                        child_name=child.name, child_pid=child.pid,
                        description=rule["description"],
                        severity=rule["severity"], score=rule["score"],
                        mitre_id=rule["mitre_id"],
                        mitre_technique=rule["mitre_technique"],
                        chain=self._get_ancestry(child.pid),
                    ))
                    child.is_suspicious = True
                    child.suspicion_reasons.append("Spawned by scripting engine")

    def _detect_explorer_temp_child(self) -> None:
        """Detect Explorer spawning executables from Temp/AppData."""
        rule = self.relationship_rules.get("explorer_temp_child")
        if not rule:
            return

        temp_re = re.compile(
            r"(?:\\|/)(?:Temp|AppData|tmp)(?:\\|/)", re.IGNORECASE
        )

        for pid, node in self.process_tree.items():
            if node.name.lower() != "explorer.exe":
                continue
            for child in node.children:
                if temp_re.search(child.cmdline):
                    self.relationships.append(ProcessRelationship(
                        rule_id="explorer_temp_child",
                        parent_name=node.name, parent_pid=node.pid,
                        child_name=child.name, child_pid=child.pid,
                        description=rule["description"],
                        severity=rule["severity"], score=rule["score"],
                        mitre_id=rule["mitre_id"],
                        mitre_technique=rule["mitre_technique"],
                        chain=self._get_ancestry(child.pid),
                    ))
                    child.is_suspicious = True
                    child.suspicion_reasons.append("Temp-located child of Explorer")

    def _detect_svchost_shell_spawn(self) -> None:
        """Detect svchost.exe spawning shells."""
        rule = self.relationship_rules.get("svchost_shell_spawn")
        if not rule:
            return

        sus_children = {c.lower() for c in rule["suspicious_children"]}

        for pid, node in self.process_tree.items():
            if node.name.lower() != "svchost.exe":
                continue
            for child in node.children:
                if child.name.lower() in sus_children:
                    self.relationships.append(ProcessRelationship(
                        rule_id="svchost_shell_spawn",
                        parent_name=node.name, parent_pid=node.pid,
                        child_name=child.name, child_pid=child.pid,
                        description=rule["description"],
                        severity=rule["severity"], score=rule["score"],
                        mitre_id=rule["mitre_id"],
                        mitre_technique=rule["mitre_technique"],
                        chain=self._get_ancestry(child.pid),
                    ))
                    child.is_suspicious = True
                    child.suspicion_reasons.append("Shell spawned by svchost")

    def _detect_browser_shell_spawn(self) -> None:
        """Detect browsers spawning command shells."""
        rule = self.relationship_rules.get("browser_shell_spawn")
        if not rule:
            return

        parents = {p.lower() for p in rule["parents"]}
        sus_children = {c.lower() for c in rule["suspicious_children"]}

        for pid, node in self.process_tree.items():
            if node.name.lower() not in parents:
                continue
            for child in node.children:
                if child.name.lower() in sus_children:
                    self.relationships.append(ProcessRelationship(
                        rule_id="browser_shell_spawn",
                        parent_name=node.name, parent_pid=node.pid,
                        child_name=child.name, child_pid=child.pid,
                        description=rule["description"],
                        severity=rule["severity"], score=rule["score"],
                        mitre_id=rule["mitre_id"],
                        mitre_technique=rule["mitre_technique"],
                        chain=self._get_ancestry(child.pid),
                    ))
                    child.is_suspicious = True
                    child.suspicion_reasons.append("Shell spawned by browser")

    def _detect_spawning_storm(self) -> None:
        """Detect processes spawning abnormally high number of children."""
        rule = self.relationship_rules.get("process_spawning_storm")
        if not rule:
            return

        threshold = rule.get("threshold", 5)
        # Exclude processes that normally have many children
        normal_parents = {"svchost.exe", "services.exe", "system", "csrss.exe", "smss.exe"}

        for pid, node in self.process_tree.items():
            if node.name.lower() in normal_parents:
                continue
            unique_children = {c.name.lower() for c in node.children}
            if len(unique_children) >= threshold:
                self.relationships.append(ProcessRelationship(
                    rule_id="process_spawning_storm",
                    parent_name=node.name, parent_pid=node.pid,
                    child_name=f"{len(node.children)} children",
                    child_pid="--",
                    description=f"{rule['description']} ({len(node.children)} children)",
                    severity=rule["severity"], score=rule["score"],
                    mitre_id=rule["mitre_id"],
                    mitre_technique=rule["mitre_technique"],
                    chain=self._get_ancestry(node.pid),
                ))
                node.is_suspicious = True
                node.suspicion_reasons.append(f"Spawning storm: {len(node.children)} children")

    def _detect_attack_chains(self) -> None:
        """Detect multi-hop execution chains that form attack patterns.

        Example chains:
          Office -> wscript -> VBS -> Temp executable
          Explorer -> random.exe -> cmd.exe -> powershell.exe
        """
        # Look for chains of 3+ suspicious nodes
        for pid, node in self.process_tree.items():
            chain = self._trace_suspicious_chain(node, depth=0, path=[])
            if len(chain) >= 3:
                self.attack_chains.append({
                    "chain": chain,
                    "depth": len(chain),
                    "root": chain[0],
                    "leaf": chain[-1],
                })

    def _trace_suspicious_chain(
        self, node: ProcessNode, depth: int, path: list
    ) -> list[str]:
        """Recursively trace suspicious execution chains."""
        if depth > 6:
            return path

        entry = f"{node.name} (PID: {node.pid})"
        current_path = path + [entry]

        # Check if this node has suspicious children
        longest = current_path
        for child in node.children:
            # Only follow non-system or suspicious children
            if child.is_suspicious or not self._is_system_process(child.name):
                result = self._trace_suspicious_chain(child, depth + 1, current_path)
                if len(result) > len(longest):
                    longest = result

        return longest

    # ── Display ──────────────────────────────────────────────────────────

    def _display_summary(self) -> None:
        """Display process relationship summary in terminal."""
        if self.relationships:
            table = Table(
                title=f"[!] {len(self.relationships)} Suspicious Process Relationship(s)",
                show_header=True,
                header_style="bold bright_red",
                border_style="red",
                title_style="bold red",
            )
            table.add_column("#", style="dim", width=4)
            table.add_column("Severity", justify="center", min_width=8)
            table.add_column("Parent", min_width=15)
            table.add_column("->", width=3)
            table.add_column("Child", min_width=15)
            table.add_column("Rule", min_width=20)
            table.add_column("MITRE", min_width=10)

            for idx, rel in enumerate(self.relationships, 1):
                sev_colors = {"HIGH": "bold bright_red", "MEDIUM": "bold yellow", "LOW": "bold blue"}
                sev_color = sev_colors.get(rel.severity, "white")
                table.add_row(
                    str(idx),
                    f"[{sev_color}]{rel.severity}[/{sev_color}]",
                    f"{rel.parent_name} ({rel.parent_pid})",
                    "->",
                    f"{rel.child_name} ({rel.child_pid})",
                    rel.rule_id,
                    rel.mitre_id or "--",
                )

            console.print(table)
            console.print()

        if self.attack_chains:
            console.print(f"[bold yellow][!] {len(self.attack_chains)} attack chain(s) detected:[/bold yellow]")
            for chain in self.attack_chains:
                chain_str = " -> ".join(chain["chain"])
                console.print(f"  [dim]{chain_str}[/dim]")
            console.print()

        # Display process tree
        if self.process_tree:
            self._display_tree()

    def _display_tree(self) -> None:
        """Display a Rich tree of the process hierarchy."""
        # Find root processes (ppid not in tree or ppid=0)
        roots = [
            node for node in self.process_tree.values()
            if not node.ppid or node.ppid == "0" or node.ppid not in self.process_tree
        ]

        if not roots:
            return

        tree = RichTree("[bold cyan]Process Tree[/bold cyan]")

        def _add_children(rich_node, proc_node, max_depth=4, depth=0):
            if depth >= max_depth:
                if proc_node.children:
                    rich_node.add(f"[dim]... {len(proc_node.children)} more[/dim]")
                return
            for child in sorted(proc_node.children, key=lambda c: c.name):
                if child.is_suspicious:
                    label = f"[bold red]{child.name}[/bold red] (PID: {child.pid}) [red][!SUSPICIOUS][/red]"
                else:
                    label = f"[dim]{child.name}[/dim] (PID: {child.pid})"
                child_branch = rich_node.add(label)
                _add_children(child_branch, child, max_depth, depth + 1)

        for root in sorted(roots, key=lambda r: r.name):
            if root.is_suspicious:
                label = f"[bold red]{root.name}[/bold red] (PID: {root.pid}) [red][!SUSPICIOUS][/red]"
            else:
                label = f"[bold white]{root.name}[/bold white] (PID: {root.pid})"
            branch = tree.add(label)
            _add_children(branch, root)

        console.print(tree)
        console.print()

    # ── Public API ───────────────────────────────────────────────────────

    def analyze(self, parsed_data: dict) -> list[ProcessRelationship]:
        """Build process tree and detect suspicious relationships.

        Parameters
        ----------
        parsed_data : dict
            Parsed data from OutputParser.parse_all().

        Returns
        -------
        list[ProcessRelationship]
        """
        separator("Process Relationship Analysis")
        console.print("[bold cyan][*] Building process tree and analyzing relationships...[/bold cyan]\n")

        self._build_tree(parsed_data)

        if not self.process_tree:
            console.print("[yellow][!] No process tree data available (pslist/pstree/psscan missing)[/yellow]\n")
            return []

        console.print(f"[dim]  Process tree: {len(self.process_tree)} nodes[/dim]")

        # Detect all suspicious relationships
        self._detect_office_child_spawn()
        self._detect_script_child_spawn()
        self._detect_explorer_temp_child()
        self._detect_svchost_shell_spawn()
        self._detect_browser_shell_spawn()
        self._detect_spawning_storm()
        self._detect_attack_chains()

        self._display_summary()

        logger.info(
            "Process analysis: %d relationships, %d attack chains",
            len(self.relationships), len(self.attack_chains),
        )
        return self.relationships

    def get_tree(self) -> dict[str, ProcessNode]:
        """Return the process tree for reporting."""
        return self.process_tree

    def get_attack_chains(self) -> list[dict]:
        """Return detected attack chains for reporting."""
        return self.attack_chains

    def get_tree_text(self, max_depth: int = 4) -> str:
        """Generate a plain-text process tree for reports."""
        roots = [
            node for node in self.process_tree.values()
            if not node.ppid or node.ppid == "0" or node.ppid not in self.process_tree
        ]
        if not roots:
            return "  (no process tree data available)"

        lines = []

        def _render(node, prefix="", is_last=True, depth=0):
            if depth > max_depth:
                return
            connector = "`-- " if is_last else "|-- "
            sus = "  [!SUSPICIOUS]" if node.is_suspicious else ""
            if depth == 0:
                lines.append(f"  {node.name} (PID: {node.pid}){sus}")
            else:
                lines.append(f"  {prefix}{connector}{node.name} (PID: {node.pid}){sus}")

            children = sorted(node.children, key=lambda c: c.name)
            for i, child in enumerate(children):
                is_last_child = (i == len(children) - 1)
                child_prefix = prefix + ("    " if is_last else "|   ")
                _render(child, child_prefix, is_last_child, depth + 1)

        for root in sorted(roots, key=lambda r: r.name):
            _render(root, depth=0)

        return "\n".join(lines)
