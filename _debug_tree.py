import sys
sys.path.insert(0, ".")
from parser import OutputParser
from process_analyzer import ProcessAnalyzer

p = OutputParser()
p.parse_pslist()
recs = p.parsed_data.get("pslist", [])
print(f"pslist records: {len(recs)}")
for r in recs:
    print(f"  PID={r.get('PID','?'):6s}  PPID={r.get('PPID','?'):6s}  Process={r.get('Process','?')}")

print()
pa = ProcessAnalyzer()
pa._build_tree(p.parsed_data)
print(f"Tree nodes: {len(pa.process_tree)}")
for pid, node in pa.process_tree.items():
    kids = [c.name for c in node.children]
    print(f"  PID={node.pid:6s}  PPID={node.ppid:6s}  {node.name:20s}  children={kids}")
