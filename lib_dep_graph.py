import sys

from apk_analyzer import APKAnalyzer
from cex.cex import CEX

def print_err(msg):
    sys.stderr.write(msg + "\n")

def usage():
    print_err(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

def print_dot(g):
    header  = "digraph {\n"
    header += "\tnode  [shape=box];\n"
    header += "\tgraph [fontname = \"monospace\"];\n"
    header += "\tnode  [fontname = \"monospace\"];\n"
    header += "\tedge  [fontname = \"monospace\"];\n"
    print(header)

    for n_id in g.nodes:
        node = g.nodes[n_id]
        label = node["analyzer"].arch + " " + node["analyzer"].libname
        row = f'\tnode_{n_id} [label="{label}"];'
        print(row)

    for src_id, dst_id, n in g.edges:
        edge = g.edges[(src_id, dst_id, n)]
        label = edge["fun"]
        row = f'\tnode_{src_id} -> node_{dst_id} [label="{label}"];'
        print(row)

    print("}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    cex          = CEX()
    apk_analyzer = APKAnalyzer(cex, apk_path)

    g = apk_analyzer.build_lib_dependency_graph()
    print_dot(g)
