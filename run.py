import networkx as nx
import logging
import yaml
import sys
import gc
import os

from collections import namedtuple
from apk_analyzer import APKAnalyzer
from cex.cex import CEXProject

log = logging.getLogger("ap.run")


NativeMethod = namedtuple("NativeMethod", ["libname", "libpath", "libhash", "jni_desc", "method_name", "offset", "path"])
Callgraph = namedtuple("Callgraph", ["libhash", "graph"])


def print_err(msg):
    sys.stderr.write(msg + "\n")

def usage():
    print_err("USAGE: %s <apk-path> <vuln.yaml>" % sys.argv[0])
    exit(1)

def setup_logging():
    logging.basicConfig(filename="/tmp/android-paths.log", encoding="ascii", level=logging.WARNING,
        format="%(asctime)s : [%(name)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")

    log_nan  = logging.getLogger("ap.NativeLibAnalyzer")
    log_apka = logging.getLogger("ap.APKAnalyzer")

    log.setLevel(logging.INFO)
    log_nan.setLevel(logging.INFO)
    log_apka.setLevel(logging.INFO)

def get_supergraph_id(libhash, off):
    return f"{libhash}_{off:x}"

def get_supergraph_naive(native_dep_g, *callgraphs):
    g = nx.DiGraph()

    libhashes = set()
    for cg in callgraphs:
        libhashes.add(cg.libhash)
        for n_id in cg.graph.nodes:
            data = cg.graph.nodes[n_id]["data"]
            g.add_node(
                get_supergraph_id(cg.libhash, data.addr),
                libhash=cg.libhash,
                fname=data.name,
                addr=data.addr)
        for src_id, dst_id in cg.graph.edges:
            data_src = cg.graph.nodes[src_id]["data"]
            data_dst = cg.graph.nodes[dst_id]["data"]
            g.add_edge(
                get_supergraph_id(cg.libhash, data_src.addr),
                get_supergraph_id(cg.libhash, data_dst.addr))

    for src_id, dst_id, n in native_dep_g.edges:
        edge_data = native_dep_g.edges[(src_id, dst_id, n)]
        supergraph_src = get_supergraph_id(src_id, edge_data["src_off"])
        supergraph_dst = get_supergraph_id(dst_id, edge_data["dst_off"])
        if supergraph_src not in g.nodes:
            # log.warning("supergraph_src not in nodes")
            continue
        if supergraph_dst not in g.nodes:
            # log.warning("supergraph_dst not in nodes")
            continue

        g.add_edge(supergraph_src, supergraph_dst)
    return g

def get_supergraph(native_dep_g, jni_methods, *callgraphs):
    # Get only the connected components with the JNI Methods

    g = nx.DiGraph()

    callgraph_dict = dict()
    for cg in callgraphs:
        callgraph_dict[cg.libhash] = cg.graph

    jni_method_ids = list()
    for jni_method in jni_methods:
        supergraph_id = get_supergraph_id(jni_method.libhash, jni_method.offset)
        jni_method_ids.append(supergraph_id)
        g.add_node(
            supergraph_id,
            libhash=jni_method.libhash,
            fname=jni_method.method_name,
            addr=jni_method.offset)

    visited = set()
    stack   = jni_method_ids
    while stack:
        el = stack.pop()
        if el in visited:
            continue
        visited.add(el)

        libhash, off = el.split("_")
        off = int(off, 16)

        # collect and add direct successor in callgraph
        cg = callgraph_dict[libhash]
        succ_in_cg = cg.successors(off)
        for succ in succ_in_cg:
            succ_data = cg.nodes[succ]["data"]
            succ_id = get_supergraph_id(libhash, succ)
            if succ_id not in g.nodes:
                g.add_node(
                    succ_id,
                    libhash=libhash,
                    fname=succ_data.name,
                    addr=succ)
            g.add_edge(el, succ_id)

            stack.append(succ_id)

        # collect direct successors in dependency graph
        succ_in_dep_g = list()
        for _, dst_lib, data in native_dep_g.out_edges(libhash, data=True):
            src_off = data["src_off"]
            dst_off = data["dst_off"]
            if src_off == off:
                succ_in_dep_g.append(
                    get_supergraph_id(dst_lib, dst_off))

        # add direct successors in dependency graph
        for succ_id in succ_in_dep_g:
            succ_lib, succ_off = succ_id.split("_")
            succ_off = int(succ_off, 16)
            if succ_lib not in callgraph_dict:
                # I know from the dependency graph that
                # this edge CANNOT reach a sink library
                continue
            cg = callgraph_dict[succ_lib]
            succ_data = cg.nodes[succ_off]["data"]
            if succ_id not in g.nodes:
                g.add_node(
                    succ_id,
                    libhash=succ_lib,
                    fname=succ_data.name,
                    addr=succ_off)
            g.add_edge(el, succ_id)

            stack.append(succ_id)
    return g

def get_method_from_supergraph_id(supergraph_id, methods):
    lib_hash, off = supergraph_id.split("_")
    off = int(off, 16)
    for native_method in native_methods:
        if lib_hash == native_method.libhash and off == native_method.offset:
            return native_method
    return None

# TODO: merge graphs of different libraries

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    apk_path  = sys.argv[1]
    vuln_yaml = sys.argv[2]

    with open(vuln_yaml, "r") as fin:
        vulns = yaml.load(fin, Loader=yaml.FullLoader)
    vuln_libs = dict()
    for lib in vulns["libs"]:
        vuln_libs[lib["hash"]] = {
            "name":    lib["name"],
            "offsets": lib["offsets"]
        }

    setup_logging()
    log.info(f"running android-paths on {apk_path}")
    apk_analyzer = APKAnalyzer(apk_path)
    paths_result = apk_analyzer.get_paths_to_native()

    # Use accurate callgraph
    CEXProject.pm.get_plugin_by_name("Ghidra").use_accurate = True

    apk_analyzer.delete_callgraph()  # free some RAM
    gc.collect()

    log.info("android paths built")
    native_signatures = list(paths_result["paths"].keys())
    native_names      = list(map(
        lambda x: x.split(";->")[1].split("(")[0],
        native_signatures))
    class_names       = list(map(
        lambda x: x.split(" L")[1].split(";->")[0].replace("/", "."),
        native_signatures))
    args_strings      = list(map(
        lambda x: "(" + x.split("(")[1].split(" [access")[0],
        native_signatures))
    log.info(f"found {len(native_names)} native functions (java)")

    log.info("building library dependency graph")
    lib_dep_g = apk_analyzer.build_lib_dependency_graph()
    reversed_lib_dep_g = lib_dep_g.reverse()

    log.info("building subgraph containing vulnerable libraries")
    interesting_libs = set()
    for l_hash in vuln_libs:
        if not reversed_lib_dep_g.has_node(l_hash):
            continue
        interesting_libs |= set(nx.dfs_preorder_nodes(reversed_lib_dep_g, l_hash))
    # interesting_libs = { h for h in lib_dep_g.nodes }
    log.info(f"found {len(interesting_libs)} interesting libraries")

    log.info("finding mapping between native methods and implementation")
    native_methods = list()
    for method_name, class_name, args_str, sig in zip(native_names, class_names, args_strings, native_signatures):
        jni_descs = apk_analyzer.find_native_implementations(method_name, class_name, args_str, lib_whitelist=interesting_libs)
        for jni_desc in jni_descs:
            native_methods.append(
                NativeMethod(
                    libname=jni_desc.analyzer.libname,
                    libpath=jni_desc.analyzer.libpath,
                    libhash=jni_desc.analyzer.libhash,
                    jni_desc=jni_desc,
                    method_name=method_name,
                    offset=jni_desc.offset,
                    path=paths_result["paths"][sig]))
    log.info(f"found {len(native_methods)} methods")

    log.info(f"building callgraphs for {len(interesting_libs)} libs")
    callgraphs = list()
    for lib_hash in interesting_libs:
        proj = CEXProject(apk_analyzer.get_libpath_from_hash(lib_hash), plugins=["Ghidra"])
        cg = proj.get_callgraph()
        callgraphs.append(Callgraph(libhash=lib_hash, graph=cg))

    log.info("building supergraph")
    libs_supergraph = get_supergraph(lib_dep_g, native_methods, *callgraphs).reverse()
    log.info(f"supergraph ({libs_supergraph.number_of_nodes()} nodes, {libs_supergraph.number_of_edges()} edges) built")

    callgraphs = None
    CEXProject.clear_plugins_cache()  # free some RAM
    gc.collect()

    native_methods_id_in_supergraph = list(
        map(lambda x: get_supergraph_id(x.libhash, x.offset), native_methods))

    # Check path to vulns
    for vuln_lib_hash in vuln_libs:
        if vuln_lib_hash not in interesting_libs:
            continue

        vuln_offsets = vuln_libs[vuln_lib_hash]["offsets"]
        vuln_libname = vuln_libs[vuln_lib_hash]["name"]

        for vuln_offset in vuln_offsets:
            vuln_offset = CEXProject.rebase_addr(vuln_offset)
            src_id = get_supergraph_id(vuln_lib_hash, vuln_offset)

            log.info(f"checking path to {vuln_offset:#x} @ {vuln_libname}")
            if not libs_supergraph.has_node(src_id):
                log.info("path not found (node outside supergraph)")
                continue

            if src_id in native_methods_id_in_supergraph:
                path = [src_id]
            else:
                path = next(nx.all_simple_paths(libs_supergraph, src_id, native_methods_id_in_supergraph), None)
            if path is not None:
                print(f"[!] Found potentially vulnerable path to {vuln_offset:#x} @ {vuln_libname}")
                log.info("path found")
                path = path[::-1]
                native_method = get_method_from_supergraph_id(path[0], native_methods)
                assert native_method is not None
                for m in native_method.path:
                    print(f"  - {m}")
                for n in path:
                    data    = libs_supergraph.nodes[n]
                    libname = apk_analyzer.get_libname_from_hash(data["libhash"])
                    fname   = data["fname"]
                    offset  = data["addr"]
                    print(f"  - {fname} @ {libname} [{offset:#x}]")
            else:
                log.info("path not found")
