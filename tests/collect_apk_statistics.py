import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject
from apk_analyzer.utils.timeout_decorator import TimeoutError

def usage():
    print(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    n_java_instructions         = 0
    n_native_instructions       = 0
    n_java_native_methods       = 0
    n_armv7_libs                = 0
    n_libs_that_links_other_lib = 0
    n_lib_with_cpp_context      = 0

    apka = APKAnalyzer(sys.argv[1])

    # Number of libraries
    armv7_libs   = apka.get_armv7_libs()
    n_armv7_libs = len(armv7_libs)

    # Number of libs that link another lib
    lib_depgraph = apka.build_lib_dependency_graph()
    for armv7_lib in armv7_libs:
        if len(lib_depgraph.out_edges(armv7_lib.libhash)) > 0:
            n_libs_that_links_other_lib += 1

    # Number of JAVA instructions
    for vm in apka.dvm:
        for method in vm.get_methods():
            if method.get_code() is None:
                continue
            n_java_instructions += len(list(method.get_code().code.get_instructions()))

    # Number of native instructions
    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
    for armv7_lib in armv7_libs:
        ghidra._load_cfg_raw(armv7_lib.libpath)
        functions = ghidra.data[armv7_lib.libpath].cfg_raw

        for fun in functions:
            for block in fun["blocks"]:
                n_native_instructions += len(block["instructions"])

    # Number of java native methods
    n_java_native_methods = len(apka.find_native_methods())

    # Number of lib with at least one method with "context"
    lib_with_native_mappings = set()
    for native in apka.find_native_methods_implementations(lib_whitelist=list(map(lambda l: l.libhash, armv7_libs))):
        if native.libhash in lib_with_native_mappings:
            continue

        try:
            if len(apka.jlong_as_cpp_obj(native)) > 0:
                lib_with_native_mappings.add(native.libhash)
                print("[INFO] found jlong_as_cpp_obj in", native)
        except TimeoutError:
            print("[WARNING] jlong_as_cpp_obj timeout on", native)
        except Exception as e:
            print("[WARNING] jlong_as_cpp_obj unknown error [", str(e), "]")
    n_lib_with_cpp_context = len(lib_with_native_mappings)

    print(f"[APK_STATISTICS_RESULT] {n_java_instructions}, {n_native_instructions}, {n_java_native_methods}, {n_armv7_libs}, {n_libs_that_links_other_lib}, {n_lib_with_cpp_context}")