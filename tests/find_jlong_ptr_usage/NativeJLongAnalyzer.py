import logging
import claripy
import angr
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer.utils.jni_stubs.java_type import get_type, get_type_size
from apk_analyzer.utils.angr_find_dynamic_jni import AnalysisCenter
from apk_analyzer.utils.jni_stubs.jni_type.jni_native_interface import JNINativeInterface, JObject

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from timeout_decorator import timeout, TimeoutError

# angr, shut the fuck up
angr_logger = logging.getLogger('angr')
angr_logger.propagate = False
cle_logger  = logging.getLogger('cle')
cle_logger.propagate = False
nativedroid_logger = logging.getLogger('nativedroid')
nativedroid_logger.propagate = False


class NativeJLongAnalyzer(object):
    DEBUG     = False
    MAXITER   = 100
    MAXSTATES = 200

    def __init__(self, libpath):
        self.libpath = libpath
        self.project = angr.Project(libpath, auto_load_libs=False)
        self.state   = self.project.factory.blank_state()  # general purpose state... Can be useful to read memory
        self.jni_ptr = claripy.BVV(
            JNINativeInterface(
                self.project,
                AnalysisCenter(None, "", "")).ptr,
                self.project.arch.bits)

        self.obj     = JObject(self.project)
        self.cpp_obj = JObject(self.project)
        self.vtable  = JObject(self.project)
        self.struct  = JObject(self.project)

    def mk_type(self, arg_id, arg_type):
        typ_size = get_type_size(self.project, arg_type)
        if arg_type in {'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'}:
            return claripy.BVS("%s_%d" % (arg_type, arg_id), typ_size)
        return claripy.BVV(get_type(self.project, arg_type).ptr, typ_size)

    def mk_cpp_obj(self, state):
        if NativeJLongAnalyzer.DEBUG:
            print("obj ptr:",    claripy.BVV(self.cpp_obj.ptr, self.project.arch.bits))
            print("vtable ptr:", claripy.BVV(self.vtable.ptr, self.project.arch.bits))

        state.memory.store(
            self.cpp_obj.ptr,
            claripy.BVV(self.vtable.ptr, self.project.arch.bits),
            endness=self.project.arch.memory_endness)
        for i in range(0, 300, self.project.arch.bits // 8):
            state.memory.store(
                self.vtable.ptr + i,
                claripy.BVS("vtable_entry_%d" % i, self.project.arch.bits),
                endness=self.project.arch.memory_endness)

        if NativeJLongAnalyzer.DEBUG:
            print("vtable ptr (load):", state.memory.load(self.cpp_obj.ptr, self.project.arch.bits // 8, endness=self.project.arch.memory_endness))
            print("first vtable entry (load):", state.memory.load(
                state.memory.load(self.cpp_obj.ptr, self.project.arch.bits // 8, endness=self.project.arch.memory_endness),
                self.project.arch.bits // 8, endness=self.project.arch.memory_endness))

        return claripy.BVV(self.cpp_obj.ptr, self.project.arch.bits)

    def mk_funptr_struct(self, state):
        for i in range(0, 300, self.project.arch.bits // 8):
            state.memory.store(
                self.struct.ptr + i,
                claripy.BVS("fun_ptr_%d" % i, self.project.arch.bits),
                endness=self.project.arch.memory_endness)
        return claripy.BVV(self.struct.ptr, self.project.arch.bits)

    def prepare_state_cpp(self, addr, args):
        state = self.project.factory.blank_state(addr=addr)
        state.regs.r0 = self.jni_ptr
        state.regs.r1 = claripy.BVV(
            self.obj.ptr, self.project.arch.bits)

        parsed_args = dict()
        for i, a in enumerate(args.split(",")):
            a = a.strip().replace(" ", "")
            parsed_args[i+2] = a

        for arg_id in parsed_args:
            arg_type = parsed_args[arg_id]

            if arg_type == "long":
                data = self.mk_cpp_obj(state)
            else:
                data = self.mk_type(arg_id, arg_type)

            if data.size() < self.project.arch.bits:
                data = data.zero_extend(self.project.arch.bits - data.size())

            if arg_id < 3:
                state.regs.__setattr__('r%d' % arg_id, data)
            else:
                state.stack_push(data)
        state.solver._solver.timeout = 2000 # 2 seconds as timeout
        return state

    def prepare_state_jlong_as_ptr(self, addr, args):
        state = self.project.factory.blank_state(addr=addr)
        state.regs.r0 = self.jni_ptr
        state.regs.r1 = claripy.BVV(
            self.obj.ptr, self.project.arch.bits)

        parsed_args = dict()
        for i, a in enumerate(args.split(",")):
            a = a.strip().replace(" ", "")
            parsed_args[i+2] = a

        for arg_id in parsed_args:
            arg_type = parsed_args[arg_id]
            if arg_type == "long":
                data = claripy.BVS("long_arg_%d" % arg_id, self.project.arch.bits)
            else:
                data = self.mk_type(arg_id, arg_type)

            if data.size() < self.project.arch.bits:
                data = data.zero_extend(self.project.arch.bits - data.size())

            if arg_id < 3:
                state.regs.__setattr__('r%d' % arg_id, data)
            else:
                state.stack_push(data)
        state.solver._solver.timeout = 2000 # 2 seconds as timeout
        return state

    def prepare_state_jlong_as_fun_ptr(self, addr, args):
        state = self.project.factory.blank_state(addr=addr)
        state.regs.r0 = self.jni_ptr
        state.regs.r1 = claripy.BVV(
            self.obj.ptr, self.project.arch.bits)

        parsed_args = dict()
        for i, a in enumerate(args.split(",")):
            a = a.strip().replace(" ", "")
            parsed_args[i+2] = a

        for arg_id in parsed_args:
            arg_type = parsed_args[arg_id]
            if arg_type == "long":
                data = self.mk_funptr_struct(state)
            else:
                data = self.mk_type(arg_id, arg_type)

            if data.size() < self.project.arch.bits:
                data = data.zero_extend(self.project.arch.bits - data.size())

            if arg_id < 3:
                state.regs.__setattr__('r%d' % arg_id, data)
            else:
                state.stack_push(data)
        state.solver._solver.timeout = 2000 # 2 seconds as timeout
        return state

    def _is_thumb(self, addr):
        if self.project.arch.name != "ARMEL":
            return False

        if addr % 2 != 0:
            return False

        self.state.ip = addr
        if self.state.block().size == 0:
            return True
        return False

    @timeout(60*5)  # Risky, let's try
    def _inner_check_cpp_obj(self, addr, args):
        is_thumb = self._is_thumb(addr)
        if is_thumb:
            addr = addr + 1

        state = self.prepare_state_cpp(addr, args)

        tainted_calls = list()
        def checkTaintedCall(state):
            exit_target = state.inspect.exit_target
            if NativeJLongAnalyzer.DEBUG:
                print("checkTaintedCall: ", exit_target)
            if exit_target is None or isinstance(exit_target, int):
                return
            for symb_name in exit_target.variables:
                if "vtable_entry_" in symb_name:
                    tainted_calls.append(symb_name)
                    break
        state.inspect.b('exit', when=angr.BP_BEFORE, action=checkTaintedCall)

        if NativeJLongAnalyzer.DEBUG:
            print("entry r0", state.regs.r0)
            print("entry r1", state.regs.r1)
            print("entry r2", state.regs.r2)

        i    = 0
        smgr = self.project.factory.simgr(state, veritesting=False, save_unsat=False)
        while len(smgr.active) > 0:
            if len(tainted_calls) > 0 or i > NativeJLongAnalyzer.MAXITER:
                break

            if False and NativeJLongAnalyzer.DEBUG:
                for s in smgr.active:
                    print(s)
                    if self.project.is_hooked(s.addr):
                        print(s.regs.r0, s.regs.r1, s.regs.r2)
                        print(self.project.hooked_by(s.addr))
                    else:
                        s.block().pp()
                    print(s.step())
                    input("> Press a key to continue...")

            smgr.explore(n=1)
            if NativeJLongAnalyzer.DEBUG:
                print(i, smgr, smgr.errored, tainted_calls)
            if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
                # Try to limit RAM usage
                break
            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        return len(tainted_calls) > 0

    @timeout(60*5)  # Risky, let's try
    def _inner_check_jlong_as_ptr(self, addr, args):
        is_thumb = self._is_thumb(addr)
        if is_thumb:
            addr = addr + 1

        state = self.prepare_state_jlong_as_ptr(addr, args)

        tainted_load = list()
        def checkTaintedLoads(state):
            read_addr = state.inspect.mem_read_address
            if read_addr is None:
                return
            for symb_name in read_addr.variables:
                if "long_arg_" in symb_name:
                    tainted_load.append(symb_name)
                    break
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=checkTaintedLoads)

        if NativeJLongAnalyzer.DEBUG:
            print("entry r0", state.regs.r0)
            print("entry r1", state.regs.r1)
            print("entry r2", state.regs.r2)

        i    = 0
        smgr = self.project.factory.simgr(state, veritesting=False, save_unsat=False)
        while len(smgr.active) > 0:
            if len(tainted_load) > 0 or i > NativeJLongAnalyzer.MAXITER:
                break

            if False and NativeJLongAnalyzer.DEBUG:
                for s in smgr.active:
                    print(s)
                    if self.project.is_hooked(s.addr):
                        print(s.regs.r0, s.regs.r1, s.regs.r2)
                        print(self.project.hooked_by(s.addr))
                    else:
                        s.block().pp()
                    print(s.step())
                    input("> Press a key to continue...")

            smgr.explore(n=1)
            if NativeJLongAnalyzer.DEBUG:
                print(i, smgr, smgr.errored, tainted_load)
            if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
                # Try to limit RAM usage
                break
            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        return len(tainted_load) > 0

    @timeout(60*5)  # Risky, let's try
    def _inner_check_jlong_as_fun_ptr(self, addr, args):
        is_thumb = self._is_thumb(addr)
        if is_thumb:
            addr = addr + 1

        state = self.prepare_state_jlong_as_fun_ptr(addr, args)

        tainted_calls = list()
        def checkTaintedCall(state):
            exit_target = state.inspect.exit_target
            if NativeJLongAnalyzer.DEBUG:
                print("checkTaintedCall: ", exit_target)
            if exit_target is None or isinstance(exit_target, int):
                return
            for symb_name in exit_target.variables:
                if "fun_ptr_" in symb_name:
                    tainted_calls.append(symb_name)
                    break
        state.inspect.b('exit', when=angr.BP_BEFORE, action=checkTaintedCall)

        if NativeJLongAnalyzer.DEBUG:
            print("entry r0", state.regs.r0)
            print("entry r1", state.regs.r1)
            print("entry r2", state.regs.r2)

        i    = 0
        smgr = self.project.factory.simgr(state, veritesting=False, save_unsat=False)
        while len(smgr.active) > 0:
            if len(tainted_calls) > 0 or i > NativeJLongAnalyzer.MAXITER:
                break

            if False and NativeJLongAnalyzer.DEBUG:
                for s in smgr.active:
                    print(s)
                    if self.project.is_hooked(s.addr):
                        print(s.regs.r0, s.regs.r1, s.regs.r2)
                        print(self.project.hooked_by(s.addr))
                    else:
                        s.block().pp()
                    print(s.step())
                    input("> Press a key to continue...")

            smgr.explore(n=1)
            if NativeJLongAnalyzer.DEBUG:
                print(i, smgr, smgr.errored, tainted_calls)
            if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
                # Try to limit RAM usage
                break
            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        return len(tainted_calls) > 0

    def check_cpp_obj(self, addr, args):
        try:
            res = self._inner_check_cpp_obj(addr, args)
        except TimeoutError:
            sys.stderr.write("WARNING: %#x timeout\n" % addr)
            return False
        # except:
        #     sys.stderr.write("WARNING: unknown error\n")
        #     return False
        return res

    def check_jlong_as_ptr(self, addr, args):
        try:
            res = self._inner_check_jlong_as_ptr(addr, args)
        except TimeoutError:
            sys.stderr.write("WARNING: %#x timeout\n" % addr)
            return False
        # except:
        #     sys.stderr.write("WARNING: unknown error\n")
        #     return False
        return res

    def check_jlong_as_fun_ptr(self, addr, args):
        try:
            res = self._inner_check_jlong_as_fun_ptr(addr, args)
        except TimeoutError:
            sys.stderr.write("WARNING: %#x timeout\n" % addr)
            return False
        # except:
        #     sys.stderr.write("WARNING: unknown error\n")
        #     return False
        return res


if __name__ == "__main__":
    print("[+] Debug standalone script for NativeJLongAnalyzer")

    if len(sys.argv) < 4:
        exit(1)

    binary = sys.argv[1]
    addr   = int(sys.argv[2], 16) if sys.argv[2].startswith("0x") else int(sys.argv[2])
    args   = sys.argv[3]

    NativeJLongAnalyzer.DEBUG = True
    of = NativeJLongAnalyzer(binary)
    # print(of.check_jlong_as_ptr(addr, args))
    print(of.check_jlong_as_fun_ptr(addr, args))
    # print(of.check_cpp_obj(addr, args))
