from binaryninja import *
import re

# IAT Dump for stomped PE from x64dbg, view as address in dump and just copy lines
# E.g;
# 005CA000  76E573F0  ðsåv  advapi32.GetExplicitEntriesFromAclW

iat_dump_field = MultilineTextField("""
Enter the IAT dump in the format:

<IAT addr> <Real Addr> <4 bytes ignored> <dll.Func>

E.g.:
005CA000  76E573F0  ....  ntdll.DbgPrint

This is the format from the x64dbg dump view
when the IAT is viewed as an address.
""")

imports = {
#'ntdll.DbgPrint' : (0x005CA000, 0x76E573F0)
}

regex = r"(\w+)\s+(\w+)\s+....\s+(\S+)"

class FixStompedImports(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Fixing imports', True)
        self.bv = bv

    def run(self):
        parse_iat_dump(self.bv)
        create_memory_regions(self.bv)
        fix_imports(self.bv)
        self.bv.update_analysis_and_wait()
        print('Done')


def parse_iat_dump(bv) -> bool:
    iat_dump = ""
    if get_form_input([iat_dump_field], "IAT Dump"):
        iat_dump = iat_dump_field.result
    else:
        print("User cancelled the IAT dump form")
        return False
    print('Parsing IAT dump')
    for line in iat_dump.splitlines():
        if '00000000' in line or not line.strip():
            continue
        result = re.search(regex, line)
        if not result or len(result.groups()) != 3:
            print(f'Unable to parse IAT dump line: \n{line}')
            continue
        dll = result.group(3).replace('.', '!')
        iat_addr = int(result.group(1), 16)
        real_addr = int(result.group(2), 16)
        imports[dll] = (iat_addr, real_addr)
    for imp, (iat_addr, real_addr) in imports.items():
        print(f'Found import: {imp} at 0x{hex(iat_addr)} -> 0x{hex(real_addr)}')
    return True


def fix_imports(bv):
    print('Fixing imports')
    for imp, (iat_addr, real_addr) in imports.items():
        dll, func = imp.split("!")
        bv.data_vars[iat_addr].name = func
        bv.data_vars[real_addr].name = func
        type_libs = bv.platform.get_type_libraries_by_name(f'{dll}.dll')
        if len(type_libs) == 0:
            print(f'DLL Not found: {dll}')
            continue
        type_lib = type_libs[0]
        t = bv.import_library_object(func, type_lib)
        if t is None:
            print(f'Func not found: {func} in {dll}')
            continue
        bv.data_vars[real_addr].name = func
        bv.define_data_var(real_addr, t)


def create_memory_regions(bv):
    print('Creating memory regions')
    low = 0xffffffff
    high = 0

    for (_, real_addr) in imports.values():
        if real_addr < low:
            low = real_addr
        if real_addr > high:
            high = real_addr
    start = low & 0xffff0000
    length = high - low | 0x0000ffff
    bv.add_user_segment(start, length, 0, 0, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsCode)
    bv.add_user_section('externs', start, length, SectionSemantics.ReadOnlyCodeSectionSemantics)
    bv.update_analysis_and_wait()


def main(bv):
    FixStompedImports(bv).start()


PluginCommand.register('Fix stomped imports', 'Fix stomped imports', main)
