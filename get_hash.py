import os
import pefile
import sys

BASE_DIR = os.path.join(os.environ['WINDIR'], 'system32')

def get_string_hash(s):
    v = 0
    for c in s:
        v = (v >> 0xd) | ((v & 0x1fff) << 19)
        v = (v + ord(c)) & 0xffffffff
    return v

def get_lib_hash(s):
    return get_string_hash(''.join([ i + '\x00' for i in (s + '\x00').upper() ]))

def get_sym_hash(s):
    return get_string_hash(s + '\x00')

def find_by_hash(hash, dll_postfix):
    for dll_name in os.listdir(BASE_DIR):
        if not dll_name.endswith(dll_postfix):
            continue
        dll_path = os.path.join(BASE_DIR, dll_name)
        dll_hash = get_lib_hash(dll_name)
        pe = pefile.PE(dll_path)
        if pe is None or not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            continue
        syms = [ sym.name.decode() for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols if sym.name is not None ]
        for s in syms:
            if (get_sym_hash(s) + dll_hash) & 0xFFFFFFFF == hash:
                print('%s!%s' % (dll_name, s))
                return
    print('Coult not find hash!')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        dll_postfix = '.dll' if len(sys.argv) == 2 else sys.argv[2]
        num = int(sys.argv[1], 16) if 'x' in sys.argv[1] else int(sys.argv[1])
        find_by_hash(num, dll_postfix)