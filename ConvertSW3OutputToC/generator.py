import json
import re

def extract_prototypes(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        prototypes = json.load(f)
    return prototypes

def extract_hashes(asm_path):
    with open(asm_path, 'r', encoding='utf-8') as f:
        asm_content = f.read()

    # 正则匹配函数名和哈希值
    pattern = re.compile(
        r'Sw3(\w+)\s+PROC.*?mov\s+ecx,\s+([0-9A-Fa-f]+)h.*?Sw3\1\s+ENDP',
        re.DOTALL
    )
    matches = pattern.findall(asm_content)
    hash_dict = {name: hash_val for name, hash_val in matches}
    return hash_dict

def generate_function_code(func_name, func_info, func_hash):
    return_type = func_info.get('type', 'void')
    params = func_info.get('params', [])
    param_list = [f"{param['type']} {param['name']}" for param in params]
    param_str = ', '.join(param_list)
    assignments = [f" Params.param[{i+1}] = (DWORD_PTR){params[i]['name']};" for i in range(len(params))]
    assignments_str = ''.join(assignments)
    func_code = f"{return_type} SF{func_name}({param_str}) {{{assignments_str} Params.ParamNum = {len(params)}; Params.FuncHash = 0x{func_hash}; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L\"C:\\\\Windows\\\\notepad.exe\"); return 0;}}"
    return func_code

def generate_extern_declaration(func_name, func_info):
    return_type = func_info.get('type', 'void')
    params = func_info.get('params', [])
    param_list = []
    for param in params:
        param_type = param['type']
        param_name = param['name']
        param_list.append(f"{param_type} {param_name}")
    param_str = ', '.join(param_list)
    
    extern_declaration = f"extern {return_type} SF{func_name}({param_str});\n"
    return extern_declaration

def main():
    # 定义要跳过的函数数组
    skipped_functions = ['NtCreateFile', 'NtWriteFile', 'NtGetPlugPlayEvent']
    # 用于存储实际被跳过的函数
    actually_skipped = []

    prototypes_path = './prototypes.json'  # SW3生成的文件
    asm_path = './syscalls-asm.x64.asm'   # SW3生成的文件
    output_path = './output.c'
    extern_decls_path = './header.h'

    prototypes = extract_prototypes(prototypes_path)
    hashes = extract_hashes(asm_path)

    with open(output_path, 'w', encoding='utf-8') as out_file, \
         open(extern_decls_path, 'w', encoding='utf-8') as extern_file:
        for func_name, func_info in prototypes.items():
            # 检查是否需要跳过该函数
            if func_name in skipped_functions:
                actually_skipped.append(func_name)
                print(f"[!] 跳过函数: {func_name}")
                continue
                
            func_hash = hashes.get(func_name)
            if not func_hash:
                print(f"[-] 找不到函数 {func_name} 的哈希值")
                continue
            params = func_info.get('params', [])
            # 生成函数代码
            func_code = generate_function_code(func_name, func_info, func_hash)
            out_file.write(func_code + '\n')
            # 生成extern声明
            extern_decl = generate_extern_declaration(func_name, func_info)
            extern_file.write(extern_decl)

    # 在处理完成后打印被跳过的函数
    if actually_skipped:
        print("\n被跳过的函数列表:")
        for func in actually_skipped:
            print(f"- {func}")

if __name__ == "__main__":
    main()