import sys
import pefile
import datetime
import peutils


def main(exe_path):
    print(exe_path)
    try:
        pe = pefile.PE(exe_path)
        file_type(pe)
        total_import_dll(pe)
        total_import_func(pe)
        print("[*] File timestamp = ", str(datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)))
        check_entry_point(pe)
        check_packing(pe)
        check_entropy(pe)
        zero_sized_section(pe)
        verify_checksum(pe)
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)


def file_type(pe):
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_EXECUTABLE = 0x0002
    IMAGE_FILE_SYSTEM = 0x1000

    if (IMAGE_FILE_DLL & pe.FILE_HEADER.Characteristics) == IMAGE_FILE_DLL:
        print("[*] File Type = DLL")
    elif (IMAGE_FILE_SYSTEM & pe.FILE_HEADER.Characteristics) == IMAGE_FILE_SYSTEM:
        print("[*] File Type = SERVICE")
    elif (IMAGE_FILE_EXECUTABLE & pe.FILE_HEADER.Characteristics) == IMAGE_FILE_EXECUTABLE:
        print("[*] File Type = EXECUTABLE")
    else:
        print("[*] File Type = UNKNOWN")


def check_entry_point(pe):
    ep_address = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    ep_section_name = ((pe.get_section_by_rva(ep_address)).Name).decode("utf-8")
    if ep_section_name is '.text' or ep_section_name is '.code' or ep_section_name is '.CODE' or ep_section_name is 'INIT':
        print("[*] Entry point in section: ", ep_section_name)
    else:
        print("[*] Alert: Entry point in section = ", ep_section_name)


def total_import_dll(pe):
    count = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        count = count + 1
    print("[*] Total imported DLLs = ", count)


def total_import_func(pe):
    count = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for func in entry.imports:
            count = count + 1
    print("[*] Total imported functions = ", count)


def check_packing(pe):
    signatures = peutils.SignatureDatabase('C:\\Users\\rohan\\Desktop\\Homework 2\\Signature.txt')
    matches = signatures.match(pe, ep_only=True)
    if not matches:
        print("[*] File is not packed")
    else:
        print(matches)


def check_entropy(pe):
    # pe.get_entropy()
    print("[*] Sections Entropy: (Min=0.0, Max=8.0)")
    flag = False
    for section in pe.sections:
        if section.get_entropy() > 6:
            flag = True
        print("\t", (section.Name).decode("utf-8"), " entropy: {0:f}".format(section.get_entropy()))
    if flag:
        print("Alert: PE maybe Packed/Compressed due to high entropy.")


def zero_sized_section(pe):
    for section in pe.sections:
        if section.SizeOfRawData == 0:
            print("[*] Alert: ", (section.Name).decode("utf-8"), "is a zero sized section")


def verify_checksum(pe):
    if pe.OPTIONAL_HEADER.CheckSum == pe.generate_checksum():
        print("[*] Checksum matched")
    else:
        print("[*] Alert: Checksum mis-matched")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write("ERROR:\n\tSyntax: pe_parser.py <pefile-path>\n")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))