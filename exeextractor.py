import math
import os
import hashlib
from typing import Counter
import pefile
import argparse
import csv


def analyze_executable(file_path):
    file_name = os.path.basename(file_path)
    print("The name of the file is:", file_name)

    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    md5_result = hash_md5.hexdigest()
    print("The MD5 hash of the file is:", md5_result)

    pe = pefile.PE(file_path)
    machine = pe.FILE_HEADER.Machine
    print("The machine type of the executable (decimal) is:", machine)

    size_of_opt_header = pe.FILE_HEADER.SizeOfOptionalHeader
    print("Size of Optional Header in bytes:", size_of_opt_header)

    characteristics = pe.FILE_HEADER.Characteristics
    print("Characteristics of the file (decimal):", characteristics)

    major_linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion
    minor_linker_version = pe.OPTIONAL_HEADER.MinorLinkerVersion
    print("Major Linker Version:", major_linker_version)
    print("Minor Linker Version:", minor_linker_version)

    size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
    print("Size of Code:", size_of_code)

    size_of_initialized_data = pe.OPTIONAL_HEADER.SizeOfInitializedData
    print("Size of Initialized Data:", size_of_initialized_data)

    size_of_uninitialized_data = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    print("Size of Uninitialized Data:", size_of_uninitialized_data)
    address_of_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("Address of Entry Point (RVA):", address_of_entry_point)

    base_of_code = pe.OPTIONAL_HEADER.BaseOfCode
    print("Base of Code (RVA):", base_of_code)

    # BaseOfData may not be present in PE32+ executables (64-bit)
    if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
        base_of_data = pe.OPTIONAL_HEADER.BaseOfData
        print("Base of Data (RVA):", base_of_data)
    else:
        base_of_data = 0
        print("Base of Data: Not applicable for this PE (likely a 64-bit executable)")

    image_base = pe.OPTIONAL_HEADER.ImageBase
    print("Image Base (preferred load address):", image_base)

    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    print("Section Alignment (memory):", section_alignment)

    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    print("File Alignment (disk):", file_alignment)

    major_os_version = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    minor_os_version = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    print("Major Operating System Version:", major_os_version)
    print("Minor Operating System Version:", minor_os_version)

    major_image_version = pe.OPTIONAL_HEADER.MajorImageVersion
    minor_image_version = pe.OPTIONAL_HEADER.MinorImageVersion
    print("Major Image Version:", major_image_version)
    print("Minor Image Version:", minor_image_version)

    major_subsystem_version = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    minor_subsystem_version = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    print("Major Subsystem Version:", major_subsystem_version)
    print("Minor Subsystem Version:", minor_subsystem_version)

    subsystem = pe.OPTIONAL_HEADER.Subsystem
    print("Subsystem (decimal):", subsystem)

    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    print("DLL Characteristics (decimal):", dll_characteristics)

    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    print("Size of Image (memory):", size_of_image)

    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    print("Size of Headers (disk):", size_of_headers)

    checksum = pe.OPTIONAL_HEADER.CheckSum
    print("Checksum (decimal):", checksum)

    # PE sections
    print("\nPE Sections:")
    for section in pe.sections:
        print(section.Name.decode().strip('\x00'), hex(section.VirtualAddress), hex(section.Misc_VirtualSize),
              section.SizeOfRawData)    
        
    # PE imports
    print("\nPE Imports:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll.decode())
        for imp in entry.imports:
            print('\t', hex(imp.address), imp.name.decode())

    # PE exports   
    print("\nPE Exports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode())
    else:
        print("No export table found.")

    # PE resources
    print("\nPE Resources:")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            print(resource_type.name)
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            print('\t', hex(resource_lang.data.struct.OffsetToData),
                                  resource_lang.data.struct.Size)
            print()
    else:
        print("No resource table found.")

    sizeof_stack_reserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
    print("Size of Stack Reserve:", sizeof_stack_reserve)

    sizeof_stack_commit = pe.OPTIONAL_HEADER.SizeOfStackCommit
    print("Size of Stack Commit:", sizeof_stack_commit)

    sizeof_heap_reserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    print("Size of Heap Reserve:", sizeof_heap_reserve)

    sizeof_heap_commit = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    print("Size of Heap Commit:", sizeof_heap_commit)

    loader_flags = pe.OPTIONAL_HEADER.LoaderFlags
    print("Loader Flags (decimal):", loader_flags)

    number_of_rva_and_sizes = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    print("Number of Data Directory entries:", number_of_rva_and_sizes)

    # Calculate sectionmeanentropy
    section_entropies = []
    for section in pe.sections:
        section_data = section.get_data()
        section_entropy = 0
        if len(section_data) > 0:
            section_entropy = sum(-p * math.log2(p) for p in Counter(section_data).values() if p > 0) / len(section_data)
        section_entropies.append(section_entropy)

    sectionmeanentropy = sum(section_entropies) / len(section_entropies)
    print("Section Mean Entropy:", sectionmeanentropy)

    # Calculate sectionminentropy
    section_entropies = []
    for section in pe.sections:
        section_data = section.get_data()
        section_entropy = 0
        if len(section_data) > 0:
            section_entropy = min(-p * math.log2(p) for p in Counter(section_data).values() if p > 0) / len(section_data)
        section_entropies.append(section_entropy)
    sectionminentropy = min(section_entropies)
    print("Section Min Entropy:", sectionminentropy)

    # Calculate sectionmaxentropy
    section_entropies = []
    for section in pe.sections:
        section_data = section.get_data()
        section_entropy = 0
        if len(section_data) > 0:
            section_entropy = max(-p * math.log2(p) for p in Counter(section_data).values() if p > 0) / len(section_data)
        section_entropies.append(section_entropy)
    sectionmaxentropy = max(section_entropies)
    print("Section Max Entropy:", sectionmaxentropy)



    # Calculate sectionsMeanVirtualsize
    section_virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    sections_mean_virtual_size = sum(section_virtual_sizes) / len(section_virtual_sizes)
    print("Mean Virtual Size of Sections:", sections_mean_virtual_size)

    # Calculate sectionsMeanRawSize
    section_raw_sizes = [section.SizeOfRawData for section in pe.sections]
    sections_mean_raw_size = sum(section_raw_sizes) / len(section_raw_sizes)
    print("Mean Raw Size of Sections:", sections_mean_raw_size)

    # Calculate SectionsMinRawSize
    section_raw_sizes = [section.SizeOfRawData for section in pe.sections]
    sections_min_raw_size = min(section_raw_sizes)
    print("Minimum Raw Size of Sections:", sections_min_raw_size)

    # Calculate SectionsMaxRawSize
    section_raw_sizes = [section.SizeOfRawData for section in pe.sections]
    sections_max_raw_size = max(section_raw_sizes)
    print("Maximum Raw Size of Sections:", sections_max_raw_size)

    imports_nb_dll = len(pe.DIRECTORY_ENTRY_IMPORT)
    print("Number of Imported DLLs:", imports_nb_dll)

    imports_nb_ordinal = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
    print("Number of Imported Ordinals:", imports_nb_ordinal)

    export_nb = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        export_nb = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    print("Number of Exports:", export_nb)

    resources_nb = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        resources_nb = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    print("Number of Resources:", resources_nb)

    # Calculate ResourcesMeanEntropy
    resource_entropies = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_data = resource_lang.data.struct.OffsetToData
                            resource_size = resource_lang.data.struct.Size
                            resource_entropy = 0
                            if resource_size > 0:
                                resource_data = pe.get_memory_mapped_image()[resource_data:resource_data+resource_size]
                                resource_entropy = sum(-p * math.log2(p) for p in Counter(resource_data).values() if p > 0) / resource_size
                            resource_entropies.append(resource_entropy)
    resources_mean_entropy = sum(resource_entropies) / len(resource_entropies)
    print("Mean Entropy of Resources:", resources_mean_entropy)

    # Calculate ResourcesMinEntropy
    resource_entropies = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            resource_entropy = 0
                            if len(resource_data) > 0:
                                resource_entropy = min(-p * math.log2(p) for p in Counter(resource_data).values() if p > 0) / len(resource_data)
                            resource_entropies.append(resource_entropy)
    resources_min_entropy = min(resource_entropies)
    print("Minimum Entropy of Resources:", resources_min_entropy)

    # Calculate ResourcesMaxEntropy
    resource_entropies = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            resource_entropy = 0
                            if len(resource_data) > 0:
                                resource_entropy = max(-p * math.log2(p) for p in Counter(resource_data).values() if p > 0) / len(resource_data)
                            resource_entropies.append(resource_entropy)
    resources_max_entropy = max(resource_entropies)
    print("Maximum Entropy of Resources:", resources_max_entropy)

    # Calculate ResourcesMeanSize
    resource_sizes = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_size = resource_lang.data.struct.Size
                            resource_sizes.append(resource_size)
    resources_mean_size = sum(resource_sizes) / len(resource_sizes)
    print("Mean Size of Resources:", resources_mean_size)

    # Calculate ResourcesMinSize
    resource_sizes = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_size = resource_lang.data.struct.Size
                            resource_sizes.append(resource_size)
    resources_min_size = min(resource_sizes)
    print("Minimum Size of Resources:", resources_min_size)

    # Calculate ResourcesMaxSize
    resource_sizes = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_size = resource_lang.data.struct.Size
                            resource_sizes.append(resource_size)
    resources_max_size = max(resource_sizes)
    print("Maximum Size of Resources:", resources_max_size)

    load_config_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size
    print("Load Configuration Size:", load_config_size)

    version_info_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
    print("Version Information Size:", version_info_size)


    data = {
    "Name": file_name,
    "md5": md5_result,
    "Machine": machine,
    "SizeOfOptionalHeader": size_of_opt_header,
    "Characteristics": characteristics,
    "MajorLinkerVersion": major_linker_version,
    "MinorLinkerVersion": minor_linker_version,
    "SizeOfCode": size_of_code,
    "SizeOfInitializedData": size_of_initialized_data,
    "SizeOfUninitializedData": size_of_uninitialized_data,
    "AddressOfEntryPoint": address_of_entry_point,
    "BaseOfCode": base_of_code,
    "BaseOfData": base_of_data,
    "ImageBase": image_base,
    "SectionAlignment": section_alignment,
    "FileAlignment": file_alignment,
    "MajorOperatingSystemVersion": major_os_version,
    "MinorOperatingSystemVersion": minor_os_version,
    "MajorImageVersion": major_image_version,
    "MinorImageVersion": minor_image_version,
    "MajorSubsystemVersion": major_subsystem_version,
    "MinorSubsystemVersion": minor_subsystem_version,
    "SizeOfImage": size_of_image,
    "SizeOfHeaders": size_of_headers,
    "CheckSum": checksum,
    "Subsystem": subsystem,
    "DllCharacteristics": dll_characteristics,
    "SizeOfStackReserve": sizeof_stack_reserve,
    "SizeOfStackCommit": sizeof_stack_commit,
    "SizeOfHeapReserve": sizeof_heap_reserve,
    "SizeOfHeapCommit": sizeof_heap_commit,
    "LoaderFlags": loader_flags,
    "NumberOfRvaAndSizes": number_of_rva_and_sizes,
    "SectionsNb": len(pe.sections),
    "SectionsMeanEntropy": sectionmeanentropy,
    "SectionsMinEntropy": sectionminentropy,
    "SectionsMaxEntropy": sectionmaxentropy,
    "SectionsMeanRawsize": sections_mean_raw_size,
    "SectionsMinRawsize": sections_min_raw_size,
    "SectionMaxRawsize": sections_max_raw_size,
    "SectionsMeanVirtualsize": sections_mean_virtual_size,
    "SectionsMinVirtualsize": min(section_virtual_sizes),
    "SectionMaxVirtualsize": max(section_virtual_sizes),
    "ImportsNbDLL": imports_nb_dll,
    "ImportsNb": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
    "ImportsNbOrdinal": imports_nb_ordinal,
    "ExportNb": export_nb,
    "ResourcesNb": resources_nb,
    "ResourcesMeanEntropy": resources_mean_entropy,
    "ResourcesMinEntropy": resources_min_entropy,
    "ResourcesMaxEntropy": resources_max_entropy,
    "ResourcesMeanSize": resources_mean_size,
    "ResourcesMinSize": resources_min_size,
    "ResourcesMaxSize": resources_max_size,
    "LoadConfigurationSize": load_config_size,
    "VersionInformationSize": version_info_size,
    "legitmate": 0
}

    csv_file_path = 'analysis_results.csv'
    file_exists = os.path.isfile(csv_file_path)
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

    return data
    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze an executable file.')
    parser.add_argument('exe_path', type=str, help='The path to the executable file')
    args = parser.parse_args()

    # Ensure the executable path provided is valid and handle possible errors
    try:
        results = analyze_executable(args.exe_path)
        print("Analysis Results:")
        print(results)
    except FileNotFoundError:
        print(f"Error: The file '{args.exe_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred during analysis: {e}")