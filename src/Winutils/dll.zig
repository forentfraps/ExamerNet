const std = @import("std");
const win = @import("std").os.windows;
const clr = @import("clr.zig");

const winc = @import("../Windows.h.zig");

const BASE_RELOCATION_BLOCK = struct {
    PageAddress: u32,
    BlockSize: u32,
};

const BASE_RELOCATION_ENTRY = packed struct {
    Offset: u12,
    Type: u4,
};

const DLLEntry = fn (dll: win.HINSTANCE, reason: u32, reserved: ?*std.os.windows.LPVOID) bool;

const DllError = error{
    Size,
    VirtualAllocNull,
};

const print = std.debug.print;

const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    alignment: u32,
    Buffer: ?*u16,
};

const LDR_DATA_TABLE_ENTRY = extern struct {
    Reserved1: [2]usize,
    //16
    InMemoryOrderLinks: winc.LIST_ENTRY,
    // 32
    Reserved2: [4]usize,
    // 64
    DllBase: ?*void,
    //72
    EntryPoint: ?*void,
    //80
    Reserved3: usize,
    //88
    fullDllName: UNICODE_STRING,
    //106
    BaseDllName: UNICODE_STRING,
    //120
    Reserved5: usize,
    TimeDateStamp: u32,
};

const PEB_LDR_DATA = extern struct {
    Reserved1: [3]usize,
    InMemoryOrderModuleList: [2]usize,
};

const PEB = extern struct {
    Reserved1: [2]u8,
    BeingDebugged: u8,
    Reserved2: [1]u8,
    Reserved3: [2]*void,
    Ldr: *PEB_LDR_DATA,
    Reserved4: [3]*void,
    Reserved5: [2]usize,
    Reserved6: *void,
    Reserved7: usize,
    Reserved8: [4]usize,
    Reserved9: [4]usize,
    Reserved10: [1]usize,
    PostProcessInitRoutine: *const usize,
    Reserved11: [1]usize,
    Reserved12: [1]usize,
    SessionId: u32,
};

const Dll = struct {
    Exports: std.Hashmap,
    BaseAddr: [*]u8,
};

fn print16(s: [*]const u16) void {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        const c: u8 = @intCast(s[i]);
        print("{c}", .{c});
    }
    print("\n", .{});
}

pub const DllLoader = struct {
    LoadedDlls: std.Hashmap,
    pub fn init() DllLoader {}

    pub fn getLoadedDLLs() [][260]u16 {
        const heap = win.kernel32.GetProcessHeap().?;
        var modules: [1000][winc.MAX_PATH]u16 = undefined; // Buffer for module names
        var count: usize = 0;
        var peb: *PEB = undefined;
        peb = asm volatile ("mov %gs:0x60, %rax"
            : [peb] "={rax}" (-> *PEB),
            :
            : "memory"
        );
        print("PEB PTR {*}\n", .{peb});
        const ldr = peb.Ldr;
        const head: *winc.LIST_ENTRY = @ptrFromInt(ldr.InMemoryOrderModuleList[0]);
        var curr: *winc.LIST_ENTRY = head.Flink;

        while (curr != head and count < 1000) : (curr = curr.Flink) {
            print("[+] New iteration\n", .{});
            const entry: *LDR_DATA_TABLE_ENTRY = @ptrFromInt(@intFromPtr(curr) - 16);

            const BaseDllName: UNICODE_STRING = entry.BaseDllName;


            const indexable_buffer: [*]const u16 = @ptrCast(BaseDllName.Buffer.?);

            if (BaseDllName.Buffer != null and (BaseDllName.Length / 2) <= 260) {
                print16(indexable_buffer);

                var utf16_buffer: [260]u16 = undefined;
                var utf16_len: usize = 0;
                for (0..(BaseDllName.Length / 2)) |i| {
                    const ch = indexable_buffer[i];
                    utf16_buffer[utf16_len] = @intCast(ch);
                    utf16_len += 1;
                }
                utf16_buffer[utf16_len] = 0;
                std.mem.copyForwards(u16, modules[count][0..utf16_len], utf16_buffer[0..utf16_len]);
                count += 1;
            }
        }
        return modules[0..count];
    }

    pub fn ReflectiveLoad(_: DllLoader, comptime libpath: [*:0]const u8) anyerror!void {
        // get this module's image base address

        // load DLL into memory
        const heap = win.kernel32.GetProcessHeap().?;
        var libpath16_len: usize = 0;
        const libpath16: [*c]u16 = @ptrCast(@alignCast(win.kernel32.HeapAlloc(
            heap,
            winc.HEAP_ZERO_MEMORY,
            (while (true) : (libpath16_len += 1) {
                if (!(libpath[libpath16_len] != 0 and libpath16_len < 50)) break libpath16_len;
            } else 20) * 2 + 2,
        ).?));
        defer _ = win.kernel32.HeapFree(heap, 0, libpath16);
        clr.u8tou16(libpath, libpath16);
        const dll_handle = win.kernel32.CreateFileW(
            libpath16,
            win.GENERIC_READ,
            0,
            null,
            win.OPEN_EXISTING,
            0,
            null,
        );
        defer win.CloseHandle(dll_handle);

        var dll_size_i: i64 = 0;
        if ((win.kernel32.GetFileSizeEx(dll_handle, &dll_size_i) <= 0)) {
            return DllError.Size;
        }
        const dll_size: usize = @intCast(dll_size_i);

        const dll_bytes: [*c]u8 = @ptrCast(win.kernel32.HeapAlloc(
            heap,
            winc.HEAP_ZERO_MEMORY,
            dll_size,
        ).?);
        defer _ = win.kernel32.HeapFree(heap, 0, dll_bytes);

        _ = try win.ReadFile(dll_handle, dll_bytes[0..dll_size], 0);
        // get pointers to in-memory DLL headers
        const dos_headers: *winc.IMAGE_DOS_HEADER = @ptrCast(@alignCast(dll_bytes));
        const lfanewoffset: usize = @intCast(dos_headers.e_lfanew);
        const nt_headers: *const winc.IMAGE_NT_HEADERS = @ptrCast(@alignCast(dll_bytes[lfanewoffset..]));
        const dll_image_size = nt_headers.OptionalHeader.SizeOfImage;

        // allocate new memory space for the DLL
        var dll_base: [*c]u8 = @ptrCast(win.kernel32.VirtualAlloc(
            @ptrFromInt(nt_headers.OptionalHeader.ImageBase),
            dll_image_size,
            win.MEM_RESERVE | win.MEM_COMMIT,
            win.PAGE_EXECUTE_READWRITE,
        ));
        print("Checkpoint 0 \n", .{});
        if (dll_base == null) {
            dll_base = @ptrCast(win.kernel32.VirtualAlloc(
                null,
                dll_image_size,
                win.MEM_RESERVE | win.MEM_COMMIT,
                win.PAGE_EXECUTE_READWRITE,
            ).?);
        }

        print("Checkpoint 1 addr: {*}\n", .{dll_base});
        // get delta between this module's image base and the DLL that was read into memory
        const delta_image_base = @intFromPtr(dll_base) - nt_headers.OptionalHeader.ImageBase;

        // copy over DLL image headers to the newly allocated space for the DLL
        std.mem.copyForwards(u8, dll_base[0..nt_headers.OptionalHeader.SizeOfHeaders], dll_bytes[0..nt_headers.OptionalHeader.SizeOfHeaders]);

        // copy over DLL image sections to the newly allocated space for the DLL
        var section_index: usize = 0;
        var section: *const winc.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(dll_bytes[(lfanewoffset + @sizeOf(winc.IMAGE_NT_HEADERS))..]));
        while (section_index < nt_headers.FileHeader.NumberOfSections) {
            const section_destination: [*]u8 = @ptrCast(dll_base[section.VirtualAddress..]);
            const section_bytes: [*]u8 = @ptrCast(dll_bytes[section.PointerToRawData..]);
            std.mem.copyForwards(u8, section_destination[0..section.SizeOfRawData], section_bytes[0..section.SizeOfRawData]);
            section = @ptrFromInt(@intFromPtr(section) + @sizeOf(winc.IMAGE_SECTION_HEADER));
            section_index += 1;
        }

        print("Checkpoint 2\n", .{});
        // perform image base relocations
        const relocations = nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const relocation_table = @intFromPtr(dll_base) + relocations.VirtualAddress;
        var relocations_processed: usize = 0;

        while (relocations_processed < relocations.Size) {
            const relocation_block: *const BASE_RELOCATION_BLOCK = @ptrFromInt(relocation_table + relocations_processed);
            relocations_processed += @sizeOf(BASE_RELOCATION_BLOCK);
            const relocations_count = (relocation_block.BlockSize - @sizeOf(BASE_RELOCATION_BLOCK)) / @sizeOf(BASE_RELOCATION_ENTRY);
            const relocation_entries: [*]const BASE_RELOCATION_ENTRY = @ptrFromInt(relocation_table + relocations_processed);

            var entry_index: usize = 0;
            while (entry_index < relocations_count) {
                if (relocation_entries[entry_index].Type != 0) {
                    const relocation_rva: usize = relocation_block.PageAddress + relocation_entries[entry_index].Offset;
                    var address_to_patch: usize = @intFromPtr(dll_base + relocation_rva);
                    address_to_patch += delta_image_base;
                    const address_u8_array: [*]u8 = @ptrCast(&address_to_patch);
                    std.mem.copyForwards(u8, dll_base[relocation_rva .. relocation_rva + 4], address_u8_array[0..4]);
                }
                relocations_processed += @sizeOf(BASE_RELOCATION_ENTRY);
                entry_index += 1;
            }
        }

        print("Checkpoint 3\n", .{});
        // resolve import address table
        var import_descriptor: *const winc.IMAGE_IMPORT_DESCRIPTOR = @ptrCast(@alignCast(dll_base[nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress..]));
        while (import_descriptor.Name != 0) {
            const library_name: [*:0]const u8 = dll_base[import_descriptor.Name..];
            var library_name16_len: usize = 0;

            //print("Current lib to load: {s}\n", .{library_name});
            const library_name16: [*c]u16 = @ptrCast(@alignCast(win.kernel32.HeapAlloc(
                heap,
                winc.HEAP_ZERO_MEMORY,
                (while (true) : (library_name16_len += 1) {
                    if (!(library_name[library_name16_len] != 0 and library_name16_len < 50)) break library_name16_len;
                } else 20) * 2 + 2,
            ).?));
            //print("Current lib to load: {s} size in u8 {d} in u16 {d}\n", .{ library_name, (library_name16_len - 2) / 2, library_name16_len });
            defer _ = win.kernel32.HeapFree(heap, 0, library_name16);

            clr.u8tou16(library_name, library_name16);
            const library_ = win.kernel32.LoadLibraryW(library_name16);
            if (library_) |library| {
                var thunk: *winc.IMAGE_THUNK_DATA = @ptrCast(@alignCast(dll_base[import_descriptor.FirstThunk..]));
                while (thunk.u1.AddressOfData != 0) {
                    if (winc.IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) {
                        const function_ordinal: [*:0]const u8 = @ptrFromInt(winc.IMAGE_ORDINAL(thunk.u1.Ordinal));
                        thunk.u1.Function = @intFromPtr(win.kernel32.GetProcAddress(library, function_ordinal));
                    } else {
                        const function_name: *const winc.IMAGE_IMPORT_BY_NAME = @ptrCast(@alignCast(dll_base[thunk.u1.AddressOfData..]));
                        const function_name_realname: [*:0]const u8 = @ptrCast(&function_name.Name);
                        thunk.u1.Function = @intFromPtr(win.kernel32.GetProcAddress(library, function_name_realname));
                    }
                    thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(winc.IMAGE_THUNK_DATA));
                }
            }
            import_descriptor = @ptrFromInt(@intFromPtr(import_descriptor) + @sizeOf(winc.IMAGE_IMPORT_DESCRIPTOR));
        }

        print("Checkpoint 4\n", .{});
        // execute the loaded DLL
        const dll_entry: *const DLLEntry = @ptrCast(dll_base[nt_headers.OptionalHeader.AddressOfEntryPoint..]);
        const dll_base_hinstance: win.HINSTANCE = @ptrCast(dll_base);
        print("Running the dll:\n", .{});
        _ = dll_entry(dll_base_hinstance, winc.DLL_PROCESS_ATTACH, null);
    }
};
