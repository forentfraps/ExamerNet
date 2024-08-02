const std = @import("std");
const win = @import("std").os.windows;
const clr = @import("clr.zig");
const sneaky_memory = @import("memory.zig");

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

pub const DllError = error{
    Size,
    VirtualAllocNull,
    HashmapSucks,
    FuncResolutionFailed,
};

const print = std.debug.print;

const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    alignment: u32,
    Buffer: ?[*:0]u16,
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

pub const Dll = struct {
    NameExports: std.StringHashMap(*void) = undefined,
    OrdinalExports: std.AutoHashMap(u16, *void) = undefined,
    BaseAddr: [*]u8 = undefined,
    Path: [*:0]u16 = undefined,
};

fn print16(s: anytype) void {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        const c: u8 = @intCast(s[i]);
        print("{c}", .{c});
    }
    print("\n", .{});
}
const MappingContext = struct {
    pub fn hash(self: @This(), key: []u16) u64 {
        _ = self;

        const len = key.len;
        const u8ptr: [*]const u8 = @ptrCast(key.ptr);
        var hasher = std.hash.Wyhash.init(0);

        hasher.update(u8ptr[0 .. len * 2]);
        return hasher.final();
    }

    pub fn eql(self: @This(), key_1: []u16, key_2: []u16) bool {
        _ = self;

        return std.mem.eql(u16, key_1, key_2);
    }
};

pub const u16HashMapType = std.HashMap([]u16, *Dll, MappingContext, 80);

const lstring = clr.lstring;

pub const DllLoader = struct {
    LoadedDlls: u16HashMapType = undefined,
    Allocator: std.mem.Allocator,
    HeapAllocator: sneaky_memory.HeapAllocator = undefined,

    pub fn init(allocator: std.mem.Allocator) DllLoader {
        return .{
            .Allocator = allocator,
        };
    }

    pub fn getLoadedDlls(self: *DllLoader) !void {
        //const heap = win.kernel32.GetProcessHeap().?;

        const peb: *PEB = asm volatile ("mov %gs:0x60, %rax"
            : [peb] "={rax}" (-> *PEB),
            :
            : "memory"
        );
        const ldr = peb.Ldr;
        const head: *winc.LIST_ENTRY = @ptrFromInt(ldr.InMemoryOrderModuleList[0]);
        var curr: *winc.LIST_ENTRY = head.Flink;
        var count: usize = 0;
        var skipcount: i32 = 2;
        self.LoadedDlls = u16HashMapType.init(self.Allocator);
        //Skipping ListHead and .exe selfmodule
        while (curr != head and count < 1000) : ({
            curr = curr.Flink;
            count += 1;
        }) {
            const entry: *LDR_DATA_TABLE_ENTRY = @ptrFromInt(@intFromPtr(curr) - 16);

            const BaseDllName: UNICODE_STRING = entry.BaseDllName;

            if (BaseDllName.Buffer != null and (BaseDllName.Length / 2) <= 260 and skipcount <= 0) {
                var dll: *Dll = @ptrCast(@alignCast(try self.Allocator.create(Dll)));
                dll.BaseAddr = @ptrCast(entry.DllBase);
                dll.Path = @ptrCast((try self.Allocator.alloc(u16, entry.fullDllName.Length / 2 + 1)).ptr);
                std.mem.copyForwards(u16, dll.Path[0..(entry.fullDllName.Length / 2 + 1)], entry.fullDllName.Buffer.?[0..(entry.fullDllName.Length / 2 + 1)]);
                try self.ResolveExports(dll);
                try self.LoadedDlls.put(BaseDllName.Buffer.?[0..(entry.BaseDllName.Length / 2 + 1)], dll);
                print16(BaseDllName.Buffer.?[0..(entry.BaseDllName.Length / 2 + 1)].ptr);
            } else {
                skipcount -= 1;
            }
        }
        return;
    }
    pub fn ResolveExports(self: *DllLoader, dll: *Dll) !void {
        // Please cass this funciton after defining BaseAddr of the dll
        const dll_bytes: [*]u8 = dll.BaseAddr;
        const dos_headers: *winc.IMAGE_DOS_HEADER = @ptrCast(@alignCast(dll_bytes));
        const lfanewoffset: usize = @intCast(dos_headers.e_lfanew);
        const nt_headers: *const winc.IMAGE_NT_HEADERS = @ptrCast(@alignCast(dll_bytes[lfanewoffset..]));
        const export_descriptor: *const winc.IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(dll_bytes[nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress..]));
        const NumberOfNames = export_descriptor.NumberOfNames;
        const NumberOfFunctions = export_descriptor.NumberOfFunctions;
        const exportAddressTable: [*]i32 = @ptrCast(@alignCast(dll_bytes[export_descriptor.AddressOfFunctions..]));
        const exportNamePointerTable: [*]i32 = @ptrCast(@alignCast(dll_bytes[export_descriptor.AddressOfNames..]));
        //const exportNameOrdinalTable: [*]i32 = @ptrCast(@alignCast(dll_bytes[export_descriptor.AddressOfNameOrdinals..]));
        dll.NameExports = std.StringHashMap(*void).init(self.Allocator);
        dll.OrdinalExports = std.AutoHashMap(u16, *void).init(self.Allocator);
        const delta = NumberOfFunctions - NumberOfNames;
        // Really stupid ntdll ExportTable with the first entry having no name

        var ordinal: u16 = @intCast(delta);
        for (0..NumberOfNames) |i| {
            const funcname: [*:0]u8 = @ptrCast(dll_bytes[@as(usize, @intCast(exportNamePointerTable[i]))..]);
            try dll.NameExports.putNoClobber(funcname[0..std.mem.len(funcname)], @as(*void, @ptrCast(dll_bytes[@as(usize, @intCast(exportAddressTable[i + delta]))..])));
            try dll.OrdinalExports.putNoClobber(
                ordinal,
                @as(*void, @ptrCast(dll_bytes[@as(usize, @intCast(exportAddressTable[i + delta]))..])),
            );
            ordinal += 1;
        }
    }

    pub fn ReflectiveLoad(self: *DllLoader, libname16_: [:0]const u16) anyerror![*]u8 {
        // get this module's image base address

        // load DLL into memory
        //var libpath16_len: usize = 0;
        //const libpath16: [*c]u16 = @ptrCast(@alignCast(win.kernel32.HeapAlloc(
        //    heap,
        //   winc.HEAP_ZERO_MEMORY,
        //  (while (true) : (libpath16_len += 1) {
        //     if (!(libpath[libpath16_len] != 0 and libpath16_len < 260)) break libpath16_len;
        // } else 260) * 2 + 2,
        //).?));
        //defer _ = win.kernel32.HeapFree(heap, 0, libpath16);
        //clr.u8tou16(libpath, libpath16);
        print("Checkpoint 0 DirtyName \n", .{});
        print16(libname16_);
        const kernel32_s = try lstring(self.Allocator, "KERNEL32.DLL");
        defer self.Allocator.free(kernel32_s);
        const kernel32 = self.LoadedDlls.get(kernel32_s).?.NameExports;

        const ntdll_s = try lstring(self.Allocator, "ntdll.dll");
        defer self.Allocator.free(ntdll_s);
        const ntdll = self.LoadedDlls.get(ntdll_s).?.NameExports;

        var libpath16: [:0]u16 = undefined;
        var shortlibpath16: [:0]u16 = undefined;
        const GetEnvironmentVariable: *const fn ([*:0]u8, [*:0]u8, c_uint) callconv(.C) c_uint = @ptrCast(kernel32.get("GetEnvironmentVariable") orelse return DllError.FuncResolutionFailed);
        const GetFileAttributesA: *const fn ([*:0]u8) c_int = @ptrCast(kernel32.get("GetFileAttributesA") orelse return DllError.FuncResolutionFailed);
        if (clr.isFullPath(libname16_)) |symbol| {
            libpath16 = @constCast(libname16_);
            var start_index: usize = 0;
            for (libpath16, 0..) |item, index| {
                if (item == symbol) {
                    start_index = index + 1;
                }
            }
            shortlibpath16 = libpath16[start_index..];
        } else {
            libpath16 = @ptrCast(try self.Allocator.alloc(u16, 260));
            var PATH: [32767:0]u8 = undefined;
            const len: usize = GetEnvironmentVariable("PATH", PATH.ptr, 32767) + 1;
            //Please kill me this has to be done in u16
            var i: usize = 0;
            var start_pointer: usize = 0;
            var end_pointer: usize = 0;
            while (PATH[i] != 0) : (i += 1) {
                if (PATH[i] == ';') {
                    end_pointer = i;

                    const tmp_str_len = end_pointer - start_pointer + 1 + libname16_.len + 1;
                    var u8searchString = try self.Allocator.alloc(u8, tmp_str_len);
                    std.mem.copyForwards(u8, u8searchString[0 .. end_pointer - start_pointer], PATH[start_pointer..end_pointer]);
                    u8searchString[end_pointer - start_pointer] = '\\';
                    std.mem.copyForwards(
                        u8,
                        u8searchString[end_pointer - start_pointer + 1 .. tmp_str_len],
                    );

                    defer self.Allocator.free(u8searchString);
                    if (GetFileAttributesA(u8searchString.ptr) == winc.INVALID_FILE_ATTRIBUTES) {
                        start_pointer = end_pointer + 1;
                        continue;
                    }
                }
            }

            const newlen = len + 1 + libname16_.len + 1;
            std.mem.copyForwards(u16, libpath16[len + 1 .. newlen], libname16_[0 .. newlen - len - 1]);
            shortlibpath16 = @constCast(libname16_);
        }

        print("Checkpoint 1 WideNames: \n", .{});
        print16(libpath16);
        print16(shortlibpath16);
        var dll_struct: *Dll = try self.Allocator.create(Dll);
        const pathlen = libpath16.len;
        dll_struct.Path = @as([*:0]u16, @ptrCast((try self.Allocator.alloc(u16, pathlen + 1)).ptr));
        std.mem.copyForwards(u16, dll_struct.Path[0..pathlen], libpath16[0..pathlen]);
        const CreateFileW: *const fn ([*:0]const u16, u32, u32, ?*win.SECURITY_ATTRIBUTES, u32, u32, ?*anyopaque) callconv(.C) *anyopaque = @ptrCast(kernel32.get("CreateFileW"));

        const dll_handle = CreateFileW(
            libpath16,
            win.GENERIC_READ,
            0,
            null,
            win.OPEN_EXISTING,
            0,
            null,
        );
        const CloseHandle: *const fn (*anyopaque) callconv(.C) c_int = @ptrCast(kernel32.get("CloseHandle"));
        defer _ = CloseHandle(dll_handle);

        print("Checkpoint 2\n", .{});
        var dll_size_i: i64 = 0;

        const GetFileSizeEx: *const fn (*anyopaque, *i64) callconv(.C) c_int = @ptrCast(kernel32.get("GetFileSizeEx"));
        if ((GetFileSizeEx(dll_handle, &dll_size_i) <= 0)) {
            return DllError.Size;
        }
        const dll_size: usize = @intCast(dll_size_i);
        print("Checkpoint 2.25 size is {d}", .{dll_size});

        const dll_bytes: [*]u8 = (try self.Allocator.alloc(u8, dll_size)).ptr;
        defer _ = self.Allocator.free(dll_bytes[0..dll_size]);

        var bytes_read: winc.DWORD = 0;
        const ReadFile: *const fn (*anyopaque, [*]u8, u32, ?*u32, ?*win.OVERLAPPED) callconv(.C) c_int = @ptrCast(kernel32.get("ReadFile"));
        _ = ReadFile(dll_handle, dll_bytes, @as(u32, @intCast(dll_size)), &bytes_read, null);

        // get pointers to in-memory DLL headers
        const dos_headers: *winc.IMAGE_DOS_HEADER = @ptrCast(@alignCast(dll_bytes));
        const lfanewoffset: usize = @intCast(dos_headers.e_lfanew);
        const nt_headers: *const winc.IMAGE_NT_HEADERS = @ptrCast(@alignCast(dll_bytes[lfanewoffset..]));
        const dll_image_size = nt_headers.OptionalHeader.SizeOfImage;

        // allocate new memory space for the DLL

        // TODO clean stackframe calls to dangerous functions
        const VirtualAlloc: *const fn (i64, *?[*]u8, usize, *usize, u32, u32) callconv(.C) c_int = @ptrCast(ntdll.get("ZwAllocateVirtualMemory"));
        print("Checkpoint 2.5\n", .{});
        var dll_base_dirty: ?[*]u8 = @ptrFromInt(nt_headers.OptionalHeader.ImageBase);
        var virtAllocSize: usize = dll_image_size;

        var ntRes: c_int = VirtualAlloc(
            -1,
            &dll_base_dirty,
            0,
            &virtAllocSize,
            win.MEM_RESERVE | win.MEM_COMMIT,
            win.PAGE_EXECUTE_READWRITE,
        );
        if (ntRes < 0) {
            dll_base_dirty = null;
            ntRes = VirtualAlloc(
                -1,
                &dll_base_dirty,
                0,
                &virtAllocSize,
                win.MEM_RESERVE | win.MEM_COMMIT,
                win.PAGE_EXECUTE_READWRITE,
            );
        }
        const dll_base = dll_base_dirty.?;
        dll_struct.BaseAddr = dll_base;

        print("Checkpoint 4 addr: {*}\n", .{dll_base});
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

        print("Checkpoint 5\n", .{});
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

        print("Checkpoint 6\n", .{});
        // resolve import address table
        var import_descriptor: *const winc.IMAGE_IMPORT_DESCRIPTOR = @ptrCast(@alignCast(dll_base[nt_headers.OptionalHeader.DataDirectory[winc.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress..]));
        while (import_descriptor.Name != 0) {
            const library_name: [*:0]const u8 = @ptrCast(dll_base[import_descriptor.Name..]);
            if (std.mem.len(library_name) == 0) {
                break;
            }
            var library_name16_len: usize = 0;

            //print("Current lib to load: {s}\n", .{library_name});

            var library_name16: [:0]u16 = @ptrCast(try self.Allocator.alloc(
                u16,
                (while (true) : (library_name16_len += 1) {
                    if (!(library_name[library_name16_len] != 0 and library_name16_len < 260)) break library_name16_len;
                } else 260) + 1,
            ));
            library_name16_len += 2;
            //print("Current lib to load: {s} size in u8 {d} in u16 {d}\n", .{ library_name, (library_name16_len - 2) / 2, library_name16_len });
            //defer self.Allocator.free(library_name16);

            clr.u8tou16(library_name, library_name16.ptr, library_name16_len);
            if (!self.LoadedDlls.contains(library_name16[0 .. library_name16_len - 1])) {
                print("Did not found loaded lib {s}, reflective loading... \n", .{library_name});
                _ = try self.ReflectiveLoad(library_name16);
                print("Success\n", .{});
            }
            const library = self.LoadedDlls.get(library_name16[0 .. library_name16_len - 1]).?;
            const library_nameHm = library.NameExports;
            const library_ordinalHm = library.OrdinalExports;

            print("Checkpoint 7\n", .{});
            var thunk: *winc.IMAGE_THUNK_DATA = @ptrCast(@alignCast(dll_base[import_descriptor.FirstThunk..]));
            while (thunk.u1.AddressOfData != 0) {
                if (winc.IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) {
                    const function_ordinal: *u16 = @ptrFromInt(winc.IMAGE_ORDINAL(thunk.u1.Ordinal));
                    thunk.u1.Function = @intFromPtr(library_ordinalHm.get(function_ordinal.*).?);
                } else {
                    const function_name: *const winc.IMAGE_IMPORT_BY_NAME = @ptrCast(@alignCast(dll_base[thunk.u1.AddressOfData..]));
                    const function_name_realname: [*:0]const u8 = @ptrCast(&function_name.Name);
                    thunk.u1.Function = @intFromPtr(library_nameHm.get(function_name_realname[0..std.mem.len(function_name_realname)]).?);
                }
                thunk = @ptrFromInt(@intFromPtr(thunk) + @sizeOf(winc.IMAGE_THUNK_DATA));
            }
            import_descriptor = @ptrFromInt(@intFromPtr(import_descriptor) + @sizeOf(winc.IMAGE_IMPORT_DESCRIPTOR));
            print("Updated import desc {*} val {d}\n", .{ import_descriptor, import_descriptor.Name });
        }

        print("Checkpoint 8\n", .{});
        // execute the loaded DLL
        if (nt_headers.OptionalHeader.AddressOfEntryPoint != 0) {
            const dll_entry: ?*const DLLEntry = @ptrCast(dll_base[nt_headers.OptionalHeader.AddressOfEntryPoint..]);
            const dll_base_hinstance: win.HINSTANCE = @ptrCast(dll_base);
            if (dll_entry) |runnable_entry| {
                print("Running the dll  {*}:\n", .{runnable_entry});
                _ = runnable_entry(dll_base_hinstance, winc.DLL_PROCESS_ATTACH, null);
            }
        }
        try self.ResolveExports(dll_struct);

        print("Checkpoint 9\n", .{});
        try self.LoadedDlls.put(shortlibpath16, dll_struct);
        print("Deffering stuff\n", .{});
        return dll_bytes;
    }
};
