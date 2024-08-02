const std = @import("std");
const dll = @import("Winutils/dll.zig");
const clr = @import("Winutils/clr.zig");
const sneaky_memory = @import("Winutils/memory.zig");
const win = std.os.windows;
const lstring = clr.lstring;
pub fn main() !void {
    const ptr: [*]u8 = @ptrFromInt(0x180000000);
    _ = try win.VirtualAlloc(
        ptr,
        512,
        win.MEM_RESERVE | win.MEM_COMMIT,
        win.PAGE_EXECUTE_READWRITE,
    );

    std.debug.print("Starting to ref load dll\n", .{});
    var DllLoader: dll.DllLoader = undefined;
    {
        var tmp_buf: [1024000]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&tmp_buf);
        const sa = fba.allocator();
        DllLoader = dll.DllLoader.init(sa);
        //try dll.ReflectiveLoad(try lstring(sa, "C:\\Windows\\System32\\user32.dll"));
        try DllLoader.getLoadedDlls();
        //try DllLoader.switchAllocator();

        std.debug.print("space used: {d}% leaving scope\n", .{100 * fba.end_index / (1024000)});
    }
    const kernel32 = DllLoader.LoadedDlls.get(try lstring(DllLoader.Allocator, "KERNEL32.DLL")).?.NameExports;
    const ntdll = DllLoader.LoadedDlls.get(try lstring(DllLoader.Allocator, "ntdll.dll")).?.NameExports;
    const pHeapCreate = kernel32.get("HeapCreate") orelse return dll.DllError.FuncResolutionFailed;
    const pHeapAlloc = ntdll.get("RtlAllocateHeap") orelse return dll.DllError.FuncResolutionFailed;
    const pHeapRealloc = ntdll.get("RtlReAllocateHeap") orelse return dll.DllError.FuncResolutionFailed;
    const pHeapFree = ntdll.get("RtlFreeHeap") orelse return dll.DllError.FuncResolutionFailed;
    const pHeapDestroy = ntdll.get("RtlDestroyHeap") orelse return dll.DllError.FuncResolutionFailed;
    var HeapAllocator = sneaky_memory.HeapAllocator.init(pHeapCreate, pHeapAlloc, pHeapRealloc, pHeapFree, pHeapDestroy);
    const newallocator = HeapAllocator.allocator();
    var it = DllLoader.LoadedDlls.keyIterator();
    var newLoadedDlls: dll.u16HashMapType = dll.u16HashMapType.init(newallocator);

    while (true) {
        if (it.next()) |key| {
            const dll_entry = DllLoader.LoadedDlls.get(key.*).?;
            const len = std.mem.len(dll_entry.Path) + 1;
            const newpath: [*:0]u16 = @ptrCast((try newallocator.alloc(u16, len)).ptr);
            var newdll = try newallocator.create(dll.Dll);
            std.mem.copyForwards(u16, newpath[0..len], dll_entry.Path[0..len]);
            newdll.NameExports = try dll_entry.NameExports.cloneWithAllocator(newallocator);
            newdll.OrdinalExports = try dll_entry.OrdinalExports.cloneWithAllocator(newallocator);
            newdll.Path = newpath;
            newdll.BaseAddr = dll_entry.BaseAddr;
            try newLoadedDlls.put(key.*, newdll);
        } else {
            break;
        }
    }
    DllLoader.LoadedDlls = newLoadedDlls;
    DllLoader.Allocator = newallocator;
    DllLoader.HeapAllocator = HeapAllocator;
    const user32_s = try lstring(DllLoader.Allocator, "user32.dll");
    _ = try DllLoader.ReflectiveLoad(@as([:0]const u16, @ptrCast(user32_s)));
    std.debug.print("Scope left fin!\n", .{});
}
