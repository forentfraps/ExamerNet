const std = @import("std");
const ref_dll = @import("Winutils/dll.zig");
const win = std.os.windows;

pub fn main() !void {
    const ptr: [*]u8 = @ptrFromInt(0x180000000);
    _ = try win.VirtualAlloc(
        ptr,
        512,
        win.MEM_RESERVE | win.MEM_COMMIT,
        win.PAGE_EXECUTE_READWRITE,
    );

    std.debug.print("Starting to ref load dll\n", .{});
    _ = ref_dll.DllLoader.getLoadedDLLs();
    std.debug.print("Fin!\n", .{});
}
