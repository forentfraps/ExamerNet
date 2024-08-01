const std = @import("std");
const win = std.os.windows;

pub fn u8tou16(utf8: [*:0]const u8, utf16: [*:0]u16) void {
    const len = std.mem.len(utf8);
    for (0..len) |i| {
        utf16[i] = @intCast(utf8[i]);
    }
    utf16[len] = 0;
}

pub fn u16tou8(utf16: [*:0]const u16, utf8: [*:0]u8) void {
    const len = std.mem.len(utf16);
    for (0..len) |i| {
        utf8[i] = @intCast(utf16[i]);
    }
    utf8[len] = 0;
}
