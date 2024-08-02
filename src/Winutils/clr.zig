const std = @import("std");
const win = std.os.windows;

pub fn u8tou16(utf8: [*:0]const u8, utf16: [*:0]u16, len: usize) void {
    for (0..len - 1) |i| {
        utf16[i] = @intCast(utf8[i]);
    }
    utf16[len] = @as(u16, 0);
}

pub fn u16tou8(utf16: [*:0]const u16, utf8: [*:0]u8, len: usize) void {
    for (0..len) |i| {
        utf8[i] = @intCast(utf16[i]);
    }
    utf8[len] = 0;
}

pub fn lstring(allocator: std.mem.Allocator, utf8: anytype) ![]u16 {
    var utf16: [*]u16 = (try allocator.alloc(u16, utf8.len + 1)).ptr;
    for (utf8, 0..) |char, i| {
        utf16[i] = @intCast(char);
    }
    utf16[utf8.len] = 0;
    return utf16[0 .. utf8.len + 1];
}

pub fn slicestr(utf8: anytype) []u8 {
    return utf8[0 .. utf8.len + 1];
}

pub fn isFullPath(utf16: []const u16) ?u16 {
    const fw_slash: u16 = '/';
    const bw_slash: u16 = '\\';

    for (utf16) |item| {
        if (item == fw_slash) return fw_slash;
        if (item == bw_slash) return bw_slash;
    }
    return null;
}
