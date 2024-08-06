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

pub fn print16(s: anytype) void {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        const c: u8 = @intCast(s[i]);
        std.debug.print("{c}", .{c});
    }
    std.debug.print("\n", .{});
}

pub fn looksLikeAscii(possible_str: []const u8) bool {
    for (possible_str) |c| {
        if (c < ' ' or c > 'z' or c == '@') {
            return false;
        }
    }
    return true;
}

pub fn screwApiSets(possible_apiset: []const u16) bool {
    const pattern: *const [10:0]u8 = "api-ms-win";
    if (possible_apiset.len < 10) {
        return false;
    }

    for (possible_apiset, 0..) |wc, i| {
        if (i >= 9) {
            return true;
        }
        if (wc & 0xff00 != 0) {
            return false;
        }
        const c: u8 = @intCast(wc);
        if (c != pattern[i]) {
            return false;
        }
    }
    return false;
}

pub fn findExportRealName(fname: [*]const u8) ?[]const u8 {
    const len = std.mem.len(@as([*:0]const u8, @ptrCast(fname)));
    for (fname[0..len], 0..) |c, i| {
        if (c == '.') return fname[i + 1 .. len];
    }
    return null;
}
