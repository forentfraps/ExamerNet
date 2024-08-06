const std = @import("std");

pub const Logger = struct {
    current_context: u128,
    enabled: bool,
    colour_crit: LoggerColour,
    colour_info: LoggerColour,
    pref_list: []const []const u8,
    //prefix_interface shound implement method .get to resolve the prefix

    pub fn init(comptime sz: usize, comptime pref_list: [sz][]const u8) @This() {
        return .{
            .current_context = 0,
            .enabled = true,
            .colour_crit = LoggerColour.red,
            .colour_info = LoggerColour.blue,
            .pref_list = &pref_list,
        };
    }

    pub fn info(self: @This(), comptime msg: []const u8, args: anytype) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext(); // Ensure the context index is within bounds
        const prefix = self.pref_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;

        std.debug.print("{s}[{s}] {s}{s}", .{ self.colour_info.getAnsiCode(), prefix, formatted_msg, LoggerColour.getReset() });
    }
    pub fn crit(self: @This(), comptime msg: []const u8, args: anytype) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext(); // Ensure the context index is within bounds
        const prefix = self.pref_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;

        std.debug.print("{s}->[{s}]<- {s}{s}", .{ self.colour_crit.getAnsiCode(), prefix, formatted_msg, LoggerColour.getReset() });
    }

    pub fn setContext(self: *@This(), ctx: anytype) void {
        self.current_context = self.current_context << 4 | @as(u128, @intFromEnum(ctx));
    }

    pub fn rollbackContext(self: *@This()) void {
        self.current_context >>= 8;
    }

    pub fn getContext(self: @This()) usize {
        const current_context_decoded: usize = @intCast(@as(u4, @truncate(self.current_context)));
        return current_context_decoded;
    }
};

pub const LoggerColour = enum {
    red,
    blue,
    green,
    none,

    pub fn getAnsiCode(self: @This()) []const u8 {
        return switch (self) {
            .red => "\x1b[37;41m",
            .blue => "\x1b[37;44m",
            .green => "\x1b[37;42m",
            .none => "\x1b[0;0m",
        };
    }
    pub fn getReset() []const u8 {
        return "\x1b[0;0m";
    }
};
