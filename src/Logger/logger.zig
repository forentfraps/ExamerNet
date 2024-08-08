const std = @import("std");

pub const Logger = struct {
    current_context: u128,
    enabled: bool,
    colour_crit: LoggerColour,
    colour_info: LoggerColour,
    pref_list: []const []const u8,
    colour_list: []LoggerColour, // Added colour_list

    pub fn init(comptime sz: usize, comptime pref_list: [sz][]const u8, comptime colour_list: [sz]LoggerColour) @This() {
        return .{
            .current_context = 0,
            .enabled = true,
            .colour_crit = LoggerColour.red,
            .colour_info = LoggerColour.blue,
            .pref_list = &pref_list,
            .colour_list = @constCast(&colour_list),
        };
    }

    pub fn info(self: @This(), comptime msg: []const u8, args: anytype) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext();
        const prefix = self.pref_list[context_index];
        const colour = self.colour_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;

        std.debug.print("{s}[{s}] {s}{s}", .{ colour.getAnsiCode(), prefix, formatted_msg, LoggerColour.getReset() });
    }

    pub fn crit(self: @This(), comptime msg: []const u8, args: anytype) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext();
        const prefix = self.pref_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;

        std.debug.print("{s}[{s}]{s}{s}", .{ LoggerColour.getCrit(), prefix, formatted_msg, LoggerColour.getReset() });
    }
    pub fn info16(self: @This(), comptime msg: []const u8, args: anytype, arg16: []const u16) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext();
        const prefix = self.pref_list[context_index];
        const colour = self.colour_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;

        std.debug.print("{s}[{s}] {s} -> ", .{ colour.getAnsiCode(), prefix, formatted_msg });
        for (0..arg16.len) |i| {
            std.debug.print("{u}", .{arg16[i]});
        }
        std.debug.print("{s}\n", .{LoggerColour.getReset()});
    }

    pub fn crit16(self: @This(), comptime msg: []const u8, args: anytype, arg16: []const u16) void {
        if (!self.enabled) {
            return;
        }
        const context_index = self.getContext();
        const prefix = self.pref_list[context_index];
        var buf: [256]u8 = undefined;
        const formatted_msg = std.fmt.bufPrint(&buf, msg, args) catch return;
        std.debug.print("{s} [{s}] {s} -> ", .{ LoggerColour.getCrit(), prefix, formatted_msg });
        for (0..arg16.len) |i| {
            std.debug.print("{u}", .{arg16[i]});
        }
        std.debug.print("{s}\n", .{LoggerColour.getReset()});
    }

    pub fn setContext(self: *@This(), ctx: anytype) void {
        self.current_context = self.current_context << 4 | @as(u128, @intFromEnum(ctx));
    }

    pub fn rollbackContext(self: *@This()) void {
        self.current_context >>= 4;
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
    white,
    pink,
    yellow,
    cyan,
    none,

    pub fn getAnsiCode(self: @This()) []const u8 {
        return switch (self) {
            .red => "\x1b[31;40m",
            .blue => "\x1b[34;40m",
            .green => "\x1b[32;40m",
            .white => "\x1b[37;40m",
            .cyan => "\x1b[36;40m",
            .pink => "\x1b[35;40m",
            .yellow => "\x1b[33;40m",
            .none => "\x1b[0;0m",
        };
    }

    pub fn getCrit() []const u8 {
        return "\x1b[37;41m";
    }
    pub fn getReset() []const u8 {
        return "\x1b[0;0m";
    }
};
