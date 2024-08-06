const std = @import("std");
const builtin = @import("builtin");
const root = @import("root");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const c = std.c;
const Allocator = std.mem.Allocator;
const windows = std.os.windows;

const winc = @import("Windows.h.zig");

pub const HeapAllocator = switch (builtin.os.tag) {
    .windows => struct {
        heap_handle: ?HeapHandle,

        HeapCreate: *const fn (u32, usize, usize) callconv(.C) ?*anyopaque,
        HeapAlloc: *const fn (*anyopaque, u32, usize) callconv(.C) ?*anyopaque,
        HeapReAlloc: *const fn (*anyopaque, u32, *anyopaque, usize) callconv(.C) ?*anyopaque,
        HeapFree: *const fn (*anyopaque, u32, *anyopaque) callconv(.C) c_int,
        HeapDestroy: *const fn (*anyopaque) callconv(.C) c_int,

        const HeapHandle = windows.HANDLE;

        pub fn init(
            HeapCreate: *void,
            HeapAlloc: *void,
            HeapRealloc: *void,
            HeapFree: *void,
            HeapDestroy: *void,
        ) HeapAllocator {
            return HeapAllocator{
                .heap_handle = null,
                .HeapCreate = @ptrCast(HeapCreate),
                .HeapAlloc = @ptrCast(HeapAlloc),
                .HeapReAlloc = @ptrCast(HeapRealloc),
                .HeapFree = @ptrCast(HeapFree),
                .HeapDestroy = @ptrCast(HeapDestroy),
            };
        }

        pub fn allocator(self: *HeapAllocator) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        pub fn deinit(self: *HeapAllocator) void {
            if (self.heap_handle) |heap_handle| {
                self.HeapDestroy(heap_handle);
            }
        }

        fn getRecordPtr(buf: []u8) *align(1) usize {
            return @as(*align(1) usize, @ptrFromInt(@intFromPtr(buf.ptr) + buf.len));
        }

        fn alloc(
            ctx: *anyopaque,
            n: usize,
            log2_ptr_align: u8,
            return_address: usize,
        ) ?[*]u8 {
            _ = return_address;
            const self: *HeapAllocator = @ptrCast(@alignCast(ctx));

            const ptr_align = @as(usize, 1) << @as(Allocator.Log2Align, @intCast(log2_ptr_align));
            const amt = n + ptr_align - 1 + @sizeOf(usize);
            const optional_heap_handle = @atomicLoad(?HeapHandle, &self.heap_handle, .seq_cst);
            const heap_handle = optional_heap_handle orelse blk: {
                const options = 0;
                const hh = self.HeapCreate(options, amt, 0) orelse return null;
                const other_hh = @cmpxchgStrong(?HeapHandle, &self.heap_handle, null, hh, .seq_cst, .seq_cst) orelse break :blk hh;
                _ = self.HeapDestroy(hh);
                break :blk other_hh.?; // can't be null because of the cmpxchg
            };
            const ptr = self.HeapAlloc(heap_handle, 0, amt) orelse return null;
            const root_addr = @intFromPtr(ptr);
            const aligned_addr = mem.alignForward(usize, root_addr, ptr_align);
            const buf = @as([*]u8, @ptrFromInt(aligned_addr))[0..n];
            getRecordPtr(buf).* = root_addr;
            return buf.ptr;
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            new_size: usize,
            return_address: usize,
        ) bool {
            _ = log2_buf_align;
            _ = return_address;
            const self: *HeapAllocator = @ptrCast(@alignCast(ctx));

            const root_addr = getRecordPtr(buf).*;
            const align_offset = @intFromPtr(buf.ptr) - root_addr;
            const amt = align_offset + new_size + @sizeOf(usize);
            const new_ptr = self.HeapReAlloc(
                self.heap_handle.?,
                windows.HEAP_REALLOC_IN_PLACE_ONLY,
                @as(*anyopaque, @ptrFromInt(root_addr)),
                amt,
            ) orelse return false;
            assert(new_ptr == @as(*anyopaque, @ptrFromInt(root_addr)));
            getRecordPtr(buf.ptr[0..new_size]).* = root_addr;
            return true;
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            return_address: usize,
        ) void {
            _ = log2_buf_align;
            _ = return_address;
            const self: *HeapAllocator = @ptrCast(@alignCast(ctx));
            _ = self.HeapFree(self.heap_handle.?, 0, @as(*anyopaque, @ptrFromInt(getRecordPtr(buf).*)));
        }
    },
    else => @compileError("Unsupported OS"),
};
