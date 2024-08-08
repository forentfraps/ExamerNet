const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = std.builtin.OptimizeMode.Debug;
    const exe = b.addExecutable(.{
        .name = "ExamerNet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = std.process.Child.run(.{
        .argv = &[_][]const u8{
            "nasm",
            "-f",
            "win64",
            "src\\Winutils\\utils.asm",
            "-o",
            ".zig-cache\\asm_files\\utils.o",
        },
        .allocator = std.heap.page_allocator,
    }) catch |e| {
        std.debug.print("Asm build failed -> {}\n", .{e});
        return;
    };
    exe.addObjectFile(b.path(".zig-cache\\asm_files\\utils.o"));

    // b.addObject(.{
    //    .name = "utils obj",
    //    .root_source_file = b.path("src\\Winutils\\utils.o"),
    //    .target = target,
    //    .optimize = optimize,
    //});

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
