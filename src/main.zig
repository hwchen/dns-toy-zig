const std = @import("std");

const TYPE_A = 1;
const CLASS_IN = 1;
const RECURSION_DESIRED = 1 << 8;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var rng = std.rand.DefaultPrng.init(1);
    const id = rng.random().int(u16);

    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();

    try writeQuery(id, "google.com", TYPE_A, buf.writer());

    std.debug.print("{}\n", .{std.fmt.fmtSliceHexLower(buf.items)});
}

// Returns number of bytes written
fn writeQuery(id: u16, domain_name: []const u8, record_type: u16, wtr: anytype) !void {
    const header = DnsHeader{
        .id = id,
        .flags = RECURSION_DESIRED,
        .num_questions = 1,
    };
    const question = DnsQuestion{
        .name = domain_name,
        .type = record_type,
        .class = CLASS_IN,
    };

    try header.write_bytes(wtr);
    try question.write_bytes(wtr);
}

const DnsHeader = struct {
    id: u16,
    flags: u16,
    num_questions: u16 = 0,
    num_answers: u16 = 0,
    num_authorities: u16 = 0,
    num_additionals: u16 = 0,

    fn write_bytes(self: DnsHeader, wtr: anytype) !void {
        try wtr.writeIntBig(u16, self.id);
        try wtr.writeIntBig(u16, self.flags);
        try wtr.writeIntBig(u16, self.num_questions);
        try wtr.writeIntBig(u16, self.num_answers);
        try wtr.writeIntBig(u16, self.num_authorities);
        try wtr.writeIntBig(u16, self.num_additionals);
    }
};

const DnsQuestion = struct {
    name: []const u8,
    type: u16,
    class: u16,

    fn write_bytes(self: DnsQuestion, wtr: anytype) !void {
        var parts = std.mem.tokenize(u8, self.name, ".");

        while (parts.next()) |part| {
            const len = @intCast(u8, part.len); // Note: undefined behavior if cast fails
            try (wtr.writeIntBig(u8, len));
            try (wtr.writeAll(part));
        }
        try wtr.writeIntBig(u8, 0);
        try wtr.writeIntBig(u16, self.type);
        try wtr.writeIntBig(u16, self.class);
    }
};

test writeQuery {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeQuery(0x8298, "www.example.com", TYPE_A, buf.writer());
    var out_buf: [1024]u8 = undefined;
    try std.testing.expectEqualSlices(u8, buf.items, try std.fmt.hexToBytes(&out_buf, "82980100000100000000000003777777076578616d706c6503636f6d0000010001"));
}
