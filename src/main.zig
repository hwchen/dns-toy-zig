const std = @import("std");

const TYPE_A = 1;
const CLASS_IN = 1;
const RECURSION_DESIRED = 1 << 8;

pub fn main() !void {
    var in_buf = try std.BoundedArray(u8, 1024).init(0);
    var rng = std.rand.DefaultPrng.init(1);
    const id = rng.random().int(u16);
    try writeQuery(id, "google.com", TYPE_A, in_buf.writer());

    const AF_INET = std.os.AF.INET;
    const SOCK_DGRAM = std.os.SOCK.DGRAM;
    const sock = try std.os.socket(AF_INET, SOCK_DGRAM, 0);
    defer std.os.closeSocket(sock);

    var addr = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    _ = try std.os.sendto(sock, in_buf.slice(), 0, &addr.any, addr.getOsSockLen());

    var addr_len = addr.getOsSockLen();
    var out_buf: [1024]u8 = undefined;
    const bytes_read = try std.os.recvfrom(sock, &out_buf, 0, &addr.any, &addr_len);
    const out = out_buf[0..bytes_read];

    std.debug.print("{any}", .{std.fmt.fmtSliceHexLower(out)});
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
    var buf = try std.BoundedArray(u8, 1024).init(0);

    try writeQuery(0x8298, "www.example.com", TYPE_A, buf.writer());
    var out_buf: [1024]u8 = undefined;
    try std.testing.expectEqualSlices(u8, buf.slice(), try std.fmt.hexToBytes(&out_buf, "82980100000100000000000003777777076578616d706c6503636f6d0000010001"));
}
