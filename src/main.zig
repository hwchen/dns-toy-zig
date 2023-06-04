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
    var out_stream = std.io.fixedBufferStream(out);
    const out_rdr = out_stream.reader();

    std.debug.print("{any}\n", .{std.fmt.fmtSliceHexLower(out)});
    std.debug.print("{any}\n", .{DnsHeader.from_reader(out_rdr)});
}

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

test "write query" {
    var buf = try std.BoundedArray(u8, 1024).init(0);

    try writeQuery(0x8298, "www.example.com", TYPE_A, buf.writer());
    var expected_buf: [1024]u8 = undefined;
    try std.testing.expectEqualSlices(u8, buf.slice(), try std.fmt.hexToBytes(&expected_buf, "82980100000100000000000003777777076578616d706c6503636f6d0000010001"));
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

    fn from_reader(rdr: anytype) !DnsHeader {
        return DnsHeader{
            .id = try rdr.readIntBig(u16),
            .flags = try rdr.readIntBig(u16),
            .num_questions = try rdr.readIntBig(u16),
            .num_answers = try rdr.readIntBig(u16),
            .num_authorities = try rdr.readIntBig(u16),
            .num_additionals = try rdr.readIntBig(u16),
        };
    }
};

test "parse header" {
    const response = "`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8";
    var resp_stream = std.io.fixedBufferStream(response);
    const actual = try DnsHeader.from_reader(resp_stream.reader());
    try std.testing.expectEqual(actual, DnsHeader{ .id = 24662, .flags = 33152, .num_questions = 1, .num_answers = 1, .num_authorities = 0, .num_additionals = 0 });
}

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
