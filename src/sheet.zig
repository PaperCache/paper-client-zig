const std = @import("std");
const tcp = @import("tcp_client.zig");
const PaperError = @import("error.zig").PaperError;

const OK_VALUE: u8 = 33;

pub const SheetReader = struct {
	_tcp_client: *tcp.TcpClient,

	pub fn init(tcp_client: *tcp.TcpClient) SheetReader {
		return SheetReader {
			._tcp_client = tcp_client,
		};
	}

	pub fn readU8(self: SheetReader) PaperError!u8 {
		return self._tcp_client._stream.reader().readByte() catch {
			return PaperError.Internal;
		};
	}

	pub fn readBool(self: SheetReader) PaperError!bool {
		return try self.readU8() == OK_VALUE;
	}

	pub fn readU32(self: SheetReader) PaperError!u32 {
		return self._tcp_client._stream.reader().readInt(u32, std.builtin.Endian.little) catch {
			return PaperError.Internal;
		};
	}

	pub fn readU64(self: SheetReader) PaperError!u64 {
		return self._tcp_client._stream.reader().readInt(u64, std.builtin.Endian.little) catch {
			return PaperError.Internal;
		};
	}

	pub fn readF64(self: SheetReader) PaperError!f64 {
		const int_val = try self.readU64();
		return @bitCast(int_val);
	}

	pub fn readString(self: SheetReader, allocator: std.mem.Allocator) PaperError![]u8 {
		const len = @as(usize, try self.readU32());

		const buf = allocator.alloc(u8, len) catch {
			return PaperError.Internal;
		};

		errdefer allocator.free(buf);

		_ = self._tcp_client._stream.reader().readAll(buf) catch {
			return PaperError.Internal;
		};

		return buf;
	}
};

pub const SheetWriter = struct {
	_tcp_client: *tcp.TcpClient,

	pub fn init(tcp_client: *tcp.TcpClient) SheetWriter {
		return SheetWriter {
			._tcp_client = tcp_client,
		};
	}

	pub fn writeU8(self: SheetWriter, value: u8) PaperError!void {
		_ = self._tcp_client._stream.writer().writeByte(value) catch {
			return PaperError.Internal;
		};
	}

	pub fn writeU32(self: SheetWriter, value: u32) PaperError!void {
		_ = self._tcp_client._stream.writer().writeInt(u32, value, std.builtin.Endian.little) catch {
			return PaperError.Internal;
		};
	}

	pub fn writeU64(self: SheetWriter, value: u64) PaperError!void {
		_ = self._tcp_client._stream.writer().writeInt(u64, value, std.builtin.Endian.little) catch {
			return PaperError.Internal;
		};
	}

	pub fn writeString(self: SheetWriter, value: []const u8) PaperError!void {
		try self.writeU32(@intCast(value.len));

		_ = self._tcp_client._stream.writer().writeAll(value) catch {
			return PaperError.Internal;
		};
	}
};
