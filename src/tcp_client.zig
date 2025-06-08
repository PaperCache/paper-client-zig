const std = @import("std");
const sheet = @import("sheet.zig");
const PaperError = @import("error.zig").PaperError;

pub const TcpClient = struct {
	_stream: std.net.Stream,

	pub fn init(addr: std.net.Address) PaperError!TcpClient {
		const stream =  std.net.tcpConnectToAddress(addr) catch {
			return PaperError.UnreachableServer;
		};

		return TcpClient {
			._stream = stream,
		};
	}

	pub fn reader(self: *TcpClient) sheet.SheetReader {
		return sheet.SheetReader.init(self);
	}

	pub fn writer(self: *TcpClient) sheet.SheetWriter {
		return sheet.SheetWriter.init(self);
	}

	pub fn close(self: TcpClient) void {
		self._stream.close();
	}
};
