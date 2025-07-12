const std = @import("std");
const tcp = @import("tcp_client.zig");
const PaperError = @import("error.zig").PaperError;
const PaperStats = @import("stats.zig").PaperStats;

const MAX_RECONNECT_ATTEMPTS: u32 = 3;

pub const PaperClient = struct {
	_allocator: std.mem.Allocator,
	_addr: std.net.Address,

	_tcp_client: tcp.TcpClient,

	_auth_token: []u8,
	_has_auth_token: bool,
	_reconnect_attempts: u32,

	pub fn init(
		allocator: std.mem.Allocator,
		paper_addr: []const u8,
	) PaperError!PaperClient {
		const addr = try parseAddr(paper_addr);

		var tcp_client = try tcp.TcpClient.init(addr);
		try handshake(&tcp_client);

		return PaperClient {
			._allocator = allocator,
			._addr = addr,

			._tcp_client = tcp_client,

			._auth_token = undefined,
			._has_auth_token = false,
			._reconnect_attempts = 0,
		};
	}

	pub fn ping(self: *PaperClient) PaperError![]u8 {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.ping)) catch {
			try self.reconnect();
			return self.ping();
		};

		return self.processData();
	}

	pub fn version(self: *PaperClient) PaperError![]u8 {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.version)) catch {
			try self.reconnect();
			return self.version();
		};

		return self.processData();
	}

	pub fn auth(self: *PaperClient, token: []const u8) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.auth)) catch {
			try self.reconnect();
			return self.auth(token);
		};

		try self._tcp_client
			.writer()
			.writeString(token);

		if (self._has_auth_token) {
			self._allocator.free(self._auth_token);
		}

		self._auth_token = self._allocator.dupe(u8, token) catch {
			return PaperError.Internal;
		};

		self._has_auth_token = true;

		return self.process();
	}

	pub fn get(self: *PaperClient, key: []const u8) PaperError![]u8 {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.get)) catch {
			try self.reconnect();
			return self.get(key);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		return self.processData();
	}

	pub fn set(self: *PaperClient, key: []const u8, value: []const u8, maybe_ttl: ?u32) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.set)) catch {
			try self.reconnect();
			return self.set(key, value, maybe_ttl);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		try self._tcp_client
			.writer()
			.writeString(value);

		try self._tcp_client
			.writer()
			.writeU32(maybe_ttl orelse 0);

		return self.process();
	}

	pub fn del(self: *PaperClient, key: []const u8) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.del)) catch {
			try self.reconnect();
			return self.del(key);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		return self.process();
	}

	pub fn has(self: *PaperClient, key: []const u8) PaperError!bool {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.has)) catch {
			try self.reconnect();
			return self.has(key);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		return self.processBool();
	}

	pub fn peek(self: *PaperClient, key: []const u8) PaperError![]u8 {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.peek)) catch {
			try self.reconnect();
			return self.peek(key);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		return self.processData();
	}

	pub fn ttl(self: *PaperClient, key: []const u8, maybe_ttl: ?u32) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.ttl)) catch {
			try self.reconnect();
			return self.ttl(key, maybe_ttl);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		try self._tcp_client
			.writer()
			.writeU32(maybe_ttl orelse 0);

		return self.process();
	}

	pub fn size(self: *PaperClient, key: []const u8) PaperError!u32 {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.size)) catch {
			try self.reconnect();
			return self.size(key);
		};

		try self._tcp_client
			.writer()
			.writeString(key);

		return self.processSize();
	}

	pub fn wipe(self: *PaperClient) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.wipe)) catch {
			try self.reconnect();
			return self.wipe();
		};

		return self.process();
	}

	pub fn resize(self: *PaperClient, cache_size: u64) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.resize)) catch {
			try self.reconnect();
			return self.resize(cache_size);
		};

		try self._tcp_client
			.writer()
			.writeU64(cache_size);

		return self.process();
	}

	pub fn policy(self: *PaperClient, policy_id: []const u8) PaperError!void {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.policy)) catch {
			try self.reconnect();
			return self.policy(policy_id);
		};

		try self._tcp_client
			.writer()
			.writeString(policy_id);

		return self.process();
	}

	pub fn stats(self: *PaperClient) PaperError!PaperStats {
		self._tcp_client.writer().writeU8(@intFromEnum(Command.stats)) catch {
			try self.reconnect();
			return self.stats();
		};

		return self.processStats();
	}

	pub fn disconnect(self: PaperClient) void {
		self._tcp_client.close();
	}

	fn process(self: *PaperClient) PaperError!void {
		const reader = self._tcp_client.reader();
		const is_ok = try reader.readBool();

		if (!is_ok) {
			return self.processError();
		}
	}

	fn processData(self: *PaperClient) PaperError![]u8 {
		const reader = self._tcp_client.reader();
		const is_ok = try reader.readBool();

		if (!is_ok) {
			return self.processError();
		}

		return try reader.readString(self._allocator);
	}

	fn processBool(self: *PaperClient) PaperError!bool {
		const reader = self._tcp_client.reader();
		const is_ok = try reader.readBool();

		if (!is_ok) {
			return self.processError();
		}

		return try reader.readBool();
	}

	fn processSize(self: *PaperClient) PaperError!u32 {
		const reader = self._tcp_client.reader();
		const is_ok = try reader.readBool();

		if (!is_ok) {
			return self.processError();
		}

		return try reader.readU32();
	}

	fn processStats(self: *PaperClient) PaperError!PaperStats {
		const reader = self._tcp_client.reader();
		const is_ok = try reader.readBool();

		if (!is_ok) {
			return self.processError();
		}

		const max_size = try reader.readU64();
		const used_size = try reader.readU64();
		const num_objects = try reader.readU64();

		const total_gets = try reader.readU64();
		const total_sets = try reader.readU64();
		const total_dels = try reader.readU64();

		const miss_ratio = try reader.readF64();

		const num_policies = @as(usize, try reader.readU32());

		const policies = self._allocator.alloc([]u8, num_policies) catch {
			return PaperError.Internal;
		};

		errdefer self._allocator.free(policies);

		for (0..num_policies) |i| {
			policies[i] = try reader.readString(self._allocator);
		}

		const policy_id = try reader.readString(self._allocator);
		const is_auto_policy = try reader.readBool();

		const uptime = try reader.readU64();

		return PaperStats {
			.max_size = max_size,
			.used_size = used_size,
			.num_objects = num_objects,

			.total_gets = total_gets,
			.total_sets = total_sets,
			.total_dels = total_dels,

			.miss_ratio = miss_ratio,

			.policies = policies,

			.policy_id = policy_id,
			.is_auto_policy = is_auto_policy,

			.uptime = uptime,
		};
	}

	fn processError(self: *PaperClient) PaperError {
		const reader = self._tcp_client.reader();
		const code = try reader.readU8();

		if (code == 0) {
			const cache_code = try reader.readU8();

			return switch (cache_code) {
				1 => PaperError.KeyNotFound,

				2 => PaperError.ZeroValueSize,
				3 => PaperError.ExceedingValueSize,

				4 => PaperError.ZeroCacheSize,

				5 => PaperError.UnconfiguredPolicy,
				6 => PaperError.InvalidPolicy,

				else => PaperError.Internal,
			};
		}

		return switch (code) {
			2 => PaperError.MaxConnectionsExceeded,
			3 => PaperError.Unauthorized,

			else => PaperError.Internal,
		};
	}

	fn reconnect(self: *PaperClient) PaperError!void {
		self._reconnect_attempts += 1;

		if (self._reconnect_attempts > MAX_RECONNECT_ATTEMPTS) {
			return PaperError.UnreachableServer;
		}

		self._tcp_client = try tcp.TcpClient.init(self._addr);
		try handshake(&self._tcp_client);

		if (self._has_auth_token) {
			try self.auth(self._auth_token);
		}

		self._reconnect_attempts = 0;
	}
};

pub const PaperPool = struct {
	_clients: []LockableClient,
	_index: usize,
	_index_lock: std.Thread.Mutex,

	pub fn init(
		allocator: std.mem.Allocator,
		paper_addr: []const u8,
		size: usize,
	) PaperError!PaperPool {
		const clients = allocator.alloc(LockableClient, size) catch {
			return PaperError.Internal;
		};

		for (0..size) |i| {
			clients[i] = try LockableClient.init(allocator, paper_addr);
		}

		return PaperPool {
			._clients = clients,
			._index = 0,
			._index_lock = .{},
		};
	}

	pub fn disconnect(self: PaperPool) void {
		for (0..self._clients.len) |i| {
			var c = self._clients[i].lock();
			defer self._clients[i].unlock();

			c.disconnect();
		}
	}

	pub fn auth(self: *PaperPool, token: []const u8) PaperError!void {
		for (0..self._clients.len) |i| {
			var c = self._clients[i].lock();
			defer self._clients[i].unlock();

			try c.auth(token);
		}
	}

	pub fn client(self: *PaperPool) *LockableClient {
		self._index_lock.lock();
		defer self._index_lock.unlock();

		const lockable = &self._clients[self._index];
		self._index = (self._index + 1) % self._clients.len;

		return lockable;
	}
};

pub const LockableClient = struct {
	_client: PaperClient,
	_mutex: std.Thread.Mutex,

	pub fn init(
		allocator: std.mem.Allocator,
		paper_addr: []const u8,
	) PaperError!LockableClient {
		return LockableClient {
			._client = try PaperClient.init(allocator, paper_addr),
			._mutex = .{},
		};
	}

	pub fn lock(self: *LockableClient) *PaperClient {
		self._mutex.lock();
		return &self._client;
	}

	pub fn unlock(self: *LockableClient) void {
		self._mutex.unlock();
	}
};

const Command = enum(u8) {
	ping = 0,
	version = 1,

	auth = 2,

	get = 3,
	set = 4,
	del = 5,

	has = 6,
	peek = 7,
	ttl = 8,
	size = 9,

	wipe = 10,

	resize = 11,
	policy = 12,

	stats = 13,
};

fn handshake(tcp_client: *tcp.TcpClient) PaperError!void {
	const reader = tcp_client.reader();
	const is_ok = try reader.readBool();

	if (!is_ok) {
		return PaperError.UnreachableServer;
	}
}

fn parseAddr(paper_addr: []const u8) PaperError!std.net.Address {
	var buf: [8]u8 = undefined;
	@memcpy(&buf, "paper://");

	if (paper_addr.len < 8 or !std.mem.eql(u8, &buf, paper_addr[0..8])) {
		return PaperError.InvalidAddress;
	}

	var it = std.mem.splitScalar(u8, paper_addr[8..], ':');

	const addr = it.next() orelse return PaperError.InvalidAddress;
	const port_str = it.next() orelse return PaperError.InvalidAddress;

	const port = std.fmt.parseInt(u16, port_str, 10) catch {
		return PaperError.InvalidAddress;
	};

	return std.net.Address.parseIp4(addr, port) catch {
		return PaperError.InvalidAddress;
	};
}

test "init" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();
}

test "ping" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	const res = try client.ping();
	defer allocator.free(res);

	try std.testing.expectEqualStrings("pong", res);
}

test "version" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	const res = try client.version();
	defer allocator.free(res);

	try std.testing.expect(res.len > 0);
}

test "auth" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	// incorrect
	const err_res = client.auth("incorrect_auth_token");
	try std.testing.expectError(PaperError.Unauthorized, err_res);

	// correct
	try client.auth("auth_token");
}

test "get" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	// non-existing
	const err_res = client.get("non-existing");
	try std.testing.expectError(PaperError.KeyNotFound, err_res);

	try client.set("key", "value", null);

	// non-existing
	const ok_res = try client.get("key");
	try std.testing.expectEqualStrings("value", ok_res);
}

test "set" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	// no ttl
	try client.set("key", "value", null);

	// ttl
	try client.set("key", "value", 1);
	const ok_res = try client.get("key");
	try std.testing.expectEqualStrings("value", ok_res);

	std.time.sleep(2 * std.time.ns_per_s);

	const err_res = client.get("key");
	try std.testing.expectError(PaperError.KeyNotFound, err_res);
}

test "del" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();
	try client.set("key", "value", null);

	const ok_res = try client.get("key");
	try std.testing.expectEqualStrings("value", ok_res);

	try client.del("key");

	const err_res = client.get("key");
	try std.testing.expectError(PaperError.KeyNotFound, err_res);
}

test "has" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();
	try client.set("key", "value", null);

	const has_res = try client.has("key");
	try std.testing.expect(has_res);

	try client.del("key");

	const does_not_have_res = try client.has("key");
	try std.testing.expect(!does_not_have_res);
}

test "peek" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	// non-existing
	const err_res = client.peek("non-existing");
	try std.testing.expectError(PaperError.KeyNotFound, err_res);

	try client.set("key", "value", null);

	// non-existing
	const ok_res = try client.peek("key");
	try std.testing.expectEqualStrings("value", ok_res);
}

test "ttl" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();
	try client.set("key", "value", null);

	try client.ttl("key", 3);

	const err_res = client.ttl("non-existent", 3);
	try std.testing.expectError(PaperError.KeyNotFound, err_res);
}

test "size" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();
	try client.set("key", "value", null);

	const ok_res = try client.size("key");
	try std.testing.expect(ok_res > 0);

	const err_res = client.size("non-existent");
	try std.testing.expectError(PaperError.KeyNotFound, err_res);
}

test "wipe" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();
	try client.set("key", "value", null);

	const ok_res = try client.has("key");
	try std.testing.expect(ok_res);

	try client.wipe();

	const err_res = try client.has("key");
	try std.testing.expect(!err_res);
}

test "resize" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	const INITIAL_SIZE = 10 * std.math.pow(u64, 1024, 2);
	const UPDATED_SIZE = 20 * std.math.pow(u64, 1024, 2);

	try client.resize(INITIAL_SIZE);
	try std.testing.expectEqual(INITIAL_SIZE, try getCacheSize(&client));

	try client.resize(UPDATED_SIZE);
	try std.testing.expectEqual(UPDATED_SIZE, try getCacheSize(&client));
}

test "policy" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	const INITIAL_POLICY_ID = "lru";
	const UPDATED_POLICY_ID = "lfu";

	try client.policy(INITIAL_POLICY_ID);
	try std.testing.expectEqualStrings(INITIAL_POLICY_ID, try getCachePolicyId(&client));

	try client.policy(UPDATED_POLICY_ID);
	try std.testing.expectEqualStrings(UPDATED_POLICY_ID, try getCachePolicyId(&client));
}

test "stats" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
	defer client.disconnect();

	try client.auth("auth_token");
	try client.wipe();

	const stats = try client.stats();
	try std.testing.expect(stats.uptime > 0);
}

test "pool" {
	var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
	const allocator = heap.allocator();

	var pool = try PaperPool.init(allocator, "paper://127.0.0.1:3145", 2);
	defer pool.disconnect();

	{
		var lockable = pool.client();
		var client = lockable.lock();
		defer lockable.unlock();

		const res = client.set("hello", "world", null);
		try std.testing.expectError(PaperError.Unauthorized, res);
	}

	try pool.auth("auth_token");

	{
		var lockable = pool.client();
		var client = lockable.lock();
		defer lockable.unlock();

		try client.set("hello", "world", null);
	}
}

fn getCacheSize(client: *PaperClient) PaperError!u64 {
	const stats = try client.stats();
	return stats.max_size;
}

fn getCachePolicyId(client: *PaperClient) PaperError![]u8 {
	const stats = try client.stats();
	return stats.policy_id;
}
