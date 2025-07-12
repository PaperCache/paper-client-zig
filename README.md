# paper-client-zig

The Zig [PaperCache](https://papercache.io) client. The client supports all commands described in the wire protocol on the homepage.

## Example
```zig
const std = @import("std");
const PaperClient = @import("paper_client").PaperClient;

var heap = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const allocator = heap.allocator();

var client = try PaperClient.init(allocator, "paper://127.0.0.1:3145");
defer client.disconnect();

try client.set("hello", "world", null);
const got = try client.get("hello");
```
