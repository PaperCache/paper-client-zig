pub const PaperStats = struct {
	max_size: u64,
	used_size: u64,
	num_objects: u64,

	total_gets: u64,
	total_sets: u64,
	total_dels: u64,

	miss_ratio: f64,

	policies: [][]u8,

	policy_id: []u8,
	is_auto_policy: bool,

	uptime: u64,
};
