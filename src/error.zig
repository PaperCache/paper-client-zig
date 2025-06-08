pub const PaperError = error {
	InvalidAddress,
	UnreachableServer,
	MaxConnectionsExceeded,
	Unauthorized,

	KeyNotFound,

	ZeroValueSize,
	ExceedingValueSize,

	ZeroCacheSize,

	InvalidPolicy,
	UnconfiguredPolicy,

	Internal,
};
