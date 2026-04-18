# AVM (Astrolune Virtual Machine)

A standalone, reusable Rust execution environment designed for secure, isolated compute tasks.

## Overview

AVM is a Rust-first virtual machine providing secure isolated execution with a clean runtime interface, plugin architecture, and optional IPC-based integration. It can be embedded as a submodule in other projects like ACP.

## Architecture

### Crate Structure

```
avm/
├── avm-core/          # Core traits and types
├── avm-runtime/       # Runtime implementation
├── avm-sandbox/       # Sandbox and resource limits
├── avm-plugin/        # Plugin system
└── avm-ipc/          # IPC integration
```

### Core Components

#### 1. Runtime (`avm-core::Runtime`)
- Lifecycle management (start, shutdown)
- Executor registration
- Graceful shutdown with configurable timeout
- Handle-based access

#### 2. Executor (`avm-core::Executor`)
- Task execution interface
- Cancellation support
- Context-based execution with timeout and memory limits

#### 3. Sandbox (`avm-sandbox::Sandbox`)
- Memory allocation limits via semaphore-based tracking
- Filesystem access control with root restrictions
- Network access control
- Resource violation detection

#### 4. Plugin System (`avm-plugin::PluginRegistry`)
- Dynamic plugin registration
- Metadata-based discovery
- Async initialization/shutdown

#### 5. IPC (`avm-ipc`)
- Unix socket-based communication (Unix platforms)
- Message-based protocol
- Client/server architecture

### Configuration Model

```rust
Config {
    sandbox: SandboxConfig {
        max_memory_bytes: 512MB,
        max_cpu_time: 30s,
        max_wall_time: 60s,
        allow_network: false,
        allow_filesystem: false,
        filesystem_root: Option<String>,
    },
    runtime: RuntimeConfig {
        worker_threads: 4,
        max_blocking_threads: 512,
        shutdown_timeout: 10s,
    },
    telemetry: TelemetryConfig {
        enabled: true,
        log_level: "info",
    },
}
```

## Integration with ACP

### As Git Submodule

```bash
cd ACP
git submodule add https://github.com/astrolune/avm.git
git submodule update --init --recursive
```

### In ACP's Cargo.toml

```toml
[dependencies]
avm-core = { path = "avm/avm-core" }
avm-runtime = { path = "avm/avm-runtime" }
avm-sandbox = { path = "avm/avm-sandbox" }
```

### Usage Example

```rust
use avm_core::{Config, Runtime};
use avm_runtime::AvmRuntime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = AvmRuntime::new();
    let config = Config::default();
    
    runtime.start(config).await?;
    
    // Register executors, run tasks...
    
    runtime.shutdown().await?;
    Ok(())
}
```

## Security Model

### Sandbox Boundaries

1. **Memory Isolation**: Semaphore-based memory allocation tracking
2. **Filesystem Isolation**: Path-based access control with root restrictions
3. **Network Isolation**: Explicit allow/deny for network access
4. **Time Limits**: CPU time and wall-clock time enforcement
5. **No Custom Crypto**: Uses standard Rust crypto libraries
6. **No Security Through Obscurity**: Open, auditable design

### Error Handling

- Recoverable errors: Timeout, ResourceLimit, Execution
- Non-recoverable errors: SandboxViolation, Runtime, Config
- All errors implement `std::error::Error`

## Telemetry

Telemetry hooks for monitoring:
- Runtime lifecycle events
- Execution start/completion
- Resource limit violations
- Error events

## Testing

### Test Categories

1. **Unit Tests**: Per-module functionality
2. **Integration Tests**: Cross-crate interactions
3. **Security Tests**: Sandbox violation detection
4. **Property Tests**: Resource limit enforcement

### Running Tests

```bash
cargo test --workspace
cargo test --workspace -- --nocapture  # With output
```

## MVP Version

### Scope
- Basic runtime lifecycle
- Single executor support
- Memory and time limits
- Filesystem access control
- Synchronous execution model

### Timeline
- 2-3 weeks for core implementation
- 1 week for testing and documentation

### Limitations
- No plugin system
- No IPC integration
- Basic telemetry (logging only)
- Single-threaded execution

## Production-Ready Version

### Additional Features
- Multi-executor support
- Plugin system with dynamic loading
- IPC-based integration
- Advanced telemetry (metrics, tracing)
- Async execution with cancellation
- Resource pooling
- Hot reload support

### Timeline
- 6-8 weeks total
- 4 weeks for feature implementation
- 2 weeks for security audit
- 2 weeks for performance optimization

### Production Requirements
- Comprehensive test coverage (>80%)
- Security audit by external team
- Performance benchmarks
- Production deployment guide
- Monitoring and alerting setup

## Known Limitations

### Current Implementation
1. **Platform Support**: IPC only works on Unix platforms
2. **Memory Tracking**: Semaphore-based tracking is approximate
3. **CPU Time**: No actual CPU time enforcement (requires OS-level support)
4. **Process Isolation**: No process-level isolation (same process space)

### Future Improvements
1. **Windows Support**: Named pipes for IPC
2. **Process Isolation**: Fork-based or container-based isolation
3. **CPU Enforcement**: cgroups or OS-specific APIs
4. **WASM Support**: WebAssembly-based execution
5. **Distributed Execution**: Multi-node task distribution

## Dependencies

- `tokio`: Async runtime
- `serde`/`serde_json`: Serialization
- `tracing`: Structured logging
- `thiserror`: Error handling
- `async-trait`: Async trait support

## License

- Apache License, Version 2.0 ([LICENSE](LICENSE))

## Contributing

See CONTRIBUTING.md for guidelines.
