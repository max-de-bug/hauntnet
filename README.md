# 🎃 HauntNet 👻

![HauntNet](https://postimg.cc/Y4MLMKfN)

> **A peer-to-peer haunted chatroom in Halloween style**

HauntNet is a spooky decentralized chatroom where ghosts and spirits whisper across the network. Built with Rust 🦀, featuring end-to-end encryption, automatic peer discovery, and a Halloween-themed interface.

## ✨ Features

- 🔐 **End-to-End Encryption** - Private whispers encrypted with X25519 key exchange + ChaCha20-Poly1305
- 🌐 **Peer-to-Peer Networking** - No central server, direct peer communication via UDP multicast
- 👻 **Automatic Peer Discovery** - Automatically finds and connects to other ghosts on your network
- 💬 **Broadcast Messages** - Announce your presence to all ghosts in the realm
- 🔒 **Private Whispers** - Send encrypted private messages to specific peers
- 🕯️ **Online Peer List** - See who's haunting the network
- 🎨 **Halloween-Themed UI** - Spooky ASCII art and colorful terminal interface
- ⚡ **Async Architecture** - Built on Tokio for high performance

## 🚀 Quick Start

### Prerequisites

- **Rust** (1.70+ recommended)
- **Windows/Linux/macOS**
- Network access (for peer discovery)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourrepo/hauntnet.git
   cd hauntnet/hauntnet
   ```

2. **Build the project:**

   ```bash
   cargo build --release
   ```

3. **Run HauntNet:**
   ```bash
   cargo run
   # Or use the release binary:
   ./target/release/hauntnet
   ```

## 📖 Usage

### Starting the Application

Simply run:

```bash
cargo run
```

You'll be prompted for a spooky name:

```
🕯️ Please choose your spooky name: GhostRider
🎃 Welcome, GhostRider! The haunt begins… 👻
```

Or specify a name with:

```bash
cargo run -- --name GhostRider
```

### Interactive Commands

Once running, use these commands:

| Command                     | Description                                     | Example                      |
| --------------------------- | ----------------------------------------------- | ---------------------------- |
| `join`                      | Re-announce your presence (auto-joins on start) | `join`                       |
| `say <message>`             | Broadcast message to all ghosts                 | `say Hello everyone!`        |
| `whisper <ghost> <message>` | Send encrypted private message                  | `whisper SpookyGhost Hello!` |
| `list`                      | List all online ghosts                          | `list`                       |
| `vanish`                    | Leave the chat                                  | `vanish`                     |
| `help`                      | Show available commands                         | `help`                       |
| `exit`                      | Exit the program                                | `exit`                       |

### CLI Arguments

```bash
# Start with a specific name
cargo run -- --name "SpookySpectrum"

# List peers (then continues to interactive mode)
cargo run -- list

# Send a whisper from command line
cargo run -- whisper GhostRider "Secret message"
```

## 🔧 How It Works

### Architecture

HauntNet uses a **hybrid networking approach** optimized for Windows:

- **Multicast Discovery (Port 6666)**: Initial peer discovery via UDP multicast
- **Unique Ports**: Each instance binds to a unique OS-assigned port for peer-to-peer communication
- **Direct Communication**: After discovery, peers communicate directly via their unique ports
- **Heartbeat System**: Periodic heartbeats (every 3 seconds) to maintain peer presence
- **Automatic Cleanup**: Stale peers are removed after 30 seconds of inactivity

### Security

- **X25519 Key Exchange**: Elliptic curve Diffie-Hellman for secure key agreement
- **ChaCha20-Poly1305**: Authenticated encryption for message confidentiality
- **Automatic Encryption**: Whispers are automatically encrypted when both peers have public keys
- **Key Derivation**: SHA-256 with domain separation for key derivation

### Message Types

- `Join` - Announce presence with public key and receive port
- `Broadcast` - Public message to all peers
- `Whisper` - Unencrypted private message (fallback)
- `EncryptedWhisper` - Encrypted private message (preferred)
- `Heartbeat` - Keep-alive messages
- `Leave` - Announce departure
- `ListResponse` - Response to list request

## 🛠️ Development

### Project Structure

```
hauntnet/
├── src/
│   ├── main.rs          # Entry point
│   ├── cli.rs           # CLI argument parsing
│   ├── network.rs       # P2P networking and encryption
│   ├── message.rs       # Message types and display
│   └── banner.rs        # ASCII art banner
├── Cargo.toml           # Dependencies
└── README.md            # This file
```

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check code quality
cargo clippy

# Format code
cargo fmt
```

## 🧪 Testing

### Local Testing

1. **Open multiple terminals** on the same machine
2. **Run the app** in each terminal:

   ```bash
   # Terminal 1
   cargo run
   # Enter name: Ghost1

   # Terminal 2
   cargo run
   # Enter name: Ghost2

   # Terminal 3
   cargo run
   # Enter name: Ghost3
   ```

3. **Test commands:**
   ```bash
   # In Terminal 1
   list              # Should show Ghost2 and Ghost3
   say Hello!        # Should appear in Terminals 2 & 3
   whisper Ghost2 Hi # Should appear only in Terminal 2
   ```

### Network Testing

For testing across multiple machines on the same local network:

1. Ensure all machines are on the same subnet
2. Run HauntNet on each machine
3. Peers should automatically discover each other
4. Check firewall settings - allow UDP port 6666 (multicast) and the dynamic ports

## ⚙️ Configuration

### Network Settings

Default configuration (in `src/network.rs`):

- **Multicast IP**: `224.0.0.251` (mDNS multicast)
- **Discovery Port**: `6666`
- **Heartbeat Interval**: `3 seconds`
- **Peer Timeout**: `30 seconds`
- **Buffer Size**: `65536 bytes`

### Customization

To modify network settings, edit constants in `src/network.rs`:

```rust
const BROADCAST_PORT: u16 = 6666;      // Change discovery port
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);  // Adjust heartbeat
const PEER_TIMEOUT: Duration = Duration::from_secs(30);       // Adjust timeout
```

## 🔍 Troubleshooting

### Peers Not Appearing

**Problem**: `list` shows no peers even though other instances are running

**Solutions:**

1. **Wait a few seconds** - Discovery can take 3-10 seconds
2. **Check firewall** - Allow UDP traffic on port 6666
3. **Verify network** - Ensure all instances are on the same network
4. **Try `join` command** - Re-announce your presence

### Whisper Messages Not Received

**Problem**: Whisper sent but recipient doesn't see it

**Solutions:**

1. **Verify peer exists** - Run `list` to confirm peer name
2. **Check name spelling** - Names are case-sensitive
3. **Wait for encryption** - Both peers need to exchange public keys first
4. **Try `join`** - Re-establish connection

### Peers Disappearing After Timeout

**Problem**: Peers appear in `list` but disappear after ~30 seconds

**Cause**: This is normal behavior - peers timeout if no heartbeat is received

**Solutions:**

1. **Peers may have crashed** - Check if other instances are still running
2. **Network issues** - Packets may be dropped
3. **Windows Firewall** - May be blocking heartbeat packets
4. **Adjust timeout** - Increase `PEER_TIMEOUT` if needed

### Windows-Specific Issues

**Problem**: Only one instance receives messages

**Solution**: Already handled! HauntNet uses unique ports to avoid Windows SO_REUSEADDR limitations.

**Problem**: "Access denied" errors when binding

**Solution**: Run as Administrator or allow the app through Windows Firewall.

## 📝 Example Session

```bash
$ cargo run
[ASCII Banner]
🕯️ Please choose your spooky name: GhostRider
🎃 Welcome, GhostRider! The haunt begins… 👻
🧛‍♂️ GhostRider has joined the haunted realm!
🕸️  Listening on unique port 52345 for peer communication
📡 Listening on port 6666 for multicast discovery
🔐 Encryption keys generated
✅ You're now online! Type 'help' to see available commands

👻> list
🕯️ Requesting list of online ghosts...
🕯️  Ghosts online:
  • SpookySpectrum (127.0.0.1:61234)
  • PhantomWhisper (127.0.0.1:58901)

👻> say Hello haunted realm!
🗣️ Message sent to all ghosts...

👻> whisper SpookySpectrum This is a secret!
👻 Whisper sent...
🔒 ✅ Encrypted whisper delivered to SpookySpectrum
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cargo clippy` and `cargo fmt`
5. Submit a pull request

## 📄 License

This project is open source. Check the LICENSE file for details.

## 🙏 Credits

- **Author**: Connor
- **Built with**: Rust, Tokio, X25519, ChaCha20-Poly1305
- **Inspiration**: The spirit of Halloween and P2P networking! 🎃👻

## 🔗 Links

- **Repository**: https://github.com/yourrepo/hauntnet
- **Issues**: Report bugs or request features

---

**Happy Haunting!** 👻🎃💀
