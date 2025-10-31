use std::io::{self, Write};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::sync::mpsc;
use colored::*;

/// Public key wrapper for x25519 keys (32 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBytes(pub [u8; 32]);

/// Encrypted message data with nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Message types for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    /// Broadcast message to all peers
    Broadcast {
        from: String,
        content: String,
    },
    /// Private message to specific peer
    Whisper {
        from: String,
        to: String,
        content: String,
    },
    /// Encrypted private message
    EncryptedWhisper {
        from: String,
        to: String,
        encrypted: EncryptedData,
    },
    /// Announce joining the network
    Join {
        ghost_name: String,
        public_key: Option<PublicKeyBytes>,
    },
    /// Request list of online peers
    ListRequest {
        from: String,
    },
    /// Response with list of peers
    ListResponse {
        peers: Vec<PeerInfo>,
    },
    /// Announce leaving the network
    Leave {
        ghost_name: String,
    },
    /// Heartbeat to keep connection alive
    Heartbeat {
        from: String,
    },
}

/// Information about a peer in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub ghost_name: String,
    pub addr: SocketAddr,
    pub last_seen: SystemTime,
    pub public_key: Option<PublicKeyBytes>,
}

/// Complete message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub msg_type: MessageType,
    pub timestamp: SystemTime,
}

impl Message {
    pub fn new(msg_type: MessageType) -> Self {
        Self {
            msg_type,
            timestamp: SystemTime::now(),
        }
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Channel for sending commands from CLI to network
pub enum Command {
    SendBroadcast(String),
    SendWhisper { to: String, content: String },
    Join,
    ListPeers,
    Leave,
}

/// Starts the interactive command loop for the chat
pub async fn start_interactive_loop(
    spooky_name: String,
    command_tx: mpsc::UnboundedSender<Command>,
) {
    println!("\nType 'help' to see available commands");
    
    let mut input = String::new();
    loop {
        print!("👻> ");
        io::stdout().flush().unwrap();
        
        input.clear();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input.");
            continue;
        }
        
        let input = input.trim();
        let mut parts = input.split_whitespace();
        let command = match parts.next() {
            Some(cmd) => cmd.to_lowercase(),
            None => continue, // Empty input
        };

        match command.as_str() {
            "join" => {
                if command_tx.send(Command::Join).is_ok() {
                    println!("🎃 Joining the haunted network...");
                } else {
                    eprintln!("Failed to send join command");
                }
            }
            "say" | "broadcast" => {
                let message = parts.collect::<Vec<_>>().join(" ");
                if message.is_empty() {
                    println!("Usage: say <message>");
                } else if command_tx.send(Command::SendBroadcast(message)).is_ok() {
                    println!("🗣️ Message sent to all ghosts...");
                } else {
                    eprintln!("Failed to send message");
                }
            }
            "whisper" => {
                let to = parts.next().unwrap_or("").to_string();
                let content = parts.collect::<Vec<_>>().join(" ");
                if to.is_empty() || content.is_empty() {
                    println!("Usage: whisper <ghost_name> <message>");
                } else if command_tx.send(Command::SendWhisper { to, content }).is_ok() {
                    println!("👻 Whisper sent...");
                } else {
                    eprintln!("Failed to send whisper");
                }
            }
            "list" => {
                if command_tx.send(Command::ListPeers).is_ok() {
                    println!("🕯️ Requesting list of online ghosts...");
                } else {
                    eprintln!("Failed to request peer list");
                }
            }
            "vanish" | "leave" => {
                if command_tx.send(Command::Leave).is_ok() {
                    println!("👋 Poof! You vanish into the mist...");
                }
                break;
            }
            "help" => print_help(),
            "exit" => {
                let _ = command_tx.send(Command::Leave);
                println!("👋 Farewell, {}! Until next haunting...", spooky_name);
                break;
            }
            _ => println!("💀 Unknown command. Type 'help' for available commands."),
        }
        println!();
    }
}

/// Prints the help message with available commands
fn print_help() {
    println!("\n🎃 Available commands:");
    println!("  {} - Join the haunted network", "join".bright_cyan());
    println!("  {} - Broadcast message to all ghosts", "say <message>".bright_cyan());
    println!("  {} - Send private message", "whisper <ghost> <message>".bright_cyan());
    println!("  {} - List online ghosts", "list".bright_cyan());
    println!("  {} - Leave the chat", "vanish".bright_cyan());
    println!("  {} - Show this help", "help".bright_cyan());
    println!("  {} - Exit the program", "exit".bright_cyan());
}

/// Display received message
pub fn display_message(msg: &Message, current_user: &str) {
    match &msg.msg_type {
        MessageType::Broadcast { from, content } => {
            if from != current_user {
                println!(
                    "\n🗣️  {} {}: {}",
                    "[".bright_black(),
                    from.bright_magenta().bold(),
                    content.bright_white()
                );
                print!("👻> ");
                io::stdout().flush().unwrap();
            }
        }
        MessageType::Whisper { from, to, content } => {
            if to == current_user {
                println!(
                    "\n👻 {} whispers to you: {}",
                    from.bright_magenta().italic(),
                    content.bright_cyan().italic()
                );
                print!("👻> ");
                io::stdout().flush().unwrap();
            }
        }
        MessageType::Join { ghost_name, .. } => {
            if ghost_name != current_user {
                println!(
                    "\n🎃 {} has entered the haunted realm!",
                    ghost_name.bright_green().bold()
                );
                print!("👻> ");
                io::stdout().flush().unwrap();
            }
        }
        MessageType::EncryptedWhisper { from, to, .. } => {
            if to == current_user {
                println!(
                    "\n🔒 {} sent you an encrypted whisper",
                    from.bright_magenta().italic()
                );
                print!("👻> ");
                io::stdout().flush().unwrap();
            }
        }
        MessageType::Leave { ghost_name } => {
            if ghost_name != current_user {
                println!(
                    "\n👋 {} has vanished into the mist...",
                    ghost_name.bright_black().italic()
                );
                print!("👻> ");
                io::stdout().flush().unwrap();
            }
        }
        MessageType::ListResponse { peers } => {
            println!("\n🕯️  {} online:", "Ghosts".bright_yellow().bold());
            if peers.is_empty() {
                println!("  👻 No other ghosts detected...");
            } else {
                for peer in peers {
                    println!("  • {} ({})", peer.ghost_name.bright_magenta(), peer.addr);
                }
            }
            print!("👻> ");
            io::stdout().flush().unwrap();
        }
        _ => {} // Ignore other message types for display
    }
}