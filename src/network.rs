use crate::message::{Command, EncryptedData, Message, MessageType, PeerInfo, PublicKeyBytes};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

const BUFFER_SIZE: usize = 65536;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const PEER_TIMEOUT: Duration = Duration::from_secs(30);
const BROADCAST_PORT: u16 = 6666; // Spooky port number 🎃
const MULTICAST_ADDR: &str = "224.0.0.251:6666"; // Local multicast

/// Peer-to-peer network manager
pub struct Network {
    socket: Arc<UdpSocket>,
    ghost_name: String,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    command_rx: mpsc::UnboundedReceiver<Command>,
    secret_key: EphemeralSecret,
    public_key: PublicKey,
}

impl Network {
    /// Create a new network instance
    pub async fn new(
        ghost_name: String,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;
        
        let local_addr = socket.local_addr()?;
        println!("🕸️  Listening on {}", local_addr);

        // Generate encryption keys
        let secret_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        println!("🔐 Encryption keys generated");

        Ok(Self {
            socket: Arc::new(socket),
            ghost_name,
            peers: Arc::new(RwLock::new(HashMap::new())),
            command_rx,
            secret_key,
            public_key,
        })
    }

    /// Start the network event loop
    pub async fn run(mut self) {
        let socket = Arc::clone(&self.socket);
        let peers = Arc::clone(&self.peers);
        let ghost_name = self.ghost_name.clone();

        // Spawn message receiver task
        let recv_socket = Arc::clone(&socket);
        let recv_peers = Arc::clone(&peers);
        let recv_name = ghost_name.clone();
        tokio::spawn(async move {
            Self::receive_messages(recv_socket, recv_peers, recv_name).await;
        });

        // Spawn heartbeat task
        let hb_socket = Arc::clone(&socket);
        let hb_peers = Arc::clone(&peers);
        let hb_name = ghost_name.clone();
        tokio::spawn(async move {
            Self::heartbeat_loop(hb_socket, hb_peers, hb_name).await;
        });

        // Handle commands from CLI
        while let Some(command) = self.command_rx.recv().await {
            match command {
                Command::Join => {
                    self.broadcast_message(MessageType::Join {
                        ghost_name: self.ghost_name.clone(),
                        public_key: Some(PublicKeyBytes(self.public_key.to_bytes())),
                    })
                    .await;
                }
                Command::SendBroadcast(content) => {
                    self.broadcast_message(MessageType::Broadcast {
                        from: self.ghost_name.clone(),
                        content,
                    })
                    .await;
                }
                Command::SendWhisper { to, content } => {
                    self.send_whisper(to, content).await;
                }
                Command::ListPeers => {
                    self.list_peers().await;
                }
                Command::Leave => {
                    self.broadcast_message(MessageType::Leave {
                        ghost_name: self.ghost_name.clone(),
                    })
                    .await;
                    break;
                }
            }
        }
    }

    /// Receive and process incoming messages
    async fn receive_messages(
        socket: Arc<UdpSocket>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        current_user: String,
    ) {
        let mut buf = vec![0u8; BUFFER_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    if let Ok(message) = Message::from_bytes(&buf[..len]) {
                        // Update peer information
                        if let Some(peer_name) = Self::extract_peer_name(&message) {
                            if peer_name != current_user {
                                let pub_key = Self::extract_public_key(&message);
                                let mut peers = peers.write().await;
                                peers.insert(
                                    peer_name.clone(),
                                    PeerInfo {
                                        ghost_name: peer_name,
                                        addr,
                                        last_seen: SystemTime::now(),
                                        public_key: pub_key,
                                    },
                                );
                            }
                        }

                        // Display message
                        crate::message::display_message(&message, &current_user);
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving message: {}", e);
                }
            }
        }
    }

    /// Extract peer name from message
    fn extract_peer_name(message: &Message) -> Option<String> {
        match &message.msg_type {
            MessageType::Broadcast { from, .. } => Some(from.clone()),
            MessageType::Whisper { from, .. } => Some(from.clone()),
            MessageType::EncryptedWhisper { from, .. } => Some(from.clone()),
            MessageType::Join { ghost_name, .. } => Some(ghost_name.clone()),
            MessageType::Leave { ghost_name } => Some(ghost_name.clone()),
            MessageType::Heartbeat { from } => Some(from.clone()),
            MessageType::ListRequest { from } => Some(from.clone()),
            _ => None,
        }
    }

    /// Extract public key from message
    fn extract_public_key(message: &Message) -> Option<PublicKeyBytes> {
        match &message.msg_type {
            MessageType::Join { public_key, .. } => public_key.clone(),
            _ => None,
        }
    }

    /// Send heartbeat periodically and clean up stale peers
    async fn heartbeat_loop(
        socket: Arc<UdpSocket>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        ghost_name: String,
    ) {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            // Send heartbeat
            let message = Message::new(MessageType::Heartbeat {
                from: ghost_name.clone(),
            });

            if let Ok(bytes) = message.to_bytes() {
                let broadcast_addr: SocketAddr = MULTICAST_ADDR.parse().unwrap();
                let _ = socket.send_to(&bytes, broadcast_addr).await;
            }

            // Remove stale peers
            let mut peers = peers.write().await;
            let now = SystemTime::now();
            peers.retain(|_, peer| {
                now.duration_since(peer.last_seen)
                    .unwrap_or(Duration::from_secs(0))
                    < PEER_TIMEOUT
            });
        }
    }

    /// Broadcast message to all peers
    async fn broadcast_message(&self, msg_type: MessageType) {
        let message = Message::new(msg_type);

        if let Ok(bytes) = message.to_bytes() {
            // Send to multicast address for discovery
            let broadcast_addr: SocketAddr = MULTICAST_ADDR.parse().unwrap();
            if let Err(e) = self.socket.send_to(&bytes, broadcast_addr).await {
                eprintln!("Failed to send broadcast: {}", e);
                return;
            }

            // Also send directly to known peers
            let peers = self.peers.read().await;
            for peer in peers.values() {
                let _ = self.socket.send_to(&bytes, peer.addr).await;
            }
        }
    }

    /// Send private whisper to specific peer (encrypted if they have a public key)
    async fn send_whisper(&self, to: String, content: String) {
        let peers = self.peers.read().await;

        if let Some(peer) = peers.get(&to) {
            // Try to send encrypted if peer has public key
            if let Some(peer_public_key) = &peer.public_key {
                match self.send_encrypted_whisper(&to, &content, peer_public_key, peer.addr).await
                {
                    Ok(_) => {
                        println!("🔒 ✅ Encrypted whisper delivered to {}", to);
                    }
                    Err(e) => {
                        eprintln!("❌ Encryption failed: {}", e);
                    }
                }
            } else {
                // Fallback to unencrypted
                let message = Message::new(MessageType::Whisper {
                    from: self.ghost_name.clone(),
                    to: to.clone(),
                    content,
                });

                if let Ok(bytes) = message.to_bytes() {
                    if let Err(e) = self.socket.send_to(&bytes, peer.addr).await {
                        eprintln!("Failed to send whisper: {}", e);
                    } else {
                        println!("✅ Whisper delivered to {}", to);
                    }
                }
            }
        } else {
            println!("❌ Ghost '{}' not found in the haunted realm", to);
        }
    }

    /// Send encrypted whisper using x25519 key exchange
    async fn send_encrypted_whisper(
        &self,
        to: &str,
        content: &str,
        peer_public_key: &PublicKeyBytes,
        peer_addr: SocketAddr,
    ) -> Result<(), String> {
        // Convert peer's public key
        let their_public = PublicKey::from(peer_public_key.0);

        // Compute shared secret
        let shared_secret = self.secret_key.diffie_hellman(&their_public);

        // Encrypt message
        let encrypted = encrypt_message(content, &shared_secret)?;

        // Send encrypted whisper
        let message = Message::new(MessageType::EncryptedWhisper {
            from: self.ghost_name.clone(),
            to: to.to_string(),
            encrypted,
        });

        if let Ok(bytes) = message.to_bytes() {
            self.socket
                .send_to(&bytes, peer_addr)
                .await
                .map_err(|e| format!("Failed to send: {}", e))?;
        }

        Ok(())
    }

    /// List all online peers
    async fn list_peers(&self) {
        let peers = self.peers.read().await;
        let peer_list: Vec<PeerInfo> = peers.values().cloned().collect();

        let message = Message::new(MessageType::ListResponse { peers: peer_list });
        crate::message::display_message(&message, &self.ghost_name);
    }
}

/// Encrypt plaintext using shared secret
fn encrypt_message(plaintext: &str, shared_secret: &SharedSecret) -> Result<EncryptedData, String> {
    // Derive encryption key from shared secret
    let key = derive_key(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key.into());

    // Generate random nonce
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt ciphertext using shared secret
pub fn decrypt_message(
    encrypted: &EncryptedData,
    shared_secret: &SharedSecret,
) -> Result<String, String> {
    // Derive encryption key from shared secret
    let key = derive_key(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key.into());

    // Decrypt
    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

/// Derive a 256-bit key from shared secret using SHA-256
fn derive_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"hauntnet-encryption-v1"); // Domain separation
    hasher.finalize().into()
}