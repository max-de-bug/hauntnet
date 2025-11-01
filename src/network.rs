use crate::message::{Command, EncryptedData, Message, MessageType, PeerInfo, PublicKeyBytes};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305
};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};

const BUFFER_SIZE: usize = 65536;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const PEER_TIMEOUT: Duration = Duration::from_secs(60); 
const BROADCAST_PORT: u16 = 6666;
const MULTICAST_IP: &str = "224.0.0.251";

/// Peer-to-peer network manager
pub struct Network {
    unique_socket: Arc<UdpSocket>,
    multicast_socket: Arc<UdpSocket>,
    send_socket: Arc<UdpSocket>,
    ghost_name: String,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    command_rx: mpsc::UnboundedReceiver<Command>,
    secret_key: StaticSecret,
    public_key: PublicKey,
    receive_port: u16,
}

impl Network {
    pub async fn new(
        ghost_name: String,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create socket with socket2 to set options before binding
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        
        // Create socket for unique port (peer-to-peer communication)
        let unique_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let unique_addr: SocketAddr = ([0, 0, 0, 0], 0).into();
        unique_socket.bind(&unique_addr.into())?;
        unique_socket.set_nonblocking(true)?;
        let std_unique_socket: std::net::UdpSocket = unique_socket.into();
        let unique_tokio_socket = UdpSocket::from_std(std_unique_socket)?;
        let receive_port = unique_tokio_socket.local_addr()?.port();
        
        // Create separate socket for multicast discovery (bound to shared port 6666)
        socket.set_reuse_address(true)?;
        let multicast_bind_addr: SocketAddr = ([0, 0, 0, 0], BROADCAST_PORT).into();
        socket.bind(&multicast_bind_addr.into())?;
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        
        // Configure multicast settings
        let multicast_addr: std::net::Ipv4Addr = MULTICAST_IP.parse()?;
        std_socket.set_multicast_loop_v4(true)?;
        std_socket.set_multicast_ttl_v4(1)?;
        std_socket.set_broadcast(true)?;
        std_socket.join_multicast_v4(&multicast_addr, &std::net::Ipv4Addr::UNSPECIFIED)?;
        
        // Convert multicast socket to tokio
        let multicast_socket = UdpSocket::from_std(std_socket)?;
        
        // Create separate socket for sending
        let send_socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Generate encryption keys
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);

        Ok(Self {
            unique_socket: Arc::new(unique_tokio_socket),
            multicast_socket: Arc::new(multicast_socket),
            send_socket: Arc::new(send_socket),
            ghost_name,
            peers: Arc::new(RwLock::new(HashMap::new())),
            command_rx,
            secret_key,
            public_key,
            receive_port,
        })
    }

    /// Start the network event loop
    pub async fn run(mut self) {
        let peers = Arc::clone(&self.peers);
        let ghost_name = self.ghost_name.clone();

        // Spawn message receiver task for unique port (peer communication)
        let unique_socket = Arc::clone(&self.unique_socket);
        let recv_send_socket = Arc::clone(&self.send_socket);
        let recv_peers = Arc::clone(&peers);
        let recv_name = ghost_name.clone();
        let recv_secret = StaticSecret::from(self.secret_key.to_bytes());
        let recv_public_key = PublicKeyBytes(self.public_key.to_bytes());
        let recv_port = self.receive_port;
        tokio::spawn(async move {
            Self::receive_messages(unique_socket, recv_send_socket, recv_peers, recv_name, recv_secret, recv_public_key, recv_port).await;
        });
        
        // Spawn multicast receiver task for discovery (port 6666)
        let multicast_socket = Arc::clone(&self.multicast_socket);
        let multicast_send_socket = Arc::clone(&self.send_socket);
        let multicast_peers = Arc::clone(&peers);
        let multicast_name = ghost_name.clone();
        let multicast_secret = StaticSecret::from(self.secret_key.to_bytes());
        let multicast_public_key = PublicKeyBytes(self.public_key.to_bytes());
        let multicast_port = self.receive_port;
        tokio::spawn(async move {
            Self::receive_messages(multicast_socket, multicast_send_socket, multicast_peers, multicast_name, multicast_secret, multicast_public_key, multicast_port).await;
        });

        // Spawn heartbeat task
        let hb_send_socket = Arc::clone(&self.send_socket);
        let hb_peers = Arc::clone(&peers);
        let hb_name = ghost_name.clone();
        let hb_public_key = self.public_key;
        let hb_receive_port = self.receive_port;
        tokio::spawn(async move {
            Self::heartbeat_loop(hb_send_socket, hb_peers, hb_name, hb_public_key, hb_receive_port).await;
        });

        // Auto-join: Announce presence to network immediately
        println!("🎃 Announcing presence to the haunted network...");
        self.broadcast_message(MessageType::Join {
            ghost_name: self.ghost_name.clone(),
            public_key: Some(PublicKeyBytes(self.public_key.to_bytes())),
            receive_port: Some(self.receive_port),
        })
        .await;

        // Handle commands from CLI
        while let Some(command) = self.command_rx.recv().await {
            match command {
                Command::Join => {
                    self.broadcast_message(MessageType::Join {
                        ghost_name: self.ghost_name.clone(),
                        public_key: Some(PublicKeyBytes(self.public_key.to_bytes())),
                        receive_port: Some(self.receive_port),
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
        send_socket: Arc<UdpSocket>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        current_user: String,
        secret_key: StaticSecret,
        public_key: PublicKeyBytes,
        receive_port: u16,
    ) {
        let mut buf = vec![0u8; BUFFER_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    if let Ok(mut message) = Message::from_bytes(&buf[..len]) {
                        // Extract peer info
                        let peer_name = match Self::extract_peer_name(&message) {
                            Some(name) if name != current_user => name,
                            _ => continue,
                        };

                        // Determine if this is a new peer (before updating)
                        let is_new_peer = {
                            let peers_read = peers.read().await;
                            !peers_read.contains_key(&peer_name)
                        };

                        // Update peer info for ALL message types (not just Join)
                        // This keeps peers alive even if heartbeats are missed
                        let peer_port = Self::extract_receive_port(&message)
                            .unwrap_or_else(|| addr.port());
                        let peer_addr = SocketAddr::new(addr.ip(), peer_port);
                        let pub_key = Self::extract_public_key(&message);

                        {
                            let mut peers_write = peers.write().await;
                            
                            // Update or insert peer
                            let peer_info = peers_write.entry(peer_name.clone()).or_insert_with(|| {
                                PeerInfo {
                                    ghost_name: peer_name.clone(),
                                    addr: peer_addr,
                                    last_seen: SystemTime::now(),
                                    public_key: pub_key.clone(),
                                }
                            });
                            
                            // Always update last_seen timestamp
                            peer_info.last_seen = SystemTime::now();
                            
                            // Update address if changed
                            if peer_info.addr != peer_addr {
                                peer_info.addr = peer_addr;
                            }
                            
                            // Update public key if we didn't have one
                            if peer_info.public_key.is_none() && pub_key.is_some() {
                                peer_info.public_key = pub_key;
                            }
                        }

                        // Send join response to new peers
                        if is_new_peer {
                            let peer_addr_for_response = peer_addr;
                            let send_socket_clone = Arc::clone(&send_socket);
                            let our_name = current_user.clone();
                            let our_key = public_key.clone();
                            let our_port = receive_port;
                            
                            tokio::spawn(async move {
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                
                                let response = Message::new(MessageType::Join {
                                    ghost_name: our_name.clone(),
                                    public_key: Some(our_key),
                                    receive_port: Some(our_port),
                                });
                                
                                if let Ok(bytes) = response.to_bytes() {
                                    let _ = send_socket_clone.send_to(&bytes, peer_addr_for_response).await;
                                }
                            });
                        }

                        // Suppress heartbeat display (not initial joins)
                        if let MessageType::Heartbeat { .. } = &message.msg_type {
                            continue;
                        }

                        // Suppress duplicate join announcements
                        if let MessageType::Join { .. } = &message.msg_type {
                            if !is_new_peer {
                                continue;
                            }
                        }

                        // Decrypt encrypted whispers if addressed to us
                        if let MessageType::EncryptedWhisper { from, to, encrypted } = &message.msg_type {
                            if to == &current_user {
                                // Get sender's public key
                                let peers_read = peers.read().await;
                                if let Some(peer) = peers_read.get(from) {
                                    if let Some(peer_public_key) = &peer.public_key {
                                        // Compute shared secret
                                        let their_public = PublicKey::from(peer_public_key.0);
                                        let shared_secret = secret_key.diffie_hellman(&their_public);
                                        
                                        // Decrypt message
                                        match decrypt_message(encrypted, &shared_secret) {
                                            Ok(plaintext) => {
                                                // Replace with decrypted whisper
                                                message.msg_type = MessageType::Whisper {
                                                    from: from.clone(),
                                                    to: to.clone(),
                                                    content: plaintext,
                                                };
                                            }
                                            Err(e) => {
                                                eprintln!("❌ Failed to decrypt message from {from}: {e}");
                                                continue;
                                            }
                                        }
                                    } else {
                                        eprintln!("❌ No public key for sender {from}");
                                        continue;
                                    }
                                } else {
                                    eprintln!("❌ Unknown sender {from}");
                                    continue;
                                }
                            } else {
                                // Not for us, ignore
                                continue;
                            }
                        }

                        // Display message
                        crate::message::display_message(&message, &current_user);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error receiving message: {e}");
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
            MessageType::Heartbeat { .. } => None,
            _ => None,
        }
    }

    /// Extract receive port from message
    fn extract_receive_port(message: &Message) -> Option<u16> {
        match &message.msg_type {
            MessageType::Join { receive_port, .. } => *receive_port,
            _ => None,
        }
    }

    /// Send heartbeat periodically and clean up stale peers
    async fn heartbeat_loop(
        socket: Arc<UdpSocket>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        ghost_name: String,
        _public_key: PublicKey,
        _receive_port: u16,
    ) {
        let mut interval = time::interval(HEARTBEAT_INTERVAL);

        loop {
            interval.tick().await;

            // Send heartbeat (simple heartbeat, not a full Join)
            let message = Message::new(MessageType::Heartbeat {
                from: ghost_name.clone(),
            });

            if let Ok(bytes) = message.to_bytes() {
                let broadcast_addr: SocketAddr = format!("{MULTICAST_IP}:{BROADCAST_PORT}").parse().unwrap();
                let _ = socket.send_to(&bytes, broadcast_addr).await;
                
                // Also send to all known peers directly
                let peers_read = peers.read().await;
                for peer in peers_read.values() {
                    let _ = socket.send_to(&bytes, peer.addr).await;
                }
            }

            // Remove stale peers
            let mut peers_write = peers.write().await;
            let now = SystemTime::now();
            let before_count = peers_write.len();
            
            peers_write.retain(|name, peer| {
                let age = now.duration_since(peer.last_seen)
                    .unwrap_or(Duration::from_secs(0));
                let keep = age < PEER_TIMEOUT;
                
                if !keep {
                    println!("⏰ Peer {} timed out (last seen {} seconds ago)", 
                        name, age.as_secs());
                }
                keep
            });
            
            let after_count = peers_write.len();
            if before_count != after_count {
                println!("🧹 Cleaned up {} stale peers", before_count - after_count);
            }
        }
    }

    /// Broadcast message to all peers
    async fn broadcast_message(&self, msg_type: MessageType) {
        let message = Message::new(msg_type);

        if let Ok(bytes) = message.to_bytes() {
            // Send to multicast address for network discovery
            let multicast_addr: SocketAddr = format!("{MULTICAST_IP}:{BROADCAST_PORT}").parse().unwrap();
            let _ = self.send_socket.send_to(&bytes, multicast_addr).await;

            // Send to broadcast address for same-machine testing
            let broadcast_all: SocketAddr = format!("255.255.255.255:{BROADCAST_PORT}").parse().unwrap();
            let _ = self.send_socket.send_to(&bytes, broadcast_all).await;
            
            // Send to localhost as fallback
            let localhost_addr: SocketAddr = format!("127.0.0.1:{BROADCAST_PORT}").parse().unwrap();
            let _ = self.send_socket.send_to(&bytes, localhost_addr).await;

            // Send directly to all known peers using their unique ports
            let peers = self.peers.read().await;
            for peer in peers.values() {
                let _ = self.send_socket.send_to(&bytes, peer.addr).await;
            }
        }
    }

    /// Send private whisper to specific peer (encrypted if they have a public key)
    async fn send_whisper(&self, to: String, content: String) {
        // Get fresh peer info with read lock
        let peer_info = {
            let peers = self.peers.read().await;
            peers.get(&to).cloned()
        };

        match peer_info {
            Some(peer) => {
                // Try to send encrypted if peer has public key
                if let Some(peer_public_key) = &peer.public_key {
                    match self.send_encrypted_whisper(&to, &content, peer_public_key, peer.addr).await {
                        Ok(_) => {
                            println!("🔒 ✅ Encrypted whisper delivered to {to}");
                        }
                        Err(e) => {
                            eprintln!("❌ Encryption failed: {e}");
                            eprintln!("   Falling back to unencrypted whisper");
                            
                            // Fallback to unencrypted
                            let message = Message::new(MessageType::Whisper {
                                from: self.ghost_name.clone(),
                                to: to.clone(),
                                content,
                            });

                            if let Ok(bytes) = message.to_bytes() {
                                if let Err(e) = self.send_socket.send_to(&bytes, peer.addr).await {
                                    eprintln!("❌ Failed to send whisper: {e}");
                                } else {
                                    println!("✅ Whisper delivered to {to}");
                                }
                            }
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
                        if let Err(e) = self.send_socket.send_to(&bytes, peer.addr).await {
                            eprintln!("❌ Failed to send whisper: {e}");
                        } else {
                            println!("✅ Whisper delivered to {to}");
                        }
                    }
                }
            }
            None => {
                println!("❌ Ghost '{to}' not found in the haunted realm");
                println!("   Try using /list to see available peers");
            }
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
            self.send_socket
                .send_to(&bytes, peer_addr)
                .await
                .map_err(|e| format!("Failed to send: {e}"))?;
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
    let nonce = &nonce_bytes.into();

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

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
    let nonce = &encrypted.nonce.into();
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {e}"))
}

/// Derive a 256-bit key from shared secret using SHA-256
fn derive_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"hauntnet-encryption-v1"); // Domain separation
    hasher.finalize().into()
}