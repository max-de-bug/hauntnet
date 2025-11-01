use colored::*; 
use std::io::{self, Write}; 
use crate::banner; 
use crate::{message, network}; 
use clap::{Parser, Subcommand, CommandFactory}; 
use tokio::sync::mpsc; 
 
#[derive(Parser)] 
#[command( 
    name = "hauntnet", 
    bin_name = "hauntnet", 
    version = "0.1.0", 
    author = "Connor", 
    long_about = "HauntNet - a spooky chatroom where ghosts and spirits whisper across the network.\n\nPowered by Rust 🦀 and Halloween vibes 🎃👻", 
    after_help = "For more info, visit: https://github.com/yourrepo/hauntnet\n\nRun without arguments to start interactive mode.", 
    disable_help_flag = true,
    override_usage = "[COMMAND]",

)] 
pub struct Cli { 
    /// Your spooky name (if not provided, you'll be prompted)
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    #[command(subcommand)] 
    pub command: Option<Commands>, 
} 
 
#[derive(Subcommand)] 
pub enum Commands { 
    /// Join the haunted network (interactive mode only)
    Join,
    
    /// Send a private whisper to another ghost
    Whisper { 
        /// Recipient's name
        #[arg(short, long)] 
        to: String,
        
        /// Message content
        #[arg(short, long)] 
        message: String, 
    },
    
    /// List all ghosts in the realm
    List,
    
    /// Leave the haunted network
    Vanish, 
} 
 
/// Handles the main CLI interaction flow 
pub async fn start_cli() { 
    
    println!("{}", banner::BANNER); 
    println!("{}", "A peer-to-peer haunted chatroom in Halloween style 🎃👻".bright_cyan());
    println!(); 
    Cli::command().print_help().unwrap();
    println!(); // add an empty line for spacing
    println!();
    let cli = Cli::parse(); 
 
    // Get user's spooky name (from CLI or prompt)
    let spooky_name = if let Some(name) = cli.name {
        println!( 
            "🧛‍♂️ {} has joined the haunted realm!", 
            name.bright_magenta().bold() 
        );
        name
    } else {
        ask_spooky_name()
    };
 
    // Create channel for CLI -> Network communication 
    let (command_tx, command_rx) = mpsc::unbounded_channel(); 
 
    // Start network 
    let network = match network::Network::new(spooky_name.clone(), command_rx).await { 
        Ok(net) => net, 
        Err(e) => { 
            eprintln!("💀 Failed to start network: {e}"); 
            return; 
        } 
    }; 
 
    // Spawn network task 
    tokio::spawn(async move { 
        network.run().await; 
    }); 

    // If a subcommand was provided, handle it then start interactive mode
    if let Some(command) = cli.command { 
        match command { 
            Commands::Join => {
                // Already joined automatically, just show message
                println!("✅ Already connected to the haunted network!");
            }
            Commands::Whisper { to, message } => {
                if let Err(e) = command_tx.send(crate::message::Command::SendWhisper { 
                    to: to.clone(), 
                    content: message.clone() 
                }) {
                    eprintln!("❌ Failed to send whisper: {e}");
                } else {
                    println!("👻 Whispering to {to}...");
                }
            }
            Commands::List => {
                if let Err(e) = command_tx.send(crate::message::Command::ListPeers) {
                    eprintln!("❌ Failed to list peers: {e}");
                }
            }
            Commands::Vanish => {
                println!("👋 Vanishing from the haunted realm...");
                let _ = command_tx.send(crate::message::Command::Leave);
                return; // Exit after vanishing
            }
        } 
        
        // Small delay to let network process the command
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
 
    // Start the interactive command loop (always run unless Vanish was used)
    message::start_interactive_loop(spooky_name, command_tx).await; 
} 
 
/// Prompts user for a spooky name and returns it 
fn ask_spooky_name() -> String { 
    loop { 
        print!("{}", "🕯️ Please choose your spooky name: ".bright_yellow().bold()); 
        io::stdout().flush().unwrap(); 
 
        let mut spooky_name = String::new(); 
        if io::stdin().read_line(&mut spooky_name).is_err() { 
            eprintln!("Failed to read input."); 
            continue; 
        } 
 
        let spooky_name = spooky_name.trim().to_string(); 
        if spooky_name.is_empty() { 
            println!("{}", "⚠️ Please enter a non-empty name.".bright_red()); 
            continue; 
        } 
 
        println!( 
            "{} {} {}", 
            "🎃".bright_magenta(), 
            format!("Welcome, {spooky_name}! The haunt begins…") 
                .truecolor(255, 140, 0) 
                .bold(), 
            "👻".bright_white() 
        ); 
        return spooky_name; 
    } 
}