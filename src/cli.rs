use colored::*;
use std::io::{self, Write};
use crate::banner;
use crate::{message, network};
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(
    name = "hauntnet",
    bin_name = "hauntnet",
    version = "0.1.0",
    author = "Connor",
    about = "A peer-to-peer haunted chatroom in Halloween style",
    long_about = "HauntNet - a spooky chatroom where ghosts and spirits whisper across the network.\n\nPowered by Rust 🦀 and Halloween vibes 🎃👻",
    disable_version_flag = true,
    after_help = "For more info, visit: https://github.com/yourrepo/hauntnet",
)]
pub struct Cli {
    #[arg(long = "version", action = clap::ArgAction::SetTrue)]
    pub show_version: bool,

    #[command(subcommand)]
pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Join,
    Whisper {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        message: String,
    },
    List,
    Vanish,
}

/// Handles the main CLI interaction flow
pub async fn start_cli() {
    println!("{}", banner::BANNER);

    // Parse initial CLI args
    let cli = Cli::parse();
    
    // Get user's spooky name
    let spooky_name = ask_spooky_name();
    println!(
        "🧛‍♂️ {} has joined the haunted realm!",
        spooky_name.bright_magenta().bold()
    );

    // If a command was provided as CLI arg, execute it and exit
    if let Some(command) = cli.command {
        match command {
            Commands::Join => println!("Joining..."),
            Commands::Whisper { to, message } => println!("Whispering to {}... '{}'", to, message),
            Commands::List => println!("Listing..."),
            Commands::Vanish => println!("Vanishing..."),
        }
        return;
    }

    // Create channel for CLI -> Network communication
    let (command_tx, command_rx) = mpsc::unbounded_channel();

    // Start network
    let network = match network::Network::new(spooky_name.clone(), command_rx).await {
        Ok(net) => net,
        Err(e) => {
            eprintln!("💀 Failed to start network: {}", e);
            return;
        }
    };

    // Spawn network task
    tokio::spawn(async move {
        network.run().await;
    });

    // Start the interactive command loop
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
            format!("Welcome, {}! The haunt begins…", spooky_name)
                .truecolor(255, 140, 0)
                .bold(),
            "👻".bright_white()
        );
        return spooky_name;
    }
}
