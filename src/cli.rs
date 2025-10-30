
use colored::*;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hauntnet", about = "HauntNet - a peer-to-peer chat application in Halloween theme", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
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


use std::io::{self, Write};
use crate::banner;

/// Handles the main CLI interaction flow
pub fn start_cli() {
    // 1. Show banner
    banner::print_banner("👻 Welcome to Hauntnet! 🎃 The ghosts are awake...");

    // 2. Ask for spooky name
    let spooky_name = ask_spooky_name();

    // 3. Show confirmation
    println!("🧛‍♂️ {} has joined the haunted realm!", spooky_name);
}

/// Prompts user for a spooky name and returns it
fn ask_spooky_name() -> String {
    print!("{}", "🕯️ Please choose your spooky name: ".bright_yellow().bold());
    io::stdout().flush().unwrap();

    let mut spooky_name = String::new();
    io::stdin()
        .read_line(&mut spooky_name)
        .expect("Failed to read line");

    let spooky_name = spooky_name.trim().to_string();
    
    
    if spooky_name.is_empty() {
         println!("Please enter a non-empty name.");
       return ask_spooky_name();
    }

// 🎃 glowing welcome line
    println!(
        "{} {} {}",
        "🎃".bright_magenta(),
        format!("Welcome, {}! The haunt begins…", spooky_name)
            .truecolor(255, 140, 0) // warm orange tone
            .bold(),
        "👻".bright_white()
    );
   spooky_name
}
