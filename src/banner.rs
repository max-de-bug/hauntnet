use crossterm::{
    execute,
    style::{Print, Stylize},
    terminal::{Clear, ClearType},
};
use std::io::stdout;

pub fn print_banner(message: &str) {
    let mut stdout = stdout();

    // Clear terminal
    execute!(stdout, Clear(ClearType::All)).unwrap();

    // Optional: add a spooky border around the message
    let border = "*".repeat(message.chars().count() + 4);
    execute!(stdout, Print(format!("{}\n", border).dark_grey())).unwrap();
    execute!(stdout, Print(format!("* {} *\n", message).magenta().bold())).unwrap();
    execute!(stdout, Print(format!("{}\n", border).dark_grey())).unwrap();

    println!();
}