mod banner;
mod cli;
mod message;
mod network;

#[tokio::main]
async fn main() {
    cli::start_cli().await;
}