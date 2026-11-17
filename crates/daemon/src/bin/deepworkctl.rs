//! Command-line control for DeepWork.

use deepwork_core::client::Client;
use deepwork_core::protocol::BlockStatus;
use deepwork_core::{format_duration, now};

const USAGE: &str = "usage: deepworkctl <command>

  status                 show blocks and what's running
  start <block> <min>    start a block for <min> minutes
  stop <block>           stop a block (if it isn't locked)
  freeze <min>           lock the whole computer for <min> minutes
  locked                 exit 0 if any block is locked or a freeze is running

<block> is a block's name or id.";

fn find<'a>(blocks: &'a [BlockStatus], key: &str) -> Option<&'a BlockStatus> {
    blocks.iter().find(|b| b.id == key).or_else(|| {
        blocks
            .iter()
            .find(|b| b.config.name.eq_ignore_ascii_case(key))
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let client = Client::default();
    let fail = |e: &dyn std::fmt::Display| -> ! {
        eprintln!("deepworkctl: {e}");
        std::process::exit(1)
    };
    let status = || client.status().unwrap_or_else(|e| fail(&e));
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] | [] => {
            let s = status();
            let t = now();
            if s.frozen_until > t {
                println!("❄  Frozen for {}", format_duration(s.frozen_until - t));
            }
            if s.blocks.is_empty() {
                println!("No blocks yet. Open DeepWork to create one.");
            }
            for b in &s.blocks {
                let state = if b.on_break {
                    "on break".to_string()
                } else if let Some(end) = b.window_end.filter(|_| b.active) {
                    format!("active, {} left", format_duration(end - t))
                } else {
                    "off".to_string()
                };
                println!(
                    "{} {:<24} {:<26} {} sites, {} apps{}   [{}]",
                    if b.locked { "🔒" } else { "  " },
                    b.config.name,
                    state,
                    b.config.effective_websites().len(),
                    b.config.effective_apps().len(),
                    if b.config.lists.is_empty() {
                        String::new()
                    } else {
                        format!(" (lists: {})", b.config.lists.join(", "))
                    },
                    b.id
                );
            }
        }
        ["start", key, mins] => {
            let s = status();
            let b = find(&s.blocks, key).unwrap_or_else(|| fail(&"no such block"));
            let m: u32 = mins
                .parse()
                .unwrap_or_else(|_| fail(&"minutes must be a number"));
            client.start_block(&b.id, m).unwrap_or_else(|e| fail(&e));
            println!(
                "Started “{}” for {}",
                b.config.name,
                format_duration(m as f64 * 60.0)
            );
        }
        ["stop", key] => {
            let s = status();
            let b = find(&s.blocks, key).unwrap_or_else(|| fail(&"no such block"));
            client.stop_block(&b.id).unwrap_or_else(|e| fail(&e));
            println!("Stopped “{}”", b.config.name);
        }
        ["freeze", mins] => {
            let m: u32 = mins
                .parse()
                .unwrap_or_else(|_| fail(&"minutes must be a number"));
            client.freeze(m).unwrap_or_else(|e| fail(&e));
            println!("Freezing for {}", format_duration(m as f64 * 60.0));
        }
        ["locked"] => {
            let s = status();
            let locked = s.frozen_until > now() || s.blocks.iter().any(|b| b.locked);
            std::process::exit(if locked { 0 } else { 1 });
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
