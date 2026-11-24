//! Command-line control for DeepWork.

use deepwork_core::client::Client;
use deepwork_core::lists;
use deepwork_core::model::{BlockConfig, LockKind, normalize_app, normalize_domain};
use deepwork_core::protocol::BlockStatus;
use deepwork_core::{format_duration, now};

const USAGE: &str = "usage: deepworkctl <command>

  status                 show blocks and what's running
  start <block> <min>    start a block for <min> minutes
  stop <block>           stop a block (if it isn't locked)
  unlock <block>         unlock a block with a random-text lock
  freeze <min>           lock the whole computer for <min> minutes
  locked                 exit 0 if any block is locked or a freeze is running
  lists                  show the built-in filter lists
  add <name> [--lock none|random|strict] <site|list:ID|app:NAME>...
                         create a block, e.g. add Social list:social reddit.com app:steam
  delete <block>         delete a block (if it isn't locked)
  --version              show the version

<block> is a block's name or id.";

/// Build a block from `add` arguments.
fn parse_add(name: &str, rest: &[&str]) -> Result<BlockConfig, String> {
    let mut cfg = BlockConfig {
        name: name.to_string(),
        ..BlockConfig::default()
    };
    let mut args = rest.iter();
    while let Some(a) = args.next() {
        if *a == "--lock" {
            cfg.lock = match args.next().copied() {
                Some("none") => LockKind::None,
                Some("random") => LockKind::Random,
                Some("strict") => LockKind::Strict,
                _ => return Err("--lock takes none, random or strict".into()),
            };
        } else if let Some(id) = a.strip_prefix("list:").or_else(|| a.strip_prefix('@')) {
            if lists::get(id).is_none() {
                return Err(format!("no filter list “{id}” (see: deepworkctl lists)"));
            }
            cfg.lists.push(id.to_string());
        } else if let Some(app) = a.strip_prefix("app:") {
            cfg.apps
                .push(normalize_app(app).map_err(|e| format!("{a}: {e}"))?);
        } else {
            cfg.websites
                .push(normalize_domain(a).map_err(|e| format!("{a}: {e}"))?);
        }
    }
    if cfg.websites.is_empty() && cfg.lists.is_empty() && cfg.apps.is_empty() {
        return Err("name at least one website, list:ID or app:NAME".into());
    }
    Ok(cfg)
}

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
                println!("No blocks yet. Open DeepWork or use “deepworkctl add” to create one.");
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
        ["unlock", key] => {
            let s = status();
            let b = find(&s.blocks, key).unwrap_or_else(|| fail(&"no such block"));
            let text = client.unlock_challenge(&b.id).unwrap_or_else(|e| fail(&e));
            println!("Type this text to unlock “{}”:\n\n{text}\n", b.config.name);
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .unwrap_or_else(|e| fail(&e));
            client
                .unlock(&b.id, answer.trim_end_matches(['\r', '\n']))
                .unwrap_or_else(|e| fail(&e));
            println!("Unlocked “{}”", b.config.name);
        }
        ["lists"] => {
            for l in lists::LISTS {
                println!(
                    "list:{:<12} {:<26} {} sites, {} apps",
                    l.id,
                    l.name,
                    l.websites.len(),
                    l.apps.len()
                );
            }
        }
        ["add", name, rest @ ..] => {
            let cfg = parse_add(name, rest).unwrap_or_else(|e| fail(&e));
            let id = client.create_block(cfg, None).unwrap_or_else(|e| fail(&e));
            // Refer to it by name when that is unambiguous and easy to type.
            let same = status()
                .blocks
                .iter()
                .filter(|b| b.config.name.eq_ignore_ascii_case(name))
                .count();
            let key = if same == 1 && !name.contains(char::is_whitespace) {
                name.to_string()
            } else {
                id.clone()
            };
            println!("Created “{name}” [{id}]. Start it with: deepworkctl start {key} <minutes>");
        }
        ["delete", key] => {
            let s = status();
            let b = find(&s.blocks, key).unwrap_or_else(|| fail(&"no such block"));
            client.delete_block(&b.id).unwrap_or_else(|e| fail(&e));
            println!("Deleted “{}”", b.config.name);
        }
        ["freeze", mins] => {
            let m: u32 = mins
                .parse()
                .unwrap_or_else(|_| fail(&"minutes must be a number"));
            client.freeze(m).unwrap_or_else(|e| fail(&e));
            println!("Freezing for {}", format_duration(m as f64 * 60.0));
        }
        ["--version"] | ["version"] => println!("deepworkctl {}", deepwork_core::VERSION),
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

#[cfg(test)]
mod tests;
