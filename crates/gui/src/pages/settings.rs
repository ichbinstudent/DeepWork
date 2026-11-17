//! "Settings" page: how deep website blocking goes.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use deepwork_core::model::Settings;

use crate::window::Ctx;

/// What DeepWork can't stop on this OS.
#[cfg(not(windows))]
const LIMITS: &[(&str, &str)] = &[
    (
        "Administrator access",
        "Anyone with sudo can stop the service, except while a hardcore block runs. Locks \
         make giving up harder, not impossible.",
    ),
    (
        "Booting something else",
        "Even hardcore mode can't stop a live USB stick or an edited boot menu. A firmware \
         (BIOS) password and a boot loader password close that gap.",
    ),
    (
        "VPNs, proxies and Tor",
        "Apps that tunnel all traffic elsewhere bypass local blocking. Block those apps if they tempt you.",
    ),
    (
        "Encrypted Client Hello",
        "Some sites hide their name from the filter when the browser uses encrypted DNS. Blocking \
         encrypted DNS prevents most of this.",
    ),
];

/// What DeepWork can't stop on this OS.
#[cfg(windows)]
const LIMITS: &[(&str, &str)] = &[
    (
        "Administrator access",
        "Any administrator can stop the service or edit the hosts file. Locks make giving up \
         harder, not impossible. Use a standard account day to day to make it harder still.",
    ),
    (
        "Other browsers",
        "Chrome, Edge, Brave and Firefox block sites through their policies, even behind a VPN \
         extension. Other browsers rely on the hosts file, which VPNs and proxies get around.",
    ),
    (
        "VPN and proxy apps",
        "Apps that tunnel all traffic elsewhere bypass the hosts file. Block those websites too.",
    ),
];

pub fn build(ctx: &Rc<Ctx>) -> gtk::Widget {
    let header = adw::HeaderBar::new();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 24);

    let group = adw::PreferencesGroup::builder()
        .title("Website blocking")
        .description(
            "Extra protection that kicks in while a block with websites is running. \
             Nothing changes while no websites are blocked.",
        )
        .build();
    let doh = adw::SwitchRow::builder()
        .title("Block encrypted DNS")
        .subtitle(
            "Stops browsers and apps from using DNS over HTTPS or TLS servers (Cloudflare, Google, \
             Quad9, NextDNS…) to look up blocked sites. Recommended.",
        )
        .build();
    let filter = adw::SwitchRow::builder()
        .title("Filter all web traffic")
        .subtitle(
            "Checks the site name of every web connection, so blocks also work in Flatpak \
             browsers, with custom DNS or direct IP addresses. Nothing is decrypted. HTTP/3 is \
             turned off while filtering, so browsers use regular HTTPS.",
        )
        .build();
    let status = adw::ActionRow::builder().title("Status").build();
    status.add_css_class("property");
    let status_icon = gtk::Image::new();
    status.add_prefix(&status_icon);
    group.add(&doh);
    group.add(&filter);
    group.add(&status);
    content.append(&group);

    // Only shown while a hardcore block runs.
    let hardcore = adw::PreferencesGroup::builder()
        .title("Hardcore mode")
        .build();
    let hc_row = adw::ActionRow::builder()
        .title("Administrator rights are off")
        .build();
    hc_row.add_prefix(&gtk::Image::from_icon_name("changes-prevent-symbolic"));
    hardcore.add(&hc_row);
    let hc_warnings = gtk::ListBox::new();
    hc_warnings.add_css_class("boxed-list");
    hc_warnings.set_selection_mode(gtk::SelectionMode::None);
    hc_warnings.set_margin_top(12);
    hardcore.add(&hc_warnings);
    content.append(&hardcore);

    let limits = adw::PreferencesGroup::builder()
        .title("What can still get through")
        .build();
    for &(title, text) in LIMITS {
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(text)
            .build();
        limits.add(&row);
    }
    content.append(&limits);

    // Programmatic updates must not be sent back to the daemon.
    let syncing = Rc::new(Cell::new(false));
    let send = {
        let (ctx, doh, filter, syncing) =
            (ctx.clone(), doh.clone(), filter.clone(), syncing.clone());
        move || {
            if syncing.get() {
                return;
            }
            let settings = Settings {
                block_doh: doh.is_active(),
                https_filter: filter.is_active(),
            };
            if ctx.act(ctx.store.client.set_settings(settings)).is_none() {
                // Refused (e.g. a block is locked): show the real state again.
                if let Some(s) = ctx.store.status() {
                    syncing.set(true);
                    doh.set_active(s.settings.block_doh);
                    filter.set_active(s.settings.https_filter);
                    syncing.set(false);
                }
            }
        }
    };
    {
        let send = send.clone();
        doh.connect_active_notify(move |_| send());
    }
    filter.connect_active_notify(move |_| send());

    let update = {
        let ctx = ctx.clone();
        let group = group.clone();
        move || {
            let Some(s) = ctx.store.status() else { return };
            syncing.set(true);
            doh.set_active(s.settings.block_doh);
            filter.set_active(s.settings.https_filter);
            syncing.set(false);
            let net = &s.net;
            let caps = ctx.store.capabilities();
            doh.set_sensitive(caps.encrypted_dns);
            filter.set_sensitive(caps.https_filter);
            // Nothing to switch on this OS: leave the section out. (On Linux
            // it stays, to explain what's missing, e.g. nftables.)
            group.set_visible(caps.os == "Linux" || caps.encrypted_dns || caps.https_filter);
            let (icon, text) = if !net.firewall_available && caps.os != "Linux" {
                (
                    "dialog-warning-symbolic",
                    format!("Not available on {} yet", caps.os),
                )
            } else if !net.firewall_available {
                (
                    "dialog-warning-symbolic",
                    "Not available: the service needs the nft command (nftables) and must run as root"
                        .to_string(),
                )
            } else if let Some(e) = &net.error {
                (
                    "dialog-warning-symbolic",
                    e.lines().next().unwrap_or(e).to_string(),
                )
            } else if net.filtering {
                (
                    "security-high-symbolic",
                    format!(
                        "Filtering web traffic{} · {} connections refused so far",
                        if net.doh_blocked {
                            " and blocking encrypted DNS"
                        } else {
                            ""
                        },
                        net.filtered_connections
                    ),
                )
            } else if net.doh_blocked {
                (
                    "security-medium-symbolic",
                    "Blocking encrypted DNS".to_string(),
                )
            } else {
                (
                    "security-low-symbolic",
                    "Waiting for the next website block".to_string(),
                )
            };
            status_icon.set_icon_name(Some(icon));
            status.set_subtitle(&text);

            let hc = &s.hardcore;
            hardcore.set_visible(hc.until > s.now);
            hc_row.set_subtitle(&format!(
                "Nobody can use sudo, su, pkexec or admin passwords until {}{}.",
                deepwork_core::format_time(hc.until),
                if net.tunnels_blocked {
                    ". VPN tunnels are refused"
                } else {
                    ""
                }
            ));
            crate::util::clear_listbox(&hc_warnings);
            hc_warnings.set_visible(!hc.warnings.is_empty());
            for w in &hc.warnings {
                let row = adw::ActionRow::builder()
                    .title("Still open")
                    .subtitle(gtk::glib::markup_escape_text(w).as_str())
                    .build();
                row.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
                hc_warnings.append(&row);
            }
        }
    };
    update();
    ctx.store.subscribe(update);

    crate::pages::page_shell(&content, &header).upcast()
}
