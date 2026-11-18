//! Shared, polled view of the daemon state.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gtk::glib;

use deepwork_core::client::{Client, ClientError};
use deepwork_core::protocol::{BlockStatus, Event, Stats, Status};

pub struct Store {
    pub client: Client,
    status: RefCell<Option<Status>>,
    stats: RefCell<Stats>,
    error: RefCell<Option<String>>,
    listeners: RefCell<Vec<Box<dyn Fn()>>>,
    /// Counts direct refreshes, so an older answer from the background
    /// poller doesn't overwrite a newer one.
    generation: Arc<AtomicU64>,
}

/// What the background poller brings back.
enum Polled {
    Status(u64, Result<Status, ClientError>),
    Events(Vec<Event>),
    Stats(Stats),
}

impl Store {
    pub fn new() -> Self {
        Self {
            client: Client::default(),
            status: RefCell::new(None),
            stats: RefCell::new(Stats::new()),
            error: RefCell::new(None),
            listeners: RefCell::new(Vec::new()),
            generation: Arc::default(),
        }
    }

    pub fn status(&self) -> Option<Status> {
        self.status.borrow().clone()
    }

    /// What the service supports on this OS. Until it has answered (or if
    /// it is too old to say), assume everything.
    pub fn capabilities(&self) -> deepwork_core::protocol::Capabilities {
        self.status
            .borrow()
            .as_ref()
            .map(|s| s.capabilities.clone())
            .filter(|c| !c.os.is_empty())
            .unwrap_or_else(|| deepwork_core::protocol::Capabilities::all(""))
    }

    pub fn stats(&self) -> Stats {
        self.stats.borrow().clone()
    }

    pub fn online(&self) -> bool {
        self.status.borrow().is_some()
    }

    pub fn block(&self, id: &str) -> Option<BlockStatus> {
        self.status
            .borrow()
            .as_ref()?
            .blocks
            .iter()
            .find(|b| b.id == id)
            .cloned()
    }

    /// Register a callback run after every refresh.
    pub fn subscribe(&self, f: impl Fn() + 'static) {
        self.listeners.borrow_mut().push(Box::new(f));
    }

    /// Ask the service now (after the user changed something).
    pub fn refresh(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.set_status(self.client.status());
    }

    /// Keep asking the service for news on another thread, so a slow answer
    /// never holds up the window: the status every second, new events
    /// (passed to `on_events`) every two, statistics every thirty.
    pub fn poll_in_background(self: &Rc<Self>, on_events: impl Fn(Vec<Event>) + 'static) {
        let (tx, rx) = async_channel::unbounded();
        let client = self.client.clone();
        let generation = self.generation.clone();
        // The last event seen; the first answer only sets it, so old events
        // don't produce a burst of notifications.
        let mut since: Option<u64> = None;
        std::thread::spawn(move || {
            for tick in 1u64.. {
                std::thread::sleep(Duration::from_secs(1));
                let generation = generation.load(Ordering::SeqCst);
                let mut out = vec![Polled::Status(generation, client.status())];
                if tick % 2 == 0
                    && let Ok(events) = client.events(since.unwrap_or(0))
                {
                    let seen = since.is_some();
                    since = events.last().map(|e| e.seq).or(since).or(Some(0));
                    if seen && !events.is_empty() {
                        out.push(Polled::Events(events));
                    }
                }
                if tick % 30 == 0
                    && let Ok(stats) = client.stats(60)
                {
                    out.push(Polled::Stats(stats));
                }
                for msg in out {
                    if tx.send_blocking(msg).is_err() {
                        return; // the app has quit
                    }
                }
            }
        });
        let store = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                let Some(store) = store.upgrade() else { break };
                match msg {
                    Polled::Status(generation, r) => {
                        if generation == store.generation.load(Ordering::SeqCst) {
                            store.set_status(r);
                        }
                    }
                    Polled::Events(events) => on_events(events),
                    Polled::Stats(stats) => {
                        store.stats.replace(stats);
                    }
                }
            }
        });
    }

    fn set_status(&self, r: Result<Status, ClientError>) {
        match r {
            Ok(s) => {
                self.status.replace(Some(s));
                self.error.replace(None);
            }
            Err(e) => {
                self.status.replace(None);
                self.error.replace(Some(match e {
                    ClientError::Unavailable(m) => m,
                    other => other.to_string(),
                }));
            }
        }
        // Clone the list of listeners isn't possible (Box<dyn Fn>), so hold a
        // shared borrow; listeners must not subscribe while being notified.
        for l in self.listeners.borrow().iter() {
            l();
        }
    }

    pub fn refresh_stats(&self) {
        if let Ok(s) = self.client.stats(60) {
            self.stats.replace(s);
        }
    }
}
