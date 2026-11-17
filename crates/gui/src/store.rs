//! Shared, polled view of the daemon state.

use std::cell::{Cell, RefCell};

use deepwork_core::client::{Client, ClientError};
use deepwork_core::protocol::{BlockStatus, Event, Stats, Status};

pub struct Store {
    pub client: Client,
    status: RefCell<Option<Status>>,
    stats: RefCell<Stats>,
    error: RefCell<Option<String>>,
    listeners: RefCell<Vec<Box<dyn Fn()>>>,
    last_seq: Cell<u64>,
    events_primed: Cell<bool>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            client: Client::default(),
            status: RefCell::new(None),
            stats: RefCell::new(Stats::new()),
            error: RefCell::new(None),
            listeners: RefCell::new(Vec::new()),
            last_seq: Cell::new(0),
            events_primed: Cell::new(false),
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

    pub fn refresh(&self) {
        match self.client.status() {
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

    /// New events since the last call. The first call only primes the cursor
    /// so old events don't produce a burst of notifications.
    pub fn new_events(&self) -> Vec<Event> {
        let Ok(events) = self.client.events(self.last_seq.get()) else {
            return vec![];
        };
        if let Some(last) = events.last() {
            self.last_seq.set(last.seq);
        }
        if !self.events_primed.replace(true) {
            return vec![];
        }
        events
    }
}
