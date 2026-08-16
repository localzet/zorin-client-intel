use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    observations: AtomicU64,
    graph_matches: AtomicU64,
    graph_new_clients: AtomicU64,
    graph_ambiguous: AtomicU64,
    storage_errors: AtomicU64,
    sensor_events: AtomicU64,
}

impl Metrics {
    pub fn observation(&self) {
        self.observations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn graph_match(&self) {
        self.graph_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn graph_new_client(&self) {
        self.graph_new_clients.fetch_add(1, Ordering::Relaxed);
    }

    pub fn graph_ambiguous(&self) {
        self.graph_ambiguous.fetch_add(1, Ordering::Relaxed);
    }

    pub fn storage_error(&self) {
        self.storage_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sensor_event(&self) {
        self.sensor_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn prometheus(&self) -> String {
        format!(
            concat!(
                "# TYPE zci_observations_total counter\n",
                "zci_observations_total {}\n",
                "# TYPE zci_graph_matches_total counter\n",
                "zci_graph_matches_total {}\n",
                "# TYPE zci_graph_new_clients_total counter\n",
                "zci_graph_new_clients_total {}\n",
                "# TYPE zci_graph_ambiguous_total counter\n",
                "zci_graph_ambiguous_total {}\n",
                "# TYPE zci_storage_errors_total counter\n",
                "zci_storage_errors_total {}\n",
                "# TYPE zci_sensor_events_total counter\n",
                "zci_sensor_events_total {}\n"
            ),
            self.observations.load(Ordering::Relaxed),
            self.graph_matches.load(Ordering::Relaxed),
            self.graph_new_clients.load(Ordering::Relaxed),
            self.graph_ambiguous.load(Ordering::Relaxed),
            self.storage_errors.load(Ordering::Relaxed),
            self.sensor_events.load(Ordering::Relaxed),
        )
    }
}
