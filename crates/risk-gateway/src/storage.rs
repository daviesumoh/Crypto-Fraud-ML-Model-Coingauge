use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use common_types::CompositeRiskReport;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_PERSISTED_ALERTS: usize = 500;
pub const MAX_PERSISTED_DISPUTES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    pub dispute_id: Uuid,
    pub evaluation_id: Option<Uuid>,
    pub chain_id: u64,
    pub address: String,
    pub proposed_label: String,
    pub analyst_notes: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub evaluation_id: Uuid,
    pub triage_status: String,
    pub updated_at: DateTime<Utc>,
    pub report: CompositeRiskReport,
}

#[derive(Debug, Clone, Default)]
pub struct JsonlStore {
    data_dir: Option<PathBuf>,
}

impl JsonlStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: Some(data_dir.into()),
        }
    }

    pub fn ephemeral() -> Self {
        Self { data_dir: None }
    }

    fn alerts_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("alerts.jsonl"))
    }

    fn disputes_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("disputes.jsonl"))
    }

    pub fn load_alerts(&self) -> VecDeque<AlertRecord> {
        let Some(path) = self.alerts_path() else {
            return VecDeque::with_capacity(MAX_PERSISTED_ALERTS);
        };
        let items: Vec<AlertRecord> = read_jsonl_bounded(&path, MAX_PERSISTED_ALERTS);
        items.into_iter().collect()
    }

    pub fn load_disputes(&self) -> Vec<DisputeRecord> {
        let Some(path) = self.disputes_path() else {
            return Vec::new();
        };
        read_jsonl_bounded(&path, MAX_PERSISTED_DISPUTES)
    }

    pub fn save_alerts(&self, alerts: &[AlertRecord]) -> std::io::Result<()> {
        let Some(path) = self.alerts_path() else {
            return Ok(());
        };
        write_jsonl_atomic(&path, alerts)
    }

    pub fn save_disputes(&self, disputes: &[DisputeRecord]) -> std::io::Result<()> {
        let Some(path) = self.disputes_path() else {
            return Ok(());
        };
        write_jsonl_atomic(&path, disputes)
    }
}

fn read_jsonl_bounded<T: for<'de> Deserialize<'de>>(path: &Path, limit: usize) -> Vec<T> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut ring: VecDeque<T> = VecDeque::with_capacity(limit);
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(item) = serde_json::from_str::<T>(trimmed) {
            if ring.len() >= limit {
                ring.pop_back();
            }
            ring.push_back(item);
        }
    }
    ring.into_iter().collect()
}

use std::sync::atomic::{AtomicU64, Ordering};

static TMP_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

fn write_jsonl_atomic<T: Serialize>(path: &Path, items: &[T]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let seq = TMP_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = path.with_extension(format!("jsonl.tmp.{}.{}", std::process::id(), seq));
    {
        let mut file = File::create(&tmp_path)?;
        for item in items {
            let line = serde_json::to_string(item)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            writeln!(file, "{line}")?;
        }
        file.sync_all()?;
    }
    fs::rename(tmp_path, path)
}
