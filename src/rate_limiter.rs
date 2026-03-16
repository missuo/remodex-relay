use std::collections::HashMap;
use std::time::Instant;

pub struct FixedWindowRateLimiter {
    buckets: HashMap<String, Bucket>,
    window_ms: u64,
    max_requests: u64,
    next_prune_at: Option<Instant>,
}

struct Bucket {
    count: u64,
    expires_at: Instant,
}

impl FixedWindowRateLimiter {
    pub fn new(window_ms: u64, max_requests: u64) -> Self {
        let window_ms = if window_ms > 0 { window_ms } else { 60_000 };
        let max_requests = if max_requests > 0 { max_requests } else { 60 };
        Self {
            buckets: HashMap::new(),
            window_ms,
            max_requests,
            next_prune_at: None,
        }
    }

    pub fn allow(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let key = if key.trim().is_empty() {
            "unknown".to_string()
        } else {
            key.trim().to_string()
        };
        let window_duration = std::time::Duration::from_millis(self.window_ms);

        // Prune expired buckets periodically
        let should_prune = match self.next_prune_at {
            None => true,
            Some(next) => now >= next,
        };
        if should_prune {
            self.next_prune_at = Some(now + window_duration);
            self.buckets.retain(|_, bucket| now < bucket.expires_at);
        }

        match self.buckets.get_mut(&key) {
            Some(bucket) if now < bucket.expires_at => {
                if bucket.count >= self.max_requests {
                    return false;
                }
                bucket.count += 1;
                true
            }
            _ => {
                self.buckets.insert(
                    key,
                    Bucket {
                        count: 1,
                        expires_at: now + window_duration,
                    },
                );
                true
            }
        }
    }
}
