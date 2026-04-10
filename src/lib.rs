/*!
# cuda-rate-limit

Rate limiting and flow control.

Agents in a fleet can overwhelm each other, external APIs, or shared
resources. Rate limiting prevents thundering herds and enforces
fair resource sharing.

- Token bucket algorithm
- Sliding window counter
- Per-agent quotas
- Priority-aware limiting
- Backpressure signaling
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token bucket rate limiter
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBucket {
    pub max_tokens: f64,
    pub refill_rate: f64,     // tokens per second
    pub available: f64,
    pub last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self { TokenBucket { max_tokens, refill_rate, available: max_tokens, last_refill_ms: now() } }

    /// Try to consume tokens
    pub fn consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.available >= tokens {
            self.available -= tokens;
            true
        } else { false }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let elapsed_ms = (now() - self.last_refill_ms) as f64 / 1000.0;
        self.available = (self.available + self.refill_rate * elapsed_ms).min(self.max_tokens);
        self.last_refill_ms = now();
    }

    /// Time until next token available
    pub fn wait_time_ms(&self, tokens: f64) -> u64 {
        if self.available >= tokens { return 0; }
        let needed = tokens - self.available;
        ((needed / self.refill_rate) * 1000.0) as u64
    }

    pub fn utilization(&self) -> f64 { 1.0 - (self.available / self.max_tokens) }
}

/// Sliding window rate limiter
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlidingWindow {
    pub max_requests: u32,
    pub window_ms: u64,
    pub timestamps: Vec<u64>,
}

impl SlidingWindow {
    pub fn new(max_requests: u32, window_ms: u64) -> Self { SlidingWindow { max_requests, window_ms, timestamps: vec![] } }

    /// Try to record a request
    pub fn allow(&mut self) -> bool {
        self.prune();
        if self.timestamps.len() >= self.max_requests as usize { return false; }
        self.timestamps.push(now());
        true
    }

    fn prune(&mut self) {
        let cutoff = now() - self.window_ms;
        self.timestamps.retain(|&t| t > cutoff);
    }

    pub fn remaining(&self) -> u32 {
        let cutoff = now() - self.window_ms;
        let active = self.timestamps.iter().filter(|&&t| t > cutoff).count();
        (self.max_requests as usize - active).max(0) as u32
    }
}

/// Per-agent quota
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentQuota {
    pub agent_id: String,
    pub daily_limit: u32,
    pub hourly_limit: u32,
    pub used_today: u32,
    pub used_this_hour: u32,
    pub last_day_reset: u64,
    pub last_hour_reset: u64,
}

impl AgentQuota {
    pub fn new(agent_id: &str, daily: u32, hourly: u32) -> Self { AgentQuota { agent_id: agent_id.to_string(), daily_limit: daily, hourly_limit: hourly, used_today: 0, used_this_hour: 0, last_day_reset: now(), last_hour_reset: now() } }

    /// Try to use quota
    pub fn consume(&mut self) -> QuotaResult {
        self.reset_if_needed();
        if self.used_today >= self.daily_limit { return QuotaResult::DailyExhausted; }
        if self.used_this_hour >= self.hourly_limit { return QuotaResult::HourlyExhausted; }
        self.used_today += 1;
        self.used_this_hour += 1;
        QuotaResult::Allowed
    }

    fn reset_if_needed(&mut self) {
        let now = now();
        if now - self.last_day_reset >= 86_400_000 { self.used_today = 0; self.last_day_reset = now; }
        if now - self.last_hour_reset >= 3_600_000 { self.used_this_hour = 0; self.last_hour_reset = now; }
    }

    pub fn remaining_daily(&self) -> u32 { self.daily_limit.saturating_sub(self.used_today) }
    pub fn remaining_hourly(&self) -> u32 { self.hourly_limit.saturating_sub(self.used_this_hour) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaResult { Allowed, HourlyExhausted, DailyExhausted }

/// Backpressure signal
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backpressure { Green, Yellow, Red }

/// The rate limiter
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimiter {
    pub buckets: HashMap<String, TokenBucket>,
    pub windows: HashMap<String, SlidingWindow>,
    pub quotas: HashMap<String, AgentQuota>,
    pub total_allowed: u64,
    pub total_rejected: u64,
}

impl RateLimiter {
    pub fn new() -> Self { RateLimiter { buckets: HashMap::new(), windows: HashMap::new(), quotas: HashMap::new(), total_allowed: 0, total_rejected: 0 } }

    /// Add a token bucket
    pub fn add_bucket(&mut self, name: &str, max_tokens: f64, refill_rate: f64) {
        self.buckets.insert(name.to_string(), TokenBucket::new(max_tokens, refill_rate));
    }

    /// Add a sliding window
    pub fn add_window(&mut self, name: &str, max_requests: u32, window_ms: u64) {
        self.windows.insert(name.to_string(), SlidingWindow::new(max_requests, window_ms));
    }

    /// Add agent quota
    pub fn add_quota(&mut self, agent_id: &str, daily: u32, hourly: u32) {
        self.quotas.insert(agent_id.to_string(), AgentQuota::new(agent_id, daily, hourly));
    }

    /// Check all rate limits for a request
    pub fn check(&mut self, bucket_name: &str, window_name: &str, tokens: f64) -> bool {
        // Check token bucket
        if let Some(bucket) = self.buckets.get_mut(bucket_name) {
            if !bucket.consume(tokens) { self.total_rejected += 1; return false; }
        }
        // Check sliding window
        if let Some(window) = self.windows.get_mut(window_name) {
            if !window.allow() { self.total_rejected += 1; return false; }
        }
        self.total_allowed += 1;
        true
    }

    /// Check agent quota
    pub fn check_quota(&mut self, agent_id: &str) -> QuotaResult {
        if let Some(quota) = self.quotas.get_mut(agent_id) { quota.consume() }
        else { QuotaResult::Allowed }
    }

    /// Overall backpressure signal
    pub fn backpressure(&self) -> Backpressure {
        let bucket_pressure: f64 = self.buckets.values().map(|b| b.utilization()).sum::<f64>() / self.buckets.len().max(1) as f64;
        if bucket_pressure > 0.8 { Backpressure::Red }
        else if bucket_pressure > 0.5 { Backpressure::Yellow }
        else { Backpressure::Green }
    }

    /// Summary
    pub fn summary(&self) -> String {
        let bp = match self.backpressure() { Backpressure::Green => "🟢", Backpressure::Yellow => "🟡", Backpressure::Red => "🔴" };
        format!("RateLimiter: {} buckets, {} windows, {} quotas, allowed={}, rejected={} {}",
            self.buckets.len(), self.windows.len(), self.quotas.len(),
            self.total_allowed, self.total_rejected, bp)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        assert!(bucket.consume(5.0));
        assert!(bucket.consume(5.0));
        assert!(!bucket.consume(1.0)); // empty
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(3, 60_000);
        assert!(window.allow());
        assert!(window.allow());
        assert!(window.allow());
        assert!(!window.allow()); // 4th in window
    }

    #[test]
    fn test_agent_quota() {
        let mut quota = AgentQuota::new("a1", 100, 10);
        for _ in 0..10 { assert_eq!(quota.consume(), QuotaResult::Allowed); }
        assert_eq!(quota.consume(), QuotaResult::HourlyExhausted);
    }

    #[test]
    fn test_combined_check() {
        let mut rl = RateLimiter::new();
        rl.add_bucket("api", 2.0, 0.0);
        rl.add_window("requests", 100, 60_000);
        assert!(rl.check("api", "requests", 1.0));
        assert!(rl.check("api", "requests", 1.0));
        assert!(!rl.check("api", "requests", 1.0)); // bucket empty
    }

    #[test]
    fn test_backpressure_green() {
        let mut rl = RateLimiter::new();
        rl.add_bucket("api", 100.0, 10.0);
        rl.check("api", "requests", 1.0);
        assert_eq!(rl.backpressure(), Backpressure::Green);
    }

    #[test]
    fn test_quota_tracking() {
        let mut rl = RateLimiter::new();
        rl.add_quota("a1", 1000, 100);
        assert_eq!(rl.check_quota("a1"), QuotaResult::Allowed);
    }

    #[test]
    fn test_window_remaining() {
        let mut window = SlidingWindow::new(5, 60_000);
        for _ in 0..3 { window.allow(); }
        assert_eq!(window.remaining(), 2);
    }

    #[test]
    fn test_bucket_utilization() {
        let mut bucket = TokenBucket::new(10.0, 0.0);
        bucket.consume(5.0);
        assert!((bucket.utilization() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_summary() {
        let rl = RateLimiter::new();
        let s = rl.summary();
        assert!(s.contains("0 buckets"));
    }
}
