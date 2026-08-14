//! Wall-clock time, portably.
//!
//! `std::time::SystemTime::now()` does not merely return a wrong value on
//! `wasm32-unknown-unknown` — it **traps** (`RuntimeError: unreachable`), because
//! the bare wasm target has no clock at all. Verified empirically, not assumed.
//!
//! That makes it exactly the kind of bug a build gate cannot catch: the code
//! compiles for wasm32 without a murmur and dies the first time a history marker
//! is written. Every wall-clock read in the vault's wasm dependency graph goes
//! through [`now_ms`] so there is one place to get this right.
//!
//! This is a *wall* clock (epoch milliseconds), not a monotonic one. It is used
//! for history markers and snapshot-retention cut-offs, both of which are
//! advisory ordering hints — nothing security-critical depends on it, and
//! nothing should: in the browser `Date.now()` is attacker-settable by the page.

/// Milliseconds since the Unix epoch, or `0` if the platform clock is unusable.
///
/// The `0` fallback matches the behaviour every call site already had (they all
/// did `.unwrap_or(0)` on a pre-epoch `SystemTime`), so a broken clock degrades
/// rather than panicking.
#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Browser/node build: `Date.now()`, which every JS host provides — window,
/// Web Worker (where roam actually runs, see `vfs`), and node alike.
#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

#[cfg(test)]
mod tests {
    /// A clock that returns 0 would satisfy any "it compiles" check while
    /// silently flattening every history marker to the epoch, so assert the
    /// value is actually a plausible present-day timestamp.
    #[test]
    fn now_ms_is_a_plausible_wall_clock_reading() {
        let now = super::now_ms();
        // 2020-01-01 .. 2100-01-01. Wide enough never to age out, narrow enough
        // to catch a zero, a seconds/millis mix-up, or a nanosecond overflow.
        assert!(
            (1_577_836_800_000..4_102_444_800_000).contains(&now),
            "now_ms() returned {now}, which is not a present-day epoch-ms value"
        );
    }
}
