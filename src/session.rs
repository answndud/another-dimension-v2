//! Bearer-session bookkeeping for the local web API.
//!
//! A session is a random token the browser receives after entering the one-time
//! connection code. Sessions expire when idle, expire after a fixed lifetime no
//! matter how active they are, and are capped in number. Every method takes the
//! current time so expiry can be tested without waiting.

use std::time::{Duration, Instant};

/// A session that has not been used for this long is dropped.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// A session never lives longer than this, however active it is.
pub(crate) const MAX_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Issuing a session beyond this count evicts the least recently used one.
pub(crate) const MAX_SESSIONS: usize = 4;

struct Session {
    token: String,
    created: Instant,
    last_used: Instant,
}

impl Session {
    fn is_live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) < MAX_LIFETIME
            && now.saturating_duration_since(self.last_used) < IDLE_TIMEOUT
    }
}

#[derive(Default)]
pub(crate) struct SessionStore {
    sessions: Vec<Session>,
}

impl SessionStore {
    /// Registers a new session, dropping expired ones and the least recently
    /// used session if the cap would be exceeded.
    pub(crate) fn issue(&mut self, token: String, now: Instant) {
        self.sessions.retain(|session| session.is_live(now));
        self.sessions.push(Session {
            token,
            created: now,
            last_used: now,
        });
        while self.sessions.len() > MAX_SESSIONS {
            if let Some(oldest) = self
                .sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, session)| session.last_used)
                .map(|(index, _)| index)
            {
                self.sessions.remove(oldest);
            }
        }
    }

    /// Returns whether `token` names a live session and, if so, counts the
    /// request as activity. Expired sessions are removed on the way.
    pub(crate) fn authorize(&mut self, token: &str, now: Instant) -> bool {
        self.sessions.retain(|session| session.is_live(now));
        match self
            .sessions
            .iter_mut()
            .find(|session| crate::equal_token(&session.token, token))
        {
            Some(session) => {
                session.last_used = now;
                true
            }
            None => false,
        }
    }

    pub(crate) fn revoke(&mut self, token: &str) {
        self.sessions
            .retain(|session| !crate::equal_token(&session.token, token));
    }

    pub(crate) fn revoke_all(&mut self) {
        self.sessions.clear();
    }

    #[cfg(test)]
    pub(crate) fn with_token(token: &str) -> Self {
        let mut store = Self::default();
        store.issue(token.to_owned(), Instant::now());
        store
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minutes(count: u64) -> Duration {
        Duration::from_secs(count * 60)
    }

    #[test]
    fn issued_token_authorizes_and_unknown_token_does_not() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("alpha".to_owned(), start);
        assert!(store.authorize("alpha", start));
        assert!(!store.authorize("beta", start));
        assert!(!store.authorize("", start));
    }

    #[test]
    fn idle_session_expires_but_activity_keeps_it_alive() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("alpha".to_owned(), start);
        // Each use restarts the idle clock, so 50-minute gaps never expire it.
        assert!(store.authorize("alpha", start + minutes(50)));
        assert!(store.authorize("alpha", start + minutes(100)));
        // A gap longer than the idle timeout does.
        assert!(!store.authorize("alpha", start + minutes(100) + IDLE_TIMEOUT));
        assert_eq!(store.len(), 0, "an expired session is removed");
    }

    #[test]
    fn idle_timeout_boundary_is_exclusive() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("alpha".to_owned(), start);
        assert!(store.authorize("alpha", start + IDLE_TIMEOUT - Duration::from_secs(1)));
        let mut store = SessionStore::default();
        store.issue("alpha".to_owned(), start);
        assert!(!store.authorize("alpha", start + IDLE_TIMEOUT));
    }

    #[test]
    fn lifetime_limit_applies_even_to_a_constantly_used_session() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("alpha".to_owned(), start);
        let mut elapsed = Duration::ZERO;
        while elapsed + minutes(30) < MAX_LIFETIME {
            elapsed += minutes(30);
            assert!(store.authorize("alpha", start + elapsed), "{elapsed:?}");
        }
        assert!(!store.authorize("alpha", start + MAX_LIFETIME));
    }

    #[test]
    fn issuing_past_the_cap_evicts_the_least_recently_used_session() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        for (index, token) in ["a", "b", "c", "d"].iter().enumerate() {
            store.issue(
                (*token).to_owned(),
                start + Duration::from_secs(index as u64),
            );
        }
        // Using "a" makes "b" the least recently used.
        assert!(store.authorize("a", start + Duration::from_secs(10)));
        store.issue("e".to_owned(), start + Duration::from_secs(11));
        assert_eq!(store.len(), MAX_SESSIONS);
        let later = start + Duration::from_secs(12);
        assert!(
            !store.authorize("b", later),
            "the least recently used one is evicted"
        );
        for token in ["a", "c", "d", "e"] {
            assert!(store.authorize(token, later), "{token}");
        }
    }

    #[test]
    fn expired_sessions_do_not_count_toward_the_cap() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        for token in ["a", "b", "c", "d"] {
            store.issue(token.to_owned(), start);
        }
        let later = start + IDLE_TIMEOUT + minutes(1);
        store.issue("fresh".to_owned(), later);
        assert_eq!(store.len(), 1);
        assert!(store.authorize("fresh", later));
    }

    #[test]
    fn revoking_one_session_leaves_the_others() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("a".to_owned(), start);
        store.issue("b".to_owned(), start);
        store.revoke("a");
        assert!(!store.authorize("a", start));
        assert!(store.authorize("b", start));
        store.revoke("missing");
        assert!(store.authorize("b", start));
    }

    #[test]
    fn revoke_all_removes_every_session() {
        let start = Instant::now();
        let mut store = SessionStore::default();
        store.issue("a".to_owned(), start);
        store.issue("b".to_owned(), start);
        store.revoke_all();
        assert!(!store.authorize("a", start));
        assert!(!store.authorize("b", start));
        assert_eq!(store.len(), 0);
    }
}
