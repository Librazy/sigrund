use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{CoreError, Result, crypto::sha256_hex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantMode {
    OneTime,
    TimeRange,
    Permanent,
}

impl GrantMode {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationResult {
    Allowed,
    ExpiredOrNotYetValid,
    Revoked,
    ReplayDetected,
}

pub struct StateStore {
    connection: Connection,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path).map_err(db)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA busy_timeout = 5000;
                 CREATE TABLE IF NOT EXISTS consumed_grants (
                     grant_id TEXT PRIMARY KEY,
                     payload_sha256 BLOB NOT NULL UNIQUE,
                     signer_id TEXT NOT NULL,
                     requester_uid INTEGER NOT NULL,
                     not_after INTEGER NOT NULL,
                     consumed_at INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS revocations (
                     target_type TEXT NOT NULL CHECK (target_type IN ('grant_id', 'payload_sha256', 'signer_id')),
                     target_value TEXT NOT NULL,
                     revoked_at INTEGER NOT NULL,
                     reason TEXT NOT NULL,
                     PRIMARY KEY (target_type, target_value)
                 ) STRICT;",
            )
            .map_err(db)?;
        Ok(Self { connection })
    }

    pub fn authorize(
        &mut self,
        grant_id: &str,
        payload: &[u8],
        signer_id: &str,
        requester_uid: u32,
        mode: GrantMode,
        not_before: i64,
        not_after: Option<i64>,
        now: i64,
    ) -> Result<AuthorizationResult> {
        if mode == GrantMode::Permanent && not_after.is_some() {
            return Err(CoreError::Value(
                "permanent grants require null not_after".into(),
            ));
        }
        let digest = sha256_hex(payload);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        if now < not_before || mode != GrantMode::Permanent && now > not_after.unwrap_or(i64::MIN) {
            transaction.rollback().map_err(db)?;
            return Ok(AuthorizationResult::ExpiredOrNotYetValid);
        }
        let revoked = transaction
            .query_row(
                "SELECT 1 FROM revocations
                 WHERE (target_type = 'grant_id' AND target_value = ?1)
                    OR (target_type = 'payload_sha256' AND target_value = ?2)
                    OR (target_type = 'signer_id' AND target_value = ?3)
                 LIMIT 1",
                params![grant_id, digest, signer_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(db)?
            .is_some();
        if revoked {
            transaction.rollback().map_err(db)?;
            return Ok(AuthorizationResult::Revoked);
        }
        if mode == GrantMode::OneTime {
            let inserted = transaction.execute(
                "INSERT INTO consumed_grants
                 (grant_id, payload_sha256, signer_id, requester_uid, not_after, consumed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    grant_id,
                    payload,
                    signer_id,
                    requester_uid,
                    not_after.unwrap_or(0),
                    now
                ],
            );
            if inserted.is_err() {
                transaction.rollback().map_err(db)?;
                return Ok(AuthorizationResult::ReplayDetected);
            }
        }
        transaction.commit().map_err(db)?;
        Ok(AuthorizationResult::Allowed)
    }

    pub fn revoke(
        &self,
        target_type: &str,
        target_value: &str,
        now: i64,
        reason: &str,
    ) -> Result<()> {
        let normalized = if target_type == "payload_sha256" {
            let lower = target_value.to_ascii_lowercase();
            if lower.len() != 64 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(CoreError::Value(
                    "digest revocation must be 64 hex digits".into(),
                ));
            }
            lower
        } else {
            target_value.to_owned()
        };
        self.connection
            .execute(
                "INSERT OR REPLACE INTO revocations (target_type, target_value, revoked_at, reason)
                 VALUES (?1, ?2, ?3, ?4)",
                params![target_type, normalized, now, reason],
            )
            .map_err(db)?;
        Ok(())
    }
}

fn db(error: rusqlite::Error) -> CoreError {
    CoreError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_grants_are_consumed_once() {
        let mut store = StateStore::open(":memory:").unwrap();
        let first = store
            .authorize(
                "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                b"payload",
                "signer",
                1001,
                GrantMode::OneTime,
                1,
                Some(10),
                2,
            )
            .unwrap();
        let second = store
            .authorize(
                "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                b"payload",
                "signer",
                1001,
                GrantMode::OneTime,
                1,
                Some(10),
                2,
            )
            .unwrap();
        assert_eq!(first, AuthorizationResult::Allowed);
        assert_eq!(second, AuthorizationResult::ReplayDetected);
    }

    #[test]
    fn digest_revocations_normalize_case() {
        let mut store = StateStore::open(":memory:").unwrap();
        let digest = sha256_hex(b"payload");
        store
            .revoke("payload_sha256", &digest.to_ascii_uppercase(), 1, "test")
            .unwrap();
        assert_eq!(
            store
                .authorize(
                    "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                    b"payload",
                    "signer",
                    1001,
                    GrantMode::TimeRange,
                    1,
                    Some(10),
                    2
                )
                .unwrap(),
            AuthorizationResult::Revoked
        );
    }
}
