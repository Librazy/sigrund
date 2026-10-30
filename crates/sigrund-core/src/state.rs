use std::{fs::File, os::fd::AsRawFd, path::Path};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{CoreError, Result, crypto::sha256_hex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantMode {
    OneTime,
    TimeRange,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationResult {
    Allowed,
    ExpiredOrNotYetValid,
    Revoked,
    ReplayDetected,
    Cancelled,
}

pub struct AuthorizationRequest<'a> {
    pub grant_id: &'a str,
    pub payload: &'a [u8],
    pub signer_id: &'a str,
    pub requester_uid: u32,
    pub mode: GrantMode,
    pub not_before: i64,
    pub not_after: Option<i64>,
    pub now: i64,
}

pub struct StateStore {
    connection: Connection,
    // The VFS keeps all database and sidecar access relative to this FD.
    _directory: Option<File>,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(db)?;
        Self::initialize(connection, None)
    }

    /// The caller verifies directory ownership/permissions and existing files
    /// before use. SQLite must not canonicalize the deliberate procfs handle
    /// back to a replaceable pathname, including for WAL/SHM sidecars.
    pub fn open_in_directory(directory: File) -> Result<Self> {
        crate::sqlite_pinned::register()?;
        let path = format!("/proc/self/fd/{}/state.sqlite", directory.as_raw_fd());
        let connection = Connection::open_with_flags_and_vfs(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "sigrund-pinned-v1",
        )
        .map_err(db)?;
        Self::initialize(connection, Some(directory))
    }

    fn initialize(connection: Connection, directory: Option<File>) -> Result<Self> {
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
        Ok(Self {
            connection,
            _directory: directory,
        })
    }

    pub fn authorize(&mut self, request: AuthorizationRequest<'_>) -> Result<AuthorizationResult> {
        let now = request.now;
        self.authorize_guarded(request, || Ok(now), || Ok(true), || Ok(true))
    }

    /// The daemon supplies a fresh realtime sample after BEGIN IMMEDIATE has
    /// acquired the write lock. The coordinator reserves COMMIT only after
    /// all transaction predicates pass; the executor then checks cancellation
    /// once more, immediately before issuing COMMIT. Errors or a refused guard
    /// leave the transaction uncommitted and cannot consume a one-time grant.
    pub fn authorize_guarded(
        &mut self,
        request: AuthorizationRequest<'_>,
        clock: impl FnOnce() -> Result<i64>,
        reserve_commit: impl FnOnce() -> Result<bool>,
        permit_commit: impl FnOnce() -> Result<bool>,
    ) -> Result<AuthorizationResult> {
        if request.mode == GrantMode::Permanent && request.not_after.is_some() {
            return Err(CoreError::Value(
                "permanent grants require null not_after".into(),
            ));
        }
        let digest = sha256_hex(request.payload);
        let digest_bytes = Sha256::digest(request.payload);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let now = clock()?;
        if now < request.not_before
            || request.mode != GrantMode::Permanent && now > request.not_after.unwrap_or(i64::MIN)
        {
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
                params![request.grant_id, digest, request.signer_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(db)?
            .is_some();
        if revoked {
            transaction.rollback().map_err(db)?;
            return Ok(AuthorizationResult::Revoked);
        }
        if request.mode == GrantMode::OneTime {
            let inserted = transaction.execute(
                "INSERT INTO consumed_grants
                 (grant_id, payload_sha256, signer_id, requester_uid, not_after, consumed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.grant_id,
                    digest_bytes.as_slice(),
                    request.signer_id,
                    request.requester_uid,
                    request.not_after.unwrap_or(0),
                    now
                ],
            );
            if let Err(error) = inserted {
                transaction.rollback().map_err(db)?;
                return match error {
                    rusqlite::Error::SqliteFailure(ref code, _)
                        if matches!(
                            code.extended_code,
                            rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                                | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                        ) =>
                    {
                        Ok(AuthorizationResult::ReplayDetected)
                    }
                    _ => Err(db(error)),
                };
            }
        }
        if !reserve_commit()? || !permit_commit()? {
            transaction.rollback().map_err(db)?;
            return Ok(AuthorizationResult::Cancelled);
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

    fn request(grant_id: &str) -> AuthorizationRequest<'_> {
        AuthorizationRequest {
            grant_id,
            payload: b"sensitive warrant payload",
            signer_id: "signer",
            requester_uid: 1001,
            mode: GrantMode::OneTime,
            not_before: 1,
            not_after: Some(10),
            now: 2,
        }
    }

    #[test]
    fn commit_guards_rollback_without_consumption_and_run_after_predicates() {
        use std::cell::Cell;
        for reserved in [false, true] {
            let mut store = StateStore::open(":memory:").unwrap();
            let permitted = Cell::new(false);
            assert_eq!(
                store
                    .authorize_guarded(
                        request("unused"),
                        || Ok(2),
                        || Ok(reserved),
                        || {
                            permitted.set(true);
                            Ok(false)
                        }
                    )
                    .unwrap(),
                AuthorizationResult::Cancelled
            );
            assert_eq!(permitted.get(), reserved);
            assert_eq!(
                store.authorize(request("unused")).unwrap(),
                AuthorizationResult::Allowed
            );
            let reserve = || -> Result<bool> { panic!("denied transaction cannot reserve COMMIT") };
            assert_eq!(
                store
                    .authorize_guarded(request("unused"), || Ok(2), reserve, || Ok(true))
                    .unwrap(),
                AuthorizationResult::ReplayDetected
            );
        }
        let mut store = StateStore::open(":memory:").unwrap();
        store.revoke("grant_id", "revoked", 1, "fixture").unwrap();
        assert_eq!(
            store
                .authorize_guarded(
                    request("revoked"),
                    || Ok(2),
                    || panic!("revoked grant reserved commit"),
                    || Ok(true)
                )
                .unwrap(),
            AuthorizationResult::Revoked
        );
        assert_eq!(
            store
                .authorize_guarded(
                    request("expired"),
                    || Ok(11),
                    || panic!("expired grant reserved commit"),
                    || Ok(true)
                )
                .unwrap(),
            AuthorizationResult::ExpiredOrNotYetValid
        );
        assert!(
            store
                .authorize_guarded(
                    request("clock-error"),
                    || Err(CoreError::Value("clock failed".into())),
                    || Ok(true),
                    || Ok(true)
                )
                .is_err()
        );
        assert_eq!(
            store.authorize(request("clock-error")).unwrap(),
            AuthorizationResult::Allowed
        );
    }

    #[test]
    fn realtime_is_sampled_after_waiting_for_the_sqlite_write_lock() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicI64, Ordering},
                mpsc,
            },
            thread,
            time::Duration,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let mut blocker = StateStore::open(&path).unwrap();
        let mut store = StateStore::open(&path).unwrap();
        let transaction = blocker
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let clock = Arc::new(AtomicI64::new(2));
        let (started, entered) = mpsc::channel();
        let (sampled, sample) = mpsc::channel();
        let executor_clock = clock.clone();
        let executor = thread::spawn(move || {
            started.send(()).unwrap();
            store
                .authorize_guarded(
                    request("expires-while-queued"),
                    || {
                        let now = executor_clock.load(Ordering::Acquire);
                        sampled.send(now).unwrap();
                        Ok(now)
                    },
                    || panic!("expired grant reserved COMMIT"),
                    || Ok(true),
                )
                .unwrap()
        });
        entered.recv().unwrap();
        assert!(matches!(
            sample.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        clock.store(11, Ordering::Release);
        transaction.commit().unwrap();
        assert_eq!(sample.recv_timeout(Duration::from_secs(2)).unwrap(), 11);
        assert_eq!(
            executor.join().unwrap(),
            AuthorizationResult::ExpiredOrNotYetValid
        );
        assert_eq!(
            blocker.authorize(request("expires-while-queued")).unwrap(),
            AuthorizationResult::Allowed
        );
    }

    #[test]
    fn consumption_stores_raw_sha256_and_deduplicates_across_grant_ids() {
        let mut store = StateStore::open(":memory:").unwrap();
        assert_eq!(
            store.authorize(request("first")).unwrap(),
            AuthorizationResult::Allowed
        );
        let (kind, stored): (String, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT typeof(payload_sha256), payload_sha256 FROM consumed_grants",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(kind, "blob");
        assert_eq!(
            stored,
            Sha256::digest(b"sensitive warrant payload").to_vec()
        );
        assert_eq!(stored.len(), 32);
        assert_eq!(
            store.authorize(request("second")).unwrap(),
            AuthorizationResult::ReplayDetected
        );
    }

    #[test]
    fn non_unique_insertion_failure_is_a_database_error() {
        let mut store = StateStore::open(":memory:").unwrap();
        // A trigger produces a constraint error distinct from PK/UNIQUE.
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_insert BEFORE INSERT ON consumed_grants
             BEGIN SELECT RAISE(ABORT, 'injected store failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            store.authorize(request("unused")),
            Err(CoreError::Database(_))
        ));
        store
            .connection
            .execute_batch("DROP TRIGGER fail_insert;")
            .unwrap();
        assert_eq!(
            store.authorize(request("unused")).unwrap(),
            AuthorizationResult::Allowed
        );
        store
            .connection
            .execute_batch("DROP TABLE consumed_grants;")
            .unwrap();
        assert!(matches!(
            store.authorize(request("another")),
            Err(CoreError::Database(_))
        ));
    }

    #[test]
    fn one_time_grants_are_consumed_once() {
        let mut store = StateStore::open(":memory:").unwrap();
        let first = store
            .authorize(AuthorizationRequest {
                grant_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                payload: b"payload",
                signer_id: "signer",
                requester_uid: 1001,
                mode: GrantMode::OneTime,
                not_before: 1,
                not_after: Some(10),
                now: 2,
            })
            .unwrap();
        let second = store
            .authorize(AuthorizationRequest {
                grant_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                payload: b"payload",
                signer_id: "signer",
                requester_uid: 1001,
                mode: GrantMode::OneTime,
                not_before: 1,
                not_after: Some(10),
                now: 2,
            })
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
                .authorize(AuthorizationRequest {
                    grant_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
                    payload: b"payload",
                    signer_id: "signer",
                    requester_uid: 1001,
                    mode: GrantMode::TimeRange,
                    not_before: 1,
                    not_after: Some(10),
                    now: 2,
                })
                .unwrap(),
            AuthorizationResult::Revoked
        );
    }
}
