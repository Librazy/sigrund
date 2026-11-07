//! Bounded host account-file lookup on the request's reserved I/O worker.
use sigrund_core::host::{Account, credentials};
use std::{
    io::{self, Read},
    path::Path,
};
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn account_file(path: &Path) -> io::Result<String> {
    let mut file = crate::startup::open_pinned(path)?;
    crate::startup::check_root_metadata(&file, false, None)?;
    let mut bytes = Vec::new();
    (&mut file).take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err(invalid("account file exceeds bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("account file is not UTF-8"))
}
pub fn resolve(account: &Account) -> io::Result<(u32, u32, Vec<u32>)> {
    account.validate().map_err(io::Error::other)?;
    if let Account::Numeric {
        uid,
        gid,
        supplementary_gids,
    } = account
    {
        return Ok((*uid, *gid, supplementary_gids.clone()));
    }
    let Account::Name { name } = account else {
        unreachable!()
    };
    let passwd = account_file(Path::new("/etc/passwd"))?;
    let groups = account_file(Path::new("/etc/group"))?;
    parse(name, &passwd, &groups)
}
fn parse(name: &str, passwd: &str, groups: &str) -> io::Result<(u32, u32, Vec<u32>)> {
    let mut selected = None;
    for line in passwd.lines() {
        if line.len() > 4096 {
            return Err(invalid("account row exceeds bound"));
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() != Some(&name) {
            continue;
        }
        if fields.len() != 7 || selected.is_some() {
            return Err(invalid("ambiguous account record"));
        }
        selected = Some((
            fields[2]
                .parse::<u32>()
                .map_err(|_| invalid("invalid account UID"))?,
            fields[3]
                .parse::<u32>()
                .map_err(|_| invalid("invalid account GID"))?,
        ));
    }
    let (uid, gid) = selected.ok_or_else(|| invalid("unknown destination account"))?;
    let mut supplementary = Vec::new();
    for line in groups.lines() {
        if line.len() > 4096 {
            return Err(invalid("group row exceeds bound"));
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 4 {
            return Err(invalid("invalid group record"));
        }
        if fields[3].split(',').any(|member| member == name) {
            let group: u32 = fields[2]
                .parse()
                .map_err(|_| invalid("invalid supplementary GID"))?;
            supplementary.push(group);
            if supplementary.len() > 64 {
                return Err(invalid("too many supplementary groups"));
            }
        }
    }
    supplementary.sort_unstable();
    supplementary.dedup();
    credentials(uid, gid, &supplementary).map_err(io::Error::other)?;
    Ok((uid, gid, supplementary))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_lookup_is_exact_bounded_and_never_falls_back_to_nss() {
        assert_eq!(
            parse(
                "alice",
                "alice:x:1001:1002::/:/bin/sh\n",
                "staff:x:10:alice,bob\nusers:x:20:alice\n"
            )
            .unwrap(),
            (1001, 1002, vec![10, 20])
        );
        assert!(
            parse(
                "alice",
                "alice:x:1:1::/:/bin/sh\nalice:x:2:2::/:/bin/sh\n",
                ""
            )
            .is_err()
        );
        assert!(parse("missing", "alice:x:1:1::/:/bin/sh\n", "").is_err());
        assert!(
            parse(
                "alice",
                "alice:x:1:1::/:/bin/sh\n",
                "staff:x:4294967295:alice\n"
            )
            .is_err()
        );
    }
}
