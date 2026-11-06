//! Frozen draft grammar only; production sigrun/sigrundctl do not call this.
use crate::contracts::{Account, Contract, Intent, Selector, identifier};
use sigrund_core::{CoreError, Result};
use std::collections::BTreeMap;

pub fn parse(args: &[String]) -> Result<Intent> {
    let bad = || CoreError::Value("invalid phase0 selection grammar".into());
    let mut options = BTreeMap::new();
    if !args.len().is_multiple_of(2) {
        return Err(bad());
    }
    for pair in args.as_chunks::<2>().0 {
        if ![
            "--target",
            "--account",
            "--target-uid",
            "--target-gid",
            "--supplementary-gids",
            "--security-profile",
        ]
        .contains(&pair[0].as_str())
            || pair[1].is_empty()
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(bad());
        }
    }
    let target = match *options.get("--target").ok_or_else(bad)? {
        "host" => Selector::Host {},
        "self" => Selector::Self_ {},
        value if value.starts_with("registered:") => Selector::Registered {
            id: value[11..].into(),
        },
        value if value.starts_with("process:") => Selector::Process {
            pid: value[8..].parse().map_err(|_| bad())?,
            pid_scope: "daemon".into(),
        },
        _ => return Err(bad()),
    };
    let number =
        |key| -> Result<u32> { options.get(key).ok_or_else(bad)?.parse().map_err(|_| bad()) };
    let account = if let Some(name) = options.get("--account") {
        if options.contains_key("--target-uid")
            || options.contains_key("--target-gid")
            || options.contains_key("--supplementary-gids")
        {
            return Err(bad());
        }
        Account::Name {
            name: (*name).into(),
        }
    } else {
        let mut groups = match options.get("--supplementary-gids") {
            Some(value) => value
                .split(',')
                .map(|s| s.parse().map_err(|_| bad()))
                .collect::<Result<Vec<u32>>>()?,
            None => vec![],
        };
        groups.sort_unstable();
        if groups.windows(2).any(|w| w[0] == w[1]) {
            return Err(bad());
        }
        Account::Numeric {
            uid: number("--target-uid")?,
            gid: number("--target-gid")?,
            supplementary_gids: groups,
        }
    };
    let result = Intent {
        target,
        account,
        security_profile: (*options.get("--security-profile").ok_or_else(bad)?).into(),
    };
    result.validate()?;
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Management {
    Register {
        id: String,
        pid: u32,
        owner_uid: u32,
        profile: String,
    },
    Revoke {
        id: String,
    },
    ExportBinding {
        id: String,
        output: String,
    },
}
pub fn management(args: &[String]) -> Result<Management> {
    let bad = || CoreError::Value("invalid phase0 management grammar".into());
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [
            "target",
            "register",
            id,
            "--pid",
            pid,
            "--owner-uid",
            owner,
            "--security-profile",
            profile,
        ] => {
            identifier(id)?;
            identifier(profile)?;
            let pid = pid.parse::<u32>().map_err(|_| bad())?;
            let owner_uid = owner.parse::<u32>().map_err(|_| bad())?;
            if owner_uid == u32::MAX {
                return Err(bad());
            }
            Selector::Process {
                pid,
                pid_scope: "daemon".into(),
            }
            .validate()?;
            Management::Register {
                id: (*id).into(),
                pid,
                owner_uid,
                profile: (*profile).into(),
            }
        }
        ["target", "revoke", id] => {
            identifier(id)?;
            Management::Revoke { id: (*id).into() }
        }
        ["target", "export-binding", id, "--output", output] if output.starts_with('/') => {
            identifier(id)?;
            if output.chars().any(char::is_control)
                || output
                    .split('/')
                    .skip(1)
                    .any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err(bad());
            }
            Management::ExportBinding {
                id: (*id).into(),
                output: (*output).into(),
            }
        }
        _ => return Err(bad()),
    };
    Ok(result)
}
