//! App Context extension support for ksud.
//!
//! Provides Rust bindings for the KSU_EXTENSION_APP_CONTEXT kernel API.
//! Manages per-UID context information: foreground state, app profile,
//! and custom tags.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{Context, Result};

#[cfg(target_os = "android")]
use crate::ksucalls;

#[cfg(target_os = "android")]
use crate::ksu_uapi as uapi;

#[cfg(target_os = "android")]
type AppContextEntry = uapi::ksu_app_context_entry;

#[cfg(target_os = "android")]
fn execute(cmd: &mut uapi::ksu_app_context_cmd) -> Result<()> {
    // SAFETY: bindgen supplies the exact UAPI layout. Nested list buffers, when
    // present, remain allocated until the synchronous ioctl returns.
    let ret = unsafe { ksucalls::app_context_io(cmd) }?;
    anyhow::ensure!(
        ret == 0,
        "App Context ioctl returned unexpected status {ret}"
    );
    Ok(())
}

#[cfg(target_os = "android")]
const fn command(op: u32) -> uapi::ksu_app_context_cmd {
    // SAFETY: the UAPI command contains only integers and integer-only unions.
    let mut cmd: uapi::ksu_app_context_cmd = unsafe { std::mem::zeroed() };
    cmd.op = op;
    cmd
}

#[cfg(target_os = "android")]
fn query_context(uid: u32) -> Result<AppContextEntry> {
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_QUERY);
    cmd.payload.query = uapi::ksu_app_context_query_cmd {
        uid,
        reserved: 0,
        // SAFETY: the returned entry consists entirely of integer fields.
        entry: unsafe { std::mem::zeroed() },
    };
    execute(&mut cmd).with_context(|| format!("Failed to query UID {uid}"))?;
    // SAFETY: QUERY writes the query arm of the UAPI union.
    Ok(unsafe { cmd.payload.query.entry })
}

#[cfg(target_os = "android")]
fn set_foreground(uid: u32, foreground: bool) -> Result<()> {
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_SET_FG);
    cmd.payload.set_fg = uapi::ksu_app_context_set_fg_cmd {
        uid,
        foreground: u32::from(foreground),
    };
    execute(&mut cmd)
}

#[cfg(target_os = "android")]
fn set_profile(uid: u32, profile_id: u32) -> Result<()> {
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_SET_PROFILE);
    cmd.payload.set_profile = uapi::ksu_app_context_set_profile_cmd { uid, profile_id };
    execute(&mut cmd)
}

#[cfg(target_os = "android")]
fn change_tags(uid: u32, tag_mask: u64, clear: bool) -> Result<()> {
    let mut cmd = command(if clear {
        uapi::KSU_APP_CONTEXT_OP_CLEAR_TAG
    } else {
        uapi::KSU_APP_CONTEXT_OP_SET_TAG
    });
    cmd.payload.tag = uapi::ksu_app_context_tag_cmd {
        uid,
        reserved: 0,
        tag_mask,
    };
    execute(&mut cmd)
}

#[cfg(target_os = "android")]
fn list_contexts() -> Result<Vec<AppContextEntry>> {
    // SAFETY: AppContextEntry contains only integer fields.
    let empty: AppContextEntry = unsafe { std::mem::zeroed() };
    let mut entries = vec![empty; uapi::KSU_APP_CONTEXT_MAX_ENTRIES as usize];
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_LIST);
    cmd.payload.list = uapi::ksu_app_context_list_cmd {
        buffer: entries.as_mut_ptr() as u64,
        max_count: uapi::KSU_APP_CONTEXT_MAX_ENTRIES,
        out_count: 0,
    };
    execute(&mut cmd).context("Failed to list App Context records")?;
    // SAFETY: LIST writes the list arm of the UAPI union.
    let count = unsafe { cmd.payload.list.out_count } as usize;
    anyhow::ensure!(
        count <= entries.len(),
        "Kernel returned invalid App Context count"
    );
    entries.truncate(count);
    entries.sort_unstable_by_key(|entry| entry.uid);
    Ok(entries)
}

#[cfg(target_os = "android")]
fn remove_context(uid: u32) -> Result<()> {
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_REMOVE);
    cmd.payload.remove = uapi::ksu_app_context_remove_cmd { uid, reserved: 0 };
    execute(&mut cmd)
}

/// JSON uses strings for 64-bit values so consumers never lose integer precision.
#[cfg(target_os = "android")]
fn entry_json(entry: &AppContextEntry) -> serde_json::Value {
    serde_json::json!({
        "uid": entry.uid,
        "foreground": entry.foreground != 0,
        "profile_id": entry.profile_id,
        "tags": format!("0x{:016x}", entry.tags),
        "last_update_ns": entry.last_update_ns.to_string(),
    })
}

#[cfg(target_os = "android")]
pub fn clear_all_cli() -> Result<()> {
    execute(&mut command(uapi::KSU_APP_CONTEXT_OP_CLEAR_ALL))?;
    println!("Cleared all App Context records");
    Ok(())
}

// CLI commands

/// Query and display a UID's context.
#[cfg(target_os = "android")]
pub fn query_context_cli(uid: u32, json: bool) -> Result<()> {
    let entry = query_context(uid)?;
    if json {
        println!(
            "{}",
            serde_json::json!({"version": 1, "entry": entry_json(&entry)})
        );
        return Ok(());
    }

    println!("UID: {}", entry.uid);
    println!(
        "Foreground: {}",
        if entry.foreground != 0 { "yes" } else { "no" }
    );
    println!("Profile ID: {}", entry.profile_id);
    println!("Tags: 0x{:016x}", entry.tags);
    println!("Last update: {} ns", entry.last_update_ns);

    Ok(())
}

/// Set foreground state via CLI.
#[cfg(target_os = "android")]
pub fn set_foreground_cli(uid: u32, foreground: bool) -> Result<()> {
    set_foreground(uid, foreground)?;
    println!(
        "Set UID {} foreground state to {}",
        uid,
        if foreground { "true" } else { "false" }
    );
    Ok(())
}

/// Set profile via CLI.
#[cfg(target_os = "android")]
pub fn set_profile_cli(uid: u32, profile_id: u32) -> Result<()> {
    set_profile(uid, profile_id)?;
    println!("Set UID {uid} profile to {profile_id}");
    Ok(())
}

/// Set tags via CLI.
#[cfg(target_os = "android")]
pub fn set_tag_cli(uid: u32, tag_mask: u64) -> Result<()> {
    change_tags(uid, tag_mask, false)?;
    println!("Set UID {uid} tags: 0x{tag_mask:016x}");
    Ok(())
}

/// Clear tags via CLI.
#[cfg(target_os = "android")]
pub fn clear_tag_cli(uid: u32, tag_mask: u64) -> Result<()> {
    change_tags(uid, tag_mask, true)?;
    println!("Cleared UID {uid} tags: 0x{tag_mask:016x}");
    Ok(())
}

/// List all contexts via CLI.
#[cfg(target_os = "android")]
pub fn list_contexts_cli(json: bool) -> Result<()> {
    let entries = list_contexts()?;
    if json {
        let records: Vec<_> = entries.iter().map(entry_json).collect();
        println!("{}", serde_json::json!({"version": 1, "entries": records}));
        return Ok(());
    }

    if entries.is_empty() {
        println!("No app contexts found");
        return Ok(());
    }

    println!("App Contexts ({} entries):", entries.len());
    println!("{}", "=".repeat(80));

    for entry in entries {
        println!(
            "UID: {:<6} FG: {:<3} Profile: {:<4} Tags: 0x{:016x}",
            entry.uid,
            if entry.foreground != 0 { "yes" } else { "no" },
            entry.profile_id,
            entry.tags
        );
    }

    Ok(())
}

/// Remove a context via CLI.
#[cfg(target_os = "android")]
pub fn remove_context_cli(uid: u32) -> Result<()> {
    remove_context(uid)?;
    println!("Removed context for UID {uid}");
    Ok(())
}

/// All supplied fields are replaced in one kernel transaction. Old kernels
/// reject the new opcode; deliberately do not fall back to non-atomic writes.
#[cfg(target_os = "android")]
pub fn transact_cli(
    uid: u32,
    create: bool,
    revision: Option<u64>,
    foreground: Option<bool>,
    profile: Option<u32>,
    tags: Option<u64>,
) -> Result<()> {
    let mut cmd = command(uapi::KSU_APP_CONTEXT_OP_TRANSACT);
    let fields = foreground.map_or(0, |_| uapi::KSU_APP_CONTEXT_FIELD_FG)
        | profile.map_or(0, |_| uapi::KSU_APP_CONTEXT_FIELD_PROFILE)
        | tags.map_or(0, |_| uapi::KSU_APP_CONTEXT_FIELD_TAGS);
    anyhow::ensure!(fields != 0, "Supply at least one field");
    anyhow::ensure!(create != revision.is_some(), "Use --create or --revision");
    cmd.payload.transaction = uapi::ksu_app_context_transaction_cmd {
        uid,
        flags: if create {
            uapi::KSU_APP_CONTEXT_TX_CREATE
        } else {
            0
        },
        fields,
        foreground: u32::from(foreground.unwrap_or(false)),
        profile_id: profile.unwrap_or(0),
        reserved: 0,
        expected_revision: revision.unwrap_or(0),
        tags: tags.unwrap_or(0),
        revision: 0,
        // SAFETY: UAPI entries contain only integer fields.
        entry: unsafe { std::mem::zeroed() },
    };
    execute(&mut cmd)
        .context("Atomic App Context transaction failed (matching kernel required)")?;
    // SAFETY: TRANSACT writes the transaction union arm.
    let result = unsafe { cmd.payload.transaction };
    println!(
        "{}",
        serde_json::json!({
            "version": 1, "exists": true, "revision": result.revision.to_string(),
            "entry": entry_json(&result.entry),
        })
    );
    Ok(())
}

#[cfg(target_os = "android")]
pub fn versioned_cli(uid: u32, revision: u64, op: u32) -> Result<()> {
    let mut cmd = command(op);
    cmd.payload.versioned = uapi::ksu_app_context_versioned_cmd {
        uid,
        reserved: 0,
        expected_revision: revision,
        revision: 0,
        exists: 0,
        reserved2: 0,
        // SAFETY: UAPI entries contain only integer fields.
        entry: unsafe { std::mem::zeroed() },
    };
    execute(&mut cmd)
        .context("Versioned App Context operation failed (stale receipt or unsupported kernel)")?;
    // SAFETY: all versioned ops write this union arm.
    let result = unsafe { cmd.payload.versioned };
    println!(
        "{}",
        serde_json::json!({
            "version": 1, "exists": result.exists != 0,
            "revision": result.revision.to_string(),
            "entry": if result.exists != 0 { entry_json(&result.entry) } else { serde_json::Value::Null },
        })
    );
    Ok(())
}

/// Parse a tag mask from string (supports hex: 0x... or decimal).
pub fn parse_tag_mask(s: &str) -> Result<u64> {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || {
                s.parse::<u64>()
                    .with_context(|| format!("Invalid decimal tag mask: {s}"))
            },
            |hex| {
                u64::from_str_radix(hex, 16).with_context(|| format!("Invalid hex tag mask: {s}"))
            },
        )
}

#[cfg(test)]
mod tests {
    use super::parse_tag_mask;

    #[test]
    fn tag_masks_cover_all_bits() {
        assert_eq!(parse_tag_mask("0xffffffffffffffff").unwrap(), u64::MAX);
        assert_eq!(parse_tag_mask("0X8000000000000000").unwrap(), 1_u64 << 63);
        assert_eq!(parse_tag_mask("18446744073709551615").unwrap(), u64::MAX);
        for invalid in [
            "-1",
            "0x",
            "0x10000000000000000",
            "18446744073709551616",
            "abc",
        ] {
            assert!(parse_tag_mask(invalid).is_err(), "{invalid}");
        }
    }
}
