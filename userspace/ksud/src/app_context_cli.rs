#[derive(clap::Subcommand, Debug)]
pub enum AppContextCmd {
    /// Query a UID's context
    Query {
        /// Target UID
        uid: u32,
        /// Emit versioned JSON
        #[arg(long)]
        json: bool,
    },

    /// Set foreground state for a UID
    SetFg {
        /// Target UID
        uid: u32,
        /// Foreground state (true/false)
        #[arg(action = clap::ArgAction::Set)]
        foreground: bool,
    },

    /// Set app profile for a UID
    SetProfile {
        /// Target UID
        uid: u32,
        /// Profile ID
        profile_id: u32,
    },

    /// Set tag bits for a UID
    SetTag {
        /// Target UID
        uid: u32,
        /// Tag mask (supports hex: 0x... or decimal)
        #[arg(value_parser = crate::app_context::parse_tag_mask)]
        tag_mask: u64,
    },

    /// Clear tag bits for a UID
    ClearTag {
        /// Target UID
        uid: u32,
        /// Tag mask (supports hex: 0x... or decimal)
        #[arg(value_parser = crate::app_context::parse_tag_mask)]
        tag_mask: u64,
    },

    /// List all app contexts
    List {
        /// Emit versioned JSON
        #[arg(long)]
        json: bool,
    },

    /// Clear all records (administrative operation)
    ClearAll,

    /// Atomically replace selected fields; emits a JSON revision receipt
    Transact {
        uid: u32,
        /// Exclusively create a new UID (fails if it already exists)
        #[arg(long, conflicts_with = "revision")]
        create: bool,
        /// Expected revision of an existing record
        #[arg(long, required_unless_present = "create")]
        revision: Option<u64>,
        #[arg(long, action = clap::ArgAction::Set)]
        foreground: Option<bool>,
        #[arg(long)]
        profile: Option<u32>,
        /// Replace the entire tag mask, not OR
        #[arg(long, value_parser = crate::app_context::parse_tag_mask)]
        tags: Option<u64>,
    },

    /// Read a record with its current revision (JSON)
    QueryVersioned { uid: u32 },

    /// Undo the latest transaction only if its revision still matches
    Rollback { uid: u32, revision: u64 },

    /// Delete only if the record still has the expected revision
    RemoveVersioned { uid: u32, revision: u64 },

    /// Remove a UID's context
    Remove {
        /// Target UID
        uid: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::AppContextCmd;
    use clap::Parser;

    #[derive(Parser)]
    struct Args {
        #[command(subcommand)]
        command: AppContextCmd,
    }

    #[test]
    fn foreground_requires_explicit_boolean() {
        for (value, expected) in [("true", true), ("false", false)] {
            let args = Args::try_parse_from(["test", "set-fg", "10086", value]).unwrap();
            assert!(
                matches!(args.command, AppContextCmd::SetFg { uid: 10086, foreground } if foreground == expected)
            );
        }
        assert!(Args::try_parse_from(["test", "set-fg", "10086"]).is_err());
        assert!(Args::try_parse_from(["test", "set-fg", "10086", "yes"]).is_err());
    }

    #[test]
    fn transactions_require_create_or_revision() {
        assert!(
            Args::try_parse_from([
                "test",
                "transact",
                "42",
                "--create",
                "--foreground",
                "false"
            ])
            .is_ok()
        );
        assert!(
            Args::try_parse_from([
                "test",
                "transact",
                "42",
                "--revision",
                "18446744073709551615",
                "--profile",
                "4294967295",
                "--tags",
                "0xffffffffffffffff"
            ])
            .is_ok()
        );
        assert!(Args::try_parse_from(["test", "transact", "42", "--profile", "1"]).is_err());
        assert!(
            Args::try_parse_from(["test", "transact", "42", "--create", "--revision", "1"])
                .is_err()
        );
        assert!(Args::try_parse_from(["test", "rollback", "42", "18446744073709551615"]).is_ok());
        assert!(Args::try_parse_from(["test", "remove-versioned", "42", "1"]).is_ok());
    }

    #[test]
    fn json_and_numeric_boundaries() {
        assert!(matches!(
            Args::try_parse_from(["test", "list", "--json"])
                .unwrap()
                .command,
            AppContextCmd::List { json: true }
        ));
        assert!(Args::try_parse_from(["test", "set-profile", "10086", "4294967295"]).is_ok());
        assert!(Args::try_parse_from(["test", "set-profile", "10086", "4294967296"]).is_err());
        assert!(Args::try_parse_from(["test", "set-tag", "10086", "0xffffffffffffffff"]).is_ok());
        assert!(Args::try_parse_from(["test", "clear-all"]).is_ok());
    }
}
