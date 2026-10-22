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
