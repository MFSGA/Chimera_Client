use crate::{app::router::rules::RuleMatcher, session::Session};

pub struct ProcessRule {
    pub value: String,
    pub target: String,
    pub name_only: bool,
}

impl std::fmt::Display for ProcessRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} process {}", self.target, self.value)
    }
}

impl RuleMatcher for ProcessRule {
    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.value.clone()
    }

    fn apply(&self, session: &Session) -> bool {
        session.process_name.as_deref().is_some_and(|process| {
            if self.name_only {
                process == self.value
            } else {
                process.contains(&self.value)
            }
        })
    }

    fn type_name(&self) -> &str {
        if self.name_only {
            "ProcessName"
        } else {
            "ProcessPath"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(process: Option<&str>) -> Session {
        Session {
            process_name: process.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn name_matching_is_exact() {
        let rule = ProcessRule {
            value: "steam.exe".to_string(),
            target: "GAME".to_string(),
            name_only: true,
        };
        assert!(rule.apply(&session(Some("steam.exe"))));
        assert!(!rule.apply(&session(Some("C:\\Games\\steam.exe"))));
        assert!(!rule.apply(&session(None)));
    }

    #[test]
    fn path_matching_uses_substring() {
        let rule = ProcessRule {
            value: "Games\\Steam".to_string(),
            target: "GAME".to_string(),
            name_only: false,
        };
        assert!(rule.apply(&session(Some("C:\\Games\\Steam\\steam.exe"))));
        assert!(!rule.apply(&session(Some("C:\\Windows\\notepad.exe"))));
    }
}
