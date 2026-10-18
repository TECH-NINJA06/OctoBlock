//! Section 5 Path classes and persistence policy (`.octoblock/policy.toml`).

use octoblock_fs::page::PathClass;
use octoblock_fs::{Errno, Error, Result};
use serde::{Deserialize, Serialize};

/// A single glob rule mapping matching paths to a [`PathClass`] (Section 5.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Gitignore-style glob pattern (e.g. `"/tmp/**"`, `"**/.cache/**"`).
    pub pattern: String,
    /// Target persistence class.
    pub class: PathClassSpec,
}

/// Serializable representation of [`PathClass`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathClassSpec {
    /// Journaled, then committed to the remote repository.
    Persist,
    /// Stored on local disk sidecar only; survives reboot, not shared.
    Local,
    /// Stored in RAM only (`tmpfs`-like); cleared on unmount.
    Volatile,
    /// Refused with `EACCES`.
    Exclude,
}

impl From<PathClassSpec> for PathClass {
    fn from(spec: PathClassSpec) -> Self {
        match spec {
            PathClassSpec::Persist => PathClass::Persist,
            PathClassSpec::Local => PathClass::Local,
            PathClassSpec::Volatile => PathClass::Volatile,
            PathClassSpec::Exclude => PathClass::Exclude,
        }
    }
}

impl From<PathClass> for PathClassSpec {
    fn from(c: PathClass) -> Self {
        match c {
            PathClass::Persist => PathClassSpec::Persist,
            PathClass::Local => PathClassSpec::Local,
            PathClass::Volatile => PathClassSpec::Volatile,
            PathClass::Exclude => PathClassSpec::Exclude,
        }
    }
}

impl PathClassSpec {
    /// Strictness rank (`Persist < Local < Volatile < Exclude`) for `EC-L03` override validation.
    pub const fn strictness(self) -> u8 {
        match self {
            PathClassSpec::Persist => 0,
            PathClassSpec::Local => 1,
            PathClassSpec::Volatile => 2,
            PathClassSpec::Exclude => 3,
        }
    }
}

/// Volume persistence policy with optional stricter machine-local overrides (Section 5.2, EC-L03).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEngine {
    /// Versioned rules from `.octoblock/policy.toml`.
    pub rules: Vec<PolicyRule>,
    /// Machine-local override rules (may only move paths from `persist` toward `local`/`volatile`/`exclude`).
    #[serde(default)]
    pub local_overrides: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Default Tier 0 policy: everything `persist` except `.octoblock/` internals (Section 5.4).
    pub fn tier0_default() -> Self {
        PolicyEngine {
            rules: vec![PolicyRule {
                pattern: "/**".into(),
                class: PathClassSpec::Persist,
            }],
            local_overrides: Vec::new(),
        }
    }

    /// Default Tier 1 persistent-state overlay policy (Section 5.2, 5.4).
    pub fn tier1_default() -> Self {
        PolicyEngine {
            rules: vec![
                PolicyRule {
                    pattern: "/tmp/**".into(),
                    class: PathClassSpec::Volatile,
                },
                PolicyRule {
                    pattern: "/run/**".into(),
                    class: PathClassSpec::Volatile,
                },
                PolicyRule {
                    pattern: "/var/log/**".into(),
                    class: PathClassSpec::Local,
                },
                PolicyRule {
                    pattern: "/var/cache/**".into(),
                    class: PathClassSpec::Local,
                },
                PolicyRule {
                    pattern: "**/.cache/**".into(),
                    class: PathClassSpec::Local,
                },
                PolicyRule {
                    pattern: "/**".into(),
                    class: PathClassSpec::Persist,
                },
            ],
            local_overrides: Vec::new(),
        }
    }

    /// Parse a subset of `.octoblock/policy.toml` (`[[rule]]` blocks with `match` and `class`).
    pub fn parse_toml(toml_text: &str) -> Result<Self> {
        let mut rules = Vec::new();
        let mut cur_match: Option<String> = None;
        let mut cur_class: Option<PathClassSpec> = None;

        let flush = |m: &mut Option<String>,
                     c: &mut Option<PathClassSpec>,
                     out: &mut Vec<PolicyRule>|
         -> Result<()> {
            if let (Some(pattern), Some(class)) = (m.take(), c.take()) {
                out.push(PolicyRule { pattern, class });
            }
            Ok(())
        };

        for raw_line in toml_text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line == "[[rule]]" {
                flush(&mut cur_match, &mut cur_class, &mut rules)?;
                continue;
            }
            for assignment in line.split(';') {
                let part = assignment.trim();
                if part.is_empty() {
                    continue;
                }
                let Some((k, v)) = part.split_once('=') else {
                    return Err(Error::new(
                        Errno::EINVAL,
                        format!("malformed policy line: {part}"),
                    ));
                };
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                match key {
                    "match" => cur_match = Some(val.to_string()),
                    "class" => {
                        let parsed = match val {
                            "persist" => PathClassSpec::Persist,
                            "local" => PathClassSpec::Local,
                            "volatile" => PathClassSpec::Volatile,
                            "exclude" => PathClassSpec::Exclude,
                            other => {
                                return Err(Error::new(
                                    Errno::EINVAL,
                                    format!("unknown path class {other:?}"),
                                ));
                            }
                        };
                        cur_class = Some(parsed);
                    }
                    _ => {}
                }
            }
        }
        flush(&mut cur_match, &mut cur_class, &mut rules)?;
        if rules.is_empty() {
            return Ok(Self::tier0_default());
        }
        Ok(PolicyEngine {
            rules,
            local_overrides: Vec::new(),
        })
    }

    /// Serialize the volume rules as canonical `.octoblock/policy.toml` text.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        for r in &self.rules {
            let cname = match r.class {
                PathClassSpec::Persist => "persist",
                PathClassSpec::Local => "local",
                PathClassSpec::Volatile => "volatile",
                PathClassSpec::Exclude => "exclude",
            };
            out.push_str(&format!(
                "[[rule]]\nmatch = {:?}\nclass = {:?}\n\n",
                r.pattern, cname
            ));
        }
        out
    }

    /// Add a machine-local override rule, rejecting any rule that tries to make a path more
    /// persistent than the volume policy allows (`EC-L03`).
    pub fn add_local_override(&mut self, rule: PolicyRule) -> Result<()> {
        let sample = sample_path_for_glob(&rule.pattern);
        let base_class = self.resolve_volume_only(&sample);
        if rule.class.strictness() < base_class.strictness() {
            return Err(Error::new(
                Errno::EINVAL,
                format!(
                    "local override for {:?} cannot relax {:?} to {:?} (EC-L03)",
                    rule.pattern, base_class, rule.class
                ),
            ));
        }
        self.local_overrides.push(rule);
        Ok(())
    }

    fn resolve_volume_only(&self, path: &str) -> PathClassSpec {
        let norm = normalize_path(path);
        // Section 16.2: `.octoblock/` is always excluded from rules that would move it off persist.
        if norm == "/.octoblock" || norm.starts_with("/.octoblock/") {
            return PathClassSpec::Persist;
        }
        for rule in &self.rules {
            if glob_matches(&rule.pattern, &norm) {
                return rule.class;
            }
        }
        PathClassSpec::Persist
    }

    /// Resolve the effective [`PathClass`] for `path` (first-match, honoring stricter local overrides).
    pub fn classify(&self, path: &str) -> PathClass {
        let norm = normalize_path(path);
        if norm == "/.octoblock" || norm.starts_with("/.octoblock/") {
            return PathClass::Persist;
        }
        let base = self.resolve_volume_only(&norm);
        for ov in &self.local_overrides {
            if glob_matches(&ov.pattern, &norm) && ov.class.strictness() >= base.strictness() {
                return ov.class.into();
            }
        }
        base.into()
    }
}

fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let trimmed = replaced.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn sample_path_for_glob(pattern: &str) -> String {
    let p = pattern.replace("**", "x").replace('*', "x");
    normalize_path(&p)
}

/// Match a gitignore-style path glob supporting `**`, `*`, and `?`.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let pat = normalize_path(pattern);
    let target = normalize_path(path);
    if pat == "/**" || pat == "**" {
        return true;
    }
    if let Some( middle ) = pat.strip_prefix("/**/").and_then(|s| s.strip_suffix("/**")) {
        let needle = format!("/{middle}/");
        let suffix = format!("/{middle}");
        return target.contains(&needle) || target.ends_with(&suffix);
    }
    if let Some(prefix) = pat.strip_suffix("/**") {
        return target == prefix || target.starts_with(&format!("{prefix}/"));
    }
    let pat_segs: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = target.split('/').filter(|s| !s.is_empty()).collect();
    match_segments(&pat_segs, &path_segs)
}

fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        if match_segments(&pat[1..], path) {
            return true;
        }
        if !path.is_empty() {
            return match_segments(pat, &path[1..]);
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    if match_wildcard(pat[0].as_bytes(), path[0].as_bytes()) {
        match_segments(&pat[1..], &path[1..])
    } else {
        false
    }
}

fn match_wildcard(pat: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);
    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_p = Some(pi);
            pi += 1;
            star_t = ti;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier1_globs_and_override_restrictions() {
        let mut engine = PolicyEngine::tier1_default();
        assert_eq!(engine.classify("/tmp/a.sock"), PathClass::Volatile);
        assert_eq!(engine.classify("/var/log/syslog"), PathClass::Local);
        assert_eq!(engine.classify("/home/user/.cache/pip/whl"), PathClass::Local);
        assert_eq!(engine.classify("/home/user/src/main.rs"), PathClass::Persist);
        assert_eq!(engine.classify("/.octoblock/status"), PathClass::Persist);

        // EC-L03: Attempting to make `/tmp/**` Persist via local override is rejected.
        let bad = PolicyRule {
            pattern: "/tmp/**".into(),
            class: PathClassSpec::Persist,
        };
        assert_eq!(engine.add_local_override(bad).unwrap_err().errno, Errno::EINVAL);

        // Making `/home/user/target/**` Local via local override is allowed.
        let good = PolicyRule {
            pattern: "/home/user/target/**".into(),
            class: PathClassSpec::Local,
        };
        engine.add_local_override(good).unwrap();
        assert_eq!(
            engine.classify("/home/user/target/debug/app"),
            PathClass::Local
        );
    }
}