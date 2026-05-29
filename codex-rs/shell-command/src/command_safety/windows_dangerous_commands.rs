use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use once_cell::sync::Lazy;
use regex::Regex;
use shlex::split as shlex_split;
use url::Url;

pub fn is_dangerous_command_windows(command: &[String]) -> bool {
    // Prefer structured parsing for PowerShell/CMD so we can spot URL-bearing
    // invocations of ShellExecute-style entry points before falling back to
    // simple argv heuristics.
    if is_dangerous_powershell(command) {
        return true;
    }

    if is_dangerous_cmd(command) {
        return true;
    }

    is_direct_gui_launch(command)
}

fn is_dangerous_powershell(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    if !is_powershell_executable(exe) {
        return false;
    }
    // Parse the PowerShell invocation to get a flat token list we can scan for
    // dangerous cmdlets/COM calls plus any URL-looking arguments. This is a
    // best-effort shlex split of the script text, not a full PS parser.
    let Some(parsed) = parse_powershell_invocation(rest) else {
        return false;
    };

    // An `-EncodedCommand` payload we could not decode/inspect is treated as
    // dangerous: we cannot prove it is safe, so fail closed.
    if parsed.undecodable_encoded_command {
        return true;
    }

    let tokens_lc: Vec<String> = parsed
        .tokens
        .iter()
        .map(|t| t.trim_matches('\'').trim_matches('"').to_ascii_lowercase())
        .collect();
    let has_url = args_have_url(&parsed.tokens);

    if has_url
        && tokens_lc.iter().any(|t| {
            matches!(
                t.as_str(),
                "start-process" | "start" | "saps" | "invoke-item" | "ii"
            ) || t.contains("start-process")
                || t.contains("invoke-item")
        })
    {
        return true;
    }

    if has_url
        && tokens_lc
            .iter()
            .any(|t| t.contains("shellexecute") || t.contains("shell.application"))
    {
        return true;
    }

    if let Some(first) = tokens_lc.first() {
        // Legacy ShellExecute path via url.dll
        if first == "rundll32"
            && tokens_lc
                .iter()
                .any(|t| t.contains("url.dll,fileprotocolhandler"))
            && has_url
        {
            return true;
        }
        if first == "mshta" && has_url {
            return true;
        }
        if is_browser_executable(first) && has_url {
            return true;
        }
        if matches!(first.as_str(), "explorer" | "explorer.exe") && has_url {
            return true;
        }
    }

    // Check for force delete operations (e.g., Remove-Item -Force)
    if has_force_delete_cmdlet(&tokens_lc) {
        return true;
    }

    false
}

fn is_dangerous_cmd(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    let Some(base) = executable_basename(exe) else {
        return false;
    };
    if base != "cmd" && base != "cmd.exe" {
        return false;
    }

    let mut iter = rest.iter();
    for arg in iter.by_ref() {
        let lower = arg.to_ascii_lowercase();
        match lower.as_str() {
            // `/k` runs the command body and keeps the shell open afterwards;
            // its body must be inspected the same as `/c`/`/r` (run-then-exit).
            "/c" | "/r" | "/k" | "-c" => break,
            _ if lower.starts_with('/') => continue,
            // Unknown tokens before the command body => bail.
            _ => return false,
        }
    }

    let remaining: Vec<String> = iter.cloned().collect();
    if remaining.is_empty() {
        return false;
    }

    let cmd_tokens: Vec<String> = match remaining.as_slice() {
        [only] => shlex_split(only).unwrap_or_else(|| vec![only.clone()]),
        _ => remaining,
    };

    // Refine tokens by splitting concatenated CMD operators (e.g. "echo hi&del")
    let tokens: Vec<String> = cmd_tokens
        .into_iter()
        .flat_map(|t| split_embedded_cmd_operators(&t))
        .collect();

    const CMD_SEPARATORS: &[&str] = &["&", "&&", "|", "||"];
    tokens
        .split(|t| CMD_SEPARATORS.contains(&t.as_str()))
        .any(|segment| {
            let Some(cmd) = segment.first() else {
                return false;
            };

            // Classic `cmd /c ... start https://...` ShellExecute path.
            if cmd.eq_ignore_ascii_case("start") && args_have_url(segment) {
                return true;
            }
            // Force delete: del /f, erase /f
            if (cmd.eq_ignore_ascii_case("del") || cmd.eq_ignore_ascii_case("erase"))
                && has_force_flag_cmd(segment)
            {
                return true;
            }
            // Recursive directory removal: rd /s /q, rmdir /s /q
            if (cmd.eq_ignore_ascii_case("rd") || cmd.eq_ignore_ascii_case("rmdir"))
                && has_recursive_flag_cmd(segment)
                && has_quiet_flag_cmd(segment)
            {
                return true;
            }
            false
        })
}

fn is_direct_gui_launch(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    let Some(base) = executable_basename(exe) else {
        return false;
    };

    // Explorer/rundll32/mshta or direct browser exe with a URL anywhere in args.
    if matches!(base.as_str(), "explorer" | "explorer.exe") && args_have_url(rest) {
        return true;
    }
    if matches!(base.as_str(), "mshta" | "mshta.exe") && args_have_url(rest) {
        return true;
    }
    if (base == "rundll32" || base == "rundll32.exe")
        && rest.iter().any(|t| {
            t.to_ascii_lowercase()
                .contains("url.dll,fileprotocolhandler")
        })
        && args_have_url(rest)
    {
        return true;
    }
    if is_browser_executable(&base) && args_have_url(rest) {
        return true;
    }

    false
}

fn split_embedded_cmd_operators(token: &str) -> Vec<String> {
    // Split concatenated CMD operators so `echo hi&del` becomes `["echo hi", "&", "del"]`.
    // Handles `&`, `&&`, `|`, `||`. Best-effort (CMD escaping is weird by nature).
    let mut parts = Vec::new();
    let mut start = 0;
    let mut it = token.char_indices().peekable();

    while let Some((i, ch)) = it.next() {
        if ch == '&' || ch == '|' {
            if i > start {
                parts.push(token[start..i].to_string());
            }

            // Detect doubled operator: && or ||
            let op_len = match it.peek() {
                Some(&(j, next)) if next == ch => {
                    it.next(); // consume second char
                    (j + next.len_utf8()) - i
                }
                _ => ch.len_utf8(),
            };

            parts.push(token[i..i + op_len].to_string());
            start = i + op_len;
        }
    }

    if start < token.len() {
        parts.push(token[start..].to_string());
    }

    parts.retain(|s| !s.trim().is_empty());
    parts
}

fn has_force_delete_cmdlet(tokens: &[String]) -> bool {
    const DELETE_CMDLETS: &[&str] = &["remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"];

    // Hard separators that end a command segment (so -Force must be in same segment)
    const SEG_SEPS: &[char] = &[';', '|', '&', '\n', '\r', '\t'];

    // Soft separators: punctuation that can stick to tokens (blocks, parens, brackets, commas, etc.)
    const SOFT_SEPS: &[char] = &['{', '}', '(', ')', '[', ']', ',', ';'];

    // Build rough command segments first
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    for tok in tokens {
        // If token itself contains segment separators, split it (best-effort)
        let mut cur = String::new();
        for ch in tok.chars() {
            if SEG_SEPS.contains(&ch) {
                let s = cur.trim();
                if let Some(msg) = segments.last_mut()
                    && !s.is_empty()
                {
                    msg.push(s.to_string());
                }
                cur.clear();
                if let Some(last) = segments.last()
                    && !last.is_empty()
                {
                    segments.push(Vec::new());
                }
            } else {
                cur.push(ch);
            }
        }
        let s = cur.trim();
        if let Some(segment) = segments.last_mut()
            && !s.is_empty()
        {
            segment.push(s.to_string());
        }
    }

    // Now, inside each segment, normalize tokens by splitting on soft punctuation
    segments.into_iter().any(|seg| {
        let atoms = seg
            .iter()
            .flat_map(|t| t.split(|c| SOFT_SEPS.contains(&c)))
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let mut has_delete = false;
        let mut has_force = false;

        for a in atoms {
            if DELETE_CMDLETS.iter().any(|cmd| a.eq_ignore_ascii_case(cmd)) {
                has_delete = true;
            }
            if a.eq_ignore_ascii_case("-force")
                || a.get(..7)
                    .is_some_and(|p| p.eq_ignore_ascii_case("-force:"))
            {
                has_force = true;
            }
        }

        has_delete && has_force
    })
}

/// Check for /f or /F flag in CMD del/erase arguments.
fn has_force_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/f"))
}

/// Check for /s or /S flag in CMD rd/rmdir arguments.
fn has_recursive_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/s"))
}

/// Check for /q or /Q flag in CMD rd/rmdir arguments.
fn has_quiet_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/q"))
}

fn args_have_url(args: &[String]) -> bool {
    args.iter().any(|arg| looks_like_url(arg))
}

fn looks_like_url(token: &str) -> bool {
    // Strip common PowerShell punctuation around inline URLs (quotes, parens, trailing semicolons).
    // Capture the middle token after trimming leading quotes/parens/whitespace and trailing semicolons/closing parens.
    static RE: Lazy<Option<Regex>> =
        Lazy::new(|| Regex::new(r#"^[ "'\(\s]*([^\s"'\);]+)[\s;\)]*$"#).ok());
    // If the token embeds a URL alongside other text (e.g., Start-Process('https://...'))
    // as a single shlex token, grab the substring starting at the first URL prefix.
    let urlish = token
        .find("https://")
        .or_else(|| token.find("http://"))
        .map(|idx| &token[idx..])
        .unwrap_or(token);

    let candidate = RE
        .as_ref()
        .and_then(|re| re.captures(urlish))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
        .unwrap_or(urlish);
    let Ok(url) = Url::parse(candidate) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
}

fn executable_basename(exe: &str) -> Option<String> {
    Path::new(exe)
        .file_name()
        .and_then(|osstr| osstr.to_str())
        .map(str::to_ascii_lowercase)
}

fn is_powershell_executable(exe: &str) -> bool {
    matches!(
        executable_basename(exe).as_deref(),
        Some("powershell") | Some("powershell.exe") | Some("pwsh") | Some("pwsh.exe")
    )
}

fn is_browser_executable(name: &str) -> bool {
    matches!(
        name,
        "chrome"
            | "chrome.exe"
            | "msedge"
            | "msedge.exe"
            | "firefox"
            | "firefox.exe"
            | "iexplore"
            | "iexplore.exe"
    )
}

struct ParsedPowershell {
    tokens: Vec<String>,
    /// Set when the invocation carries an `-EncodedCommand`/`-enc` payload that
    /// we could not decode/inspect. Such invocations are treated as dangerous
    /// (fail closed) so a malicious base64 script cannot bypass the checks.
    undecodable_encoded_command: bool,
}

impl ParsedPowershell {
    fn from_tokens(tokens: Vec<String>) -> Self {
        Self {
            tokens,
            undecodable_encoded_command: false,
        }
    }

    fn undecodable() -> Self {
        Self {
            tokens: Vec::new(),
            undecodable_encoded_command: true,
        }
    }
}

fn parse_powershell_invocation(args: &[String]) -> Option<ParsedPowershell> {
    if args.is_empty() {
        return None;
    }

    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        let lower = arg.to_ascii_lowercase();
        match lower.as_str() {
            "-command" | "/command" | "-c" => {
                let script = args.get(idx + 1)?;
                // Trailing tokens after the script body (e.g. `-Command <script>
                // -NoExit`) mean we cannot fully validate the invocation. Real
                // PowerShell still runs the script, so fail closed rather than
                // returning None (which would fail OPEN at the caller).
                if idx + 2 != args.len() {
                    return Some(ParsedPowershell::undecodable());
                }
                let tokens = shlex_split(script)?;
                return Some(ParsedPowershell::from_tokens(tokens));
            }
            // `-EncodedCommand` takes a base64-encoded UTF-16LE script. PowerShell
            // accepts any unambiguous prefix of the parameter name (`-en`, `-enco`,
            // `-encod`, …, `-encodedcommand`) plus the documented `-e`/`-ec`
            // aliases. Decode the payload and feed the resulting script through the
            // SAME dangerous-command inspection. If decoding fails we cannot inspect
            // the payload, so we fail closed and mark it dangerous.
            //
            // The colon form `-EncodedCommand:<b64>` is handled first.
            _ if encoded_command_inline(&lower).is_some() => {
                // Trailing tokens after the inline `-EncodedCommand:<b64>` arg
                // mean we cannot fully validate the invocation; fail closed
                // instead of returning None (which fails OPEN at the caller).
                if idx + 1 != args.len() {
                    return Some(ParsedPowershell::undecodable());
                }
                let encoded = encoded_command_inline(&lower).unwrap_or("");
                // Re-derive from the original (non-lowercased) arg to preserve
                // base64 case, which is significant.
                let encoded = arg.split_once(':').map(|(_, v)| v).unwrap_or(encoded);
                return Some(decode_encoded_command(encoded));
            }
            _ if is_encoded_command_flag(&lower) => {
                let Some(encoded) = args.get(idx + 1) else {
                    return Some(ParsedPowershell::undecodable());
                };
                // Trailing tokens after the encoded value (e.g.
                // `-EncodedCommand <b64> -NoExit`) mean we cannot fully validate
                // the invocation; PowerShell still executes the encoded script,
                // so fail closed instead of returning None (which fails OPEN).
                if idx + 2 != args.len() {
                    return Some(ParsedPowershell::undecodable());
                }
                return Some(decode_encoded_command(encoded));
            }
            _ if lower.starts_with("-command:") || lower.starts_with("/command:") => {
                // Trailing tokens after the inline `-Command:<script>` arg mean
                // we cannot fully validate the invocation; PowerShell still runs
                // the script, so fail closed instead of returning None (which
                // fails OPEN at the caller).
                if idx + 1 != args.len() {
                    return Some(ParsedPowershell::undecodable());
                }
                let (_, script) = arg.split_once(':')?;
                let tokens = shlex_split(script)?;
                return Some(ParsedPowershell::from_tokens(tokens));
            }
            "-nologo" | "-noprofile" | "-noninteractive" | "-mta" | "-sta" => {
                idx += 1;
            }
            // Value-taking switches (e.g. `-WindowStyle hidden`, `-ExecutionPolicy
            // bypass`, `-File script.ps1`). These consume the FOLLOWING token as
            // their value. If we treated them as valueless (the generic `-` arm
            // below), the value would fall through to the positional arm and the
            // parser would return the remaining args raw — including a trailing
            // `-EncodedCommand <b64>` that then never gets decoded/inspected
            // (the canonical `powershell -nop -w hidden -EncodedCommand <b64>`
            // bypass). Consuming the value keeps `-EncodedCommand` recognizable.
            _ if is_value_taking_flag(&lower) => {
                // Skip the flag and its value. A trailing value-taking flag with
                // no following token is just consumed (idx += 1) — fall through
                // to the loop's normal termination.
                idx += if idx + 1 < args.len() { 2 } else { 1 };
            }
            _ if lower.starts_with('-') => {
                idx += 1;
            }
            _ => {
                // Positional fallthrough: the remaining args are the command/
                // script body. Backstop against any value-taking flag we failed
                // to model above: if a `-Command`/`-EncodedCommand` flag is still
                // present in the tail, we cannot have routed it through the
                // dedicated decode arms, so fail closed rather than returning the
                // (possibly base64-encoded) payload raw and uninspected.
                let rest = &args[idx..];
                if rest.iter().any(|a| {
                    let l = a.to_ascii_lowercase();
                    is_encoded_command_flag(&l)
                        || encoded_command_inline(&l).is_some()
                        || matches!(l.as_str(), "-command" | "/command" | "-c")
                        || l.starts_with("-command:")
                        || l.starts_with("/command:")
                }) {
                    return Some(ParsedPowershell::undecodable());
                }
                return Some(ParsedPowershell::from_tokens(rest.to_vec()));
            }
        }
    }

    None
}

/// True if `lower` (an already-lowercased argv token) names a PowerShell switch
/// that consumes the NEXT argv token as its value. PowerShell resolves any
/// unambiguous prefix of a parameter name, so we match prefixes too (e.g. `-w`
/// for `-WindowStyle`, `-ex`/`-exec` for `-ExecutionPolicy`).
///
/// Modeling these is a security requirement: an unmodeled value-taking flag lets
/// its value slip into the positional stream, which can carry an undecoded
/// `-EncodedCommand <b64>` past inspection. The positional-arm backstop in
/// `parse_powershell_invocation` covers any flag missed here, but keeping this
/// list complete lets benign invocations (e.g. `-w hidden -EncodedCommand
/// <benign>`) still decode and pass through normally instead of failing closed.
fn is_value_taking_flag(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix('-').or_else(|| lower.strip_prefix('/')) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    // Inline `-flag:value` forms carry their own value; they are not next-token
    // value consumers, so they are not handled here.
    if rest.contains(':') {
        return false;
    }
    // Canonical PowerShell value-taking parameter names. Any non-empty
    // unambiguous prefix of these binds to the parameter (PowerShell semantics),
    // so `-w` -> windowstyle, `-ex`/`-exec` -> executionpolicy, etc.
    const VALUE_TAKING: &[&str] = &[
        "windowstyle",
        "executionpolicy",
        "file",
        "version",
        "inputformat",
        "outputformat",
        "configurationname",
        "psconsolefile",
        "settingsfile",
        "workingdirectory",
        "custompipename",
    ];
    VALUE_TAKING.iter().any(|name| name.starts_with(rest))
}

/// True if `lower` (an already-lowercased argv token) names PowerShell's
/// `-EncodedCommand` parameter in standalone form (value is the NEXT argv token).
///
/// PowerShell resolves any unambiguous prefix of a parameter name, so `-en`,
/// `-enco`, … `-encodedcommand` all bind to EncodedCommand. We also accept the
/// documented `-e` and `-ec` aliases. Over-matching is safe: a benign encoded
/// command still decodes and passes through the normal inspection.
fn is_encoded_command_flag(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix('-').or_else(|| lower.strip_prefix('/')) else {
        return false;
    };
    // Documented aliases that are not literal prefixes of "encodedcommand".
    if rest == "e" || rest == "ec" {
        return true;
    }
    // Any non-empty prefix of "encodedcommand" (e.g. "en", "enco", "encod").
    !rest.is_empty() && "encodedcommand".starts_with(rest)
}

/// If `lower` is the colon/inline form of an EncodedCommand flag
/// (e.g. `-enc:<b64>`, `-encodedcommand:<b64>`), return the (lowercased) value
/// portion. Returns `None` when `lower` is not an inline EncodedCommand flag.
/// The caller re-derives the value from the original-case arg to keep base64
/// case intact.
fn encoded_command_inline(lower: &str) -> Option<&str> {
    let (flag, value) = lower.split_once(':')?;
    if is_encoded_command_flag(flag) {
        Some(value)
    } else {
        None
    }
}

/// Decode a PowerShell `-EncodedCommand` payload (base64 of a UTF-16LE script)
/// into a token list. On any decode failure we return an `undecodable` marker so
/// the caller fails closed and treats the invocation as dangerous.
fn decode_encoded_command(encoded: &str) -> ParsedPowershell {
    // PowerShell ignores surrounding whitespace in the encoded argument.
    let trimmed = encoded.trim();
    let Ok(raw) = BASE64_STANDARD.decode(trimmed) else {
        return ParsedPowershell::undecodable();
    };
    // The payload is UTF-16LE; reassemble u16 code units (little-endian).
    if raw.len() % 2 != 0 {
        return ParsedPowershell::undecodable();
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let Ok(script) = String::from_utf16(&units) else {
        return ParsedPowershell::undecodable();
    };
    match shlex_split(&script) {
        Some(tokens) => ParsedPowershell::from_tokens(tokens),
        // Decoded fine but we cannot tokenize it for inspection: fail closed.
        None => ParsedPowershell::undecodable(),
    }
}

#[cfg(test)]
mod tests {
    use super::is_dangerous_command_windows;

    fn vec_str(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn powershell_start_process_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-NoLogo",
            "-Command",
            "Start-Process 'https://example.com'"
        ])));
    }

    #[test]
    fn powershell_start_process_url_with_trailing_semicolon_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Start-Process('https://example.com');"
        ])));
    }

    #[test]
    fn powershell_start_process_local_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Start-Process notepad.exe"
        ])));
    }

    #[test]
    fn cmd_start_with_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "start",
            "https://example.com"
        ])));
    }

    #[test]
    fn msedge_with_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "msedge.exe",
            "https://example.com"
        ])));
    }

    #[test]
    fn explorer_with_directory_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "explorer.exe",
            "."
        ])));
    }

    // Force delete tests for PowerShell

    #[test]
    fn powershell_remove_item_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_recurse_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Recurse -Force"
        ])));
    }

    #[test]
    fn powershell_ri_alias_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "pwsh",
            "-Command",
            "ri test -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_without_force_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test"
        ])));
    }

    // Force delete tests for CMD
    #[test]
    fn cmd_del_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "del", "/f", "test.txt"
        ])));
    }

    #[test]
    fn cmd_erase_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "erase", "/f", "test.txt"
        ])));
    }

    #[test]
    fn cmd_del_without_force_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "del", "test.txt"
        ])));
    }

    #[test]
    fn cmd_rd_recursive_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rd", "/s", "/q", "test"
        ])));
    }

    #[test]
    fn cmd_rd_without_quiet_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rd", "/s", "test"
        ])));
    }

    #[test]
    fn cmd_rmdir_recursive_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rmdir", "/s", "/q", "test"
        ])));
    }

    // Test exact scenario from issue #8567
    #[test]
    fn powershell_remove_item_path_recurse_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item -Path 'test' -Recurse -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_with_semicolon_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Force; Write-Host done"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_inside_block_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "if ($true) { Remove-Item test -Force}"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_inside_brackets_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "[void]( Remove-Item test -Force)]"
        ])));
    }

    #[test]
    fn cmd_del_path_containing_f_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "del",
            "C:/foo/bar.txt"
        ])));
    }

    #[test]
    fn cmd_rd_path_containing_s_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "rd",
            "C:/source"
        ])));
    }

    #[test]
    fn cmd_bypass_chained_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "echo", "hello", "&", "del", "/f", "file.txt"
        ])));
    }

    #[test]
    fn powershell_chained_no_space_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Write-Host hi;Remove-Item -Force C:\\tmp"
        ])));
    }

    #[test]
    fn powershell_comma_separated_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "del,-Force,C:\\foo"
        ])));
    }

    #[test]
    fn cmd_echo_del_is_not_dangerous() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "echo", "del", "/f"
        ])));
    }

    #[test]
    fn cmd_del_single_string_argument_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_del_chained_single_string_argument_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hello & del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_andand_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&&del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_oror_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi||del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_start_url_single_string_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "start https://example.com"
        ])));
    }

    #[test]
    fn cmd_chained_no_space_rmdir_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&rmdir /s /q testdir"
        ])));
    }

    #[test]
    fn cmd_del_force_uppercase_flag_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "DEL", "/F", "file.txt"
        ])));
    }

    #[test]
    fn cmdexe_r_del_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd.exe", "/r", "del", "/f", "file.txt"
        ])));
    }

    #[test]
    fn cmd_start_quoted_url_single_string_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            r#"start "https://example.com""#
        ])));
    }

    #[test]
    fn cmd_start_title_then_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            r#"start "" https://example.com"#
        ])));
    }

    #[test]
    fn powershell_rm_alias_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "rm test -Force"
        ])));
    }

    #[test]
    fn powershell_benign_force_separate_command_is_not_dangerous() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Get-ChildItem -Force; Remove-Item test"
        ])));
    }

    // `cmd /k` runs its command body (then keeps the shell open); its body must
    // be inspected the same as `/c`.
    #[test]
    fn cmd_k_del_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/k", "del", "/f", "file.txt"
        ])));
    }

    #[test]
    fn cmd_k_start_url_single_string_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/k",
            "start https://example.com"
        ])));
    }

    // `-EncodedCommand` carries a base64 UTF-16LE script that must be decoded and
    // routed through the same dangerous-command inspection.
    #[test]
    fn powershell_encoded_start_process_url_is_dangerous() {
        // base64(UTF-16LE("Start-Process 'https://example.com'"))
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-EncodedCommand",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_enc_alias_remove_item_force_is_dangerous() {
        // base64(UTF-16LE("Remove-Item test -Force")) via the -enc alias.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "pwsh",
            "-enc",
            "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAdABlAHMAdAAgAC0ARgBvAHIAYwBlAA=="
        ])));
    }

    // PowerShell binds any unambiguous prefix of `-EncodedCommand`, so `-enco`
    // (and `-en`, `-encod`, …) must be detected too — not just the full name.
    #[test]
    fn powershell_encoded_command_prefix_alias_is_dangerous() {
        // base64(UTF-16LE("Start-Process 'https://example.com'")) via `-enco`.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-enco",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_encoded_command_two_char_prefix_is_dangerous() {
        // `-en` is still an unambiguous prefix of EncodedCommand.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-en",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_ec_alias_is_dangerous() {
        // `-ec` is a documented EncodedCommand alias (not a literal name prefix).
        assert!(is_dangerous_command_windows(&vec_str(&[
            "pwsh",
            "-ec",
            "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAdABlAHMAdAAgAC0ARgBvAHIAYwBlAA=="
        ])));
    }

    #[test]
    fn powershell_encoded_command_inline_colon_is_dangerous() {
        // Inline colon form `-EncodedCommand:<b64>` must also be decoded.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-EncodedCommand:UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_encoded_garbage_payload_is_dangerous() {
        // Non-base64 payload can't be decoded/inspected => fail closed.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-EncodedCommand",
            "not valid base64!!!"
        ])));
    }

    #[test]
    fn powershell_encoded_benign_payload_is_not_flagged() {
        // base64(UTF-16LE("Get-ChildItem")) decodes to a benign command.
        let encoded = {
            use base64::Engine as _;
            let script = "Get-ChildItem";
            let mut utf16 = Vec::new();
            for unit in script.encode_utf16() {
                utf16.extend_from_slice(&unit.to_le_bytes());
            }
            base64::engine::general_purpose::STANDARD.encode(utf16)
        };
        assert!(!is_dangerous_command_windows(&[
            "powershell".to_string(),
            "-EncodedCommand".to_string(),
            encoded,
        ]));
    }

    // Trailing tokens after the value mean the invocation cannot be fully
    // validated. PowerShell still executes the script/encoded payload (e.g.
    // `-NoExit` is a benign host switch), so these must fail CLOSED (dangerous)
    // rather than fail open by returning None at the parser.
    #[test]
    fn powershell_encoded_command_trailing_token_is_dangerous() {
        // `-EncodedCommand <b64> -NoExit`
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-EncodedCommand",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA==",
            "-NoExit"
        ])));
    }

    #[test]
    fn powershell_encoded_command_inline_trailing_token_is_dangerous() {
        // `-EncodedCommand:<b64> -NoExit`
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-EncodedCommand:UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA==",
            "-NoExit"
        ])));
    }

    #[test]
    fn powershell_command_trailing_token_is_dangerous() {
        // `-Command <script> -NoExit`
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Start-Process 'https://example.com'",
            "-NoExit"
        ])));
    }

    #[test]
    fn powershell_command_inline_trailing_token_is_dangerous() {
        // `-Command:<script> -NoExit`
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command:Start-Process 'https://example.com'",
            "-NoExit"
        ])));
    }

    // ---------------------------------------------------------------------------
    // Value-taking flags preceding -EncodedCommand. Before the fix, a switch like
    // `-w hidden` / `-WindowStyle hidden` / `-ExecutionPolicy bypass` was parsed
    // as valueless, so its value (`hidden`/`bypass`) became a bare positional and
    // the parser returned the remaining args — including `-EncodedCommand <b64>` —
    // raw and UNDECODED, slipping the payload past inspection. The canonical
    // malware form is `powershell -nop -w hidden -EncodedCommand <b64>`.
    //
    // Two tests pin the behavior: the malware payload must be flagged AND a benign
    // payload behind the same preceding flags must NOT be flagged. The benign case
    // is the discriminating one: it passes ONLY if `-w hidden` was actually
    // consumed and the decoder reached (a lazy "fail closed on any -w" would
    // wrongly flag it).
    #[test]
    fn powershell_windowstyle_then_encoded_start_process_url_is_dangerous() {
        // base64(UTF-16LE("Start-Process 'https://example.com'"))
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-nop",
            "-w",
            "hidden",
            "-EncodedCommand",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_windowstyle_then_encoded_benign_payload_is_not_flagged() {
        // base64(UTF-16LE("Get-ChildItem")) — benign. Must decode and pass through
        // (NOT flagged), proving `-w hidden` was consumed and the decoder reached
        // rather than the invocation being blanket-failed-closed.
        let encoded = {
            use base64::Engine as _;
            let mut utf16 = Vec::new();
            for unit in "Get-ChildItem".encode_utf16() {
                utf16.extend_from_slice(&unit.to_le_bytes());
            }
            base64::engine::general_purpose::STANDARD.encode(utf16)
        };
        assert!(!is_dangerous_command_windows(&[
            "powershell".to_string(),
            "-nop".to_string(),
            "-w".to_string(),
            "hidden".to_string(),
            "-EncodedCommand".to_string(),
            encoded,
        ]));
    }

    #[test]
    fn powershell_full_windowstyle_name_then_encoded_remove_force_is_dangerous() {
        // base64(UTF-16LE("Remove-Item test -Force")) behind the full flag name.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAdABlAHMAdAAgAC0ARgBvAHIAYwBlAA=="
        ])));
    }

    #[test]
    fn powershell_executionpolicy_then_encoded_url_is_dangerous() {
        // `-ExecutionPolicy bypass` must consume `bypass`; the encoded payload
        // after it must still be decoded and flagged.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-ExecutionPolicy",
            "bypass",
            "-EncodedCommand",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }

    #[test]
    fn powershell_unmodeled_value_flag_with_encoded_command_is_dangerous() {
        // Backstop: even if a value-taking flag is NOT in our model list, its
        // value lands in the positional tail followed by `-EncodedCommand <b64>`.
        // The positional-arm backstop must fail closed rather than return the
        // payload raw. `-SomeUnknownFlag` is intentionally not modeled.
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-SomeUnknownFlag",
            "value",
            "-EncodedCommand",
            "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACcAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnAA=="
        ])));
    }
}
