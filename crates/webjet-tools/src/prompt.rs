//! Passphrase prompts. On a terminal the typed characters are never shown:
//! each one is echoed as `*`. Without a terminal (scripts piping the
//! passphrase in) a plain line is read from stdin, and an environment
//! variable, when set, takes precedence over both.

use anyhow::{Result, bail};
use std::io::{BufRead, IsTerminal, Write};
use zeroize::Zeroizing;

/// A passphrase, wiped from memory when dropped.
pub type Passphrase = Zeroizing<String>;

/// Read a passphrase from `$var`, or ask for it.
pub fn passphrase(var: &str, prompt: &str) -> Result<Passphrase> {
    if let Ok(p) = std::env::var(var) {
        return Ok(Zeroizing::new(p));
    }
    let p = ask(prompt)?;
    if p.is_empty() {
        bail!("empty passphrase");
    }
    Ok(p)
}

/// Read a new passphrase from `$var`, or ask for it twice: with the input
/// hidden, a typo would otherwise lock the key away. Never empty, also not
/// from `$var`.
pub fn new_passphrase(var: &str, prompt: &str) -> Result<Passphrase> {
    if let Ok(p) = std::env::var(var) {
        let p = Zeroizing::new(p);
        if p.is_empty() {
            bail!("{var} is set but empty: a new passphrase can't be empty");
        }
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        return passphrase(var, prompt);
    }
    for _ in 0..3 {
        let first = ask(prompt)?;
        if first.is_empty() {
            eprintln!("The passphrase can't be empty.");
            continue;
        }
        let again = ask("repeat it")?;
        if *first == *again {
            return Ok(first);
        }
        eprintln!("The passphrases don't match; try again.");
    }
    bail!("no passphrase set")
}

fn ask(prompt: &str) -> Result<Zeroizing<String>> {
    if std::io::stdin().is_terminal() {
        masked(prompt)
    } else {
        eprint!("{prompt}: ");
        // Room for any sane line: growing would leave copies behind.
        let mut s = Zeroizing::new(String::with_capacity(1024));
        std::io::stdin().lock().read_line(&mut s)?;
        // The piped line isn't echoed; end the prompt's line ourselves.
        eprintln!();
        let trimmed = Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_string());
        Ok(trimmed)
    }
}

/// What a key press does to the line being typed.
#[derive(Debug, PartialEq, Eq)]
enum Edit {
    Push(char),
    Backspace,
    Clear,
    Done,
    Cancel,
    Ignore,
}

fn edit(ev: &crossterm::event::KeyEvent) -> Edit {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    // Windows reports releases as well; act on presses (and repeats).
    if ev.kind == KeyEventKind::Release {
        return Edit::Ignore;
    }
    let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
    match ev.code {
        KeyCode::Enter => Edit::Done,
        KeyCode::Char('c') | KeyCode::Char('d') if ctrl => Edit::Cancel,
        KeyCode::Char('u') if ctrl => Edit::Clear,
        KeyCode::Char('h') if ctrl => Edit::Backspace,
        KeyCode::Char(c) if !ctrl => Edit::Push(c),
        KeyCode::Backspace => Edit::Backspace,
        KeyCode::Esc => Edit::Cancel,
        _ => Edit::Ignore,
    }
}

/// Raw mode for as long as it lives, also when reading fails.
struct RawMode;

impl RawMode {
    fn enable() -> Result<RawMode> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn masked(prompt: &str) -> Result<Zeroizing<String>> {
    use crossterm::event::{Event, read};
    let mut err = std::io::stderr();
    write!(err, "{prompt}: ")?;
    err.flush()?;
    // Room for any sane passphrase: growing would leave copies behind.
    let mut line = Zeroizing::new(String::with_capacity(1024));
    let outcome = {
        let _raw = RawMode::enable()?;
        loop {
            let Event::Key(key) = read()? else { continue };
            match edit(&key) {
                Edit::Push(c) => {
                    line.push(c);
                    write!(err, "*")?;
                }
                Edit::Backspace => {
                    if line.pop().is_some() {
                        write!(err, "\x08 \x08")?;
                    }
                }
                Edit::Clear => {
                    for _ in 0..line.chars().count() {
                        write!(err, "\x08 \x08")?;
                    }
                    line.clear();
                }
                Edit::Done => break Ok(()),
                Edit::Cancel => break Err(()),
                Edit::Ignore => {}
            }
            err.flush()?;
        }
    };
    // Raw mode is off again here; end the prompt's line.
    writeln!(err)?;
    match outcome {
        Ok(()) => Ok(line),
        Err(()) => bail!("cancelled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    /// Type `keys` into an empty line the way `masked` does.
    fn typed(keys: &[KeyEvent]) -> (String, Option<bool>) {
        let mut s = String::new();
        for k in keys {
            match edit(k) {
                Edit::Push(c) => s.push(c),
                Edit::Backspace => {
                    s.pop();
                }
                Edit::Clear => s.clear(),
                Edit::Done => return (s, Some(true)),
                Edit::Cancel => return (s, Some(false)),
                Edit::Ignore => {}
            }
        }
        (s, None)
    }

    #[test]
    fn line_editing() {
        let n = KeyModifiers::NONE;
        let ch = |c| key(KeyCode::Char(c), n);
        let shift_a = key(KeyCode::Char('A'), KeyModifiers::SHIFT);
        let (s, done) = typed(&[
            ch('p'),
            shift_a,
            ch('x'),
            key(KeyCode::Backspace, n),
            ch('ß'),
            key(KeyCode::Enter, n),
        ]);
        assert_eq!((s.as_str(), done), ("pAß", Some(true)));
        let (s, _) = typed(&[
            ch('a'),
            ch('b'),
            key(KeyCode::Char('u'), KeyModifiers::CONTROL),
            ch('c'),
            key(KeyCode::Enter, n),
        ]);
        assert_eq!(s, "c");
        let (_, done) = typed(&[ch('a'), key(KeyCode::Char('c'), KeyModifiers::CONTROL)]);
        assert_eq!(done, Some(false), "Ctrl-C cancels");
        // Backspace on an empty line does nothing.
        let (s, _) = typed(&[key(KeyCode::Backspace, n), ch('z'), key(KeyCode::Enter, n)]);
        assert_eq!(s, "z");
        let mut release = ch('q');
        release.kind = KeyEventKind::Release;
        assert_eq!(edit(&release), Edit::Ignore);
        assert_eq!(edit(&key(KeyCode::Left, n)), Edit::Ignore);
    }
}
