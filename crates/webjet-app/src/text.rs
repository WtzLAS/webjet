//! A multi-line text buffer with a cursor, a selection and undo: the
//! editing logic behind the configuration editor, free of GUI code. Plus
//! [`Line`], the single-line equivalent behind the app's text fields.
//!
//! Positions are (line, byte offset) on character boundaries.

use zeroize::Zeroizing;

/// A place in the buffer: line index and byte offset in that line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

impl Pos {
    pub fn new(line: usize, col: usize) -> Pos {
        Pos { line, col }
    }
}

/// How far a cursor movement goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    Left,
    Right,
    Up,
    Down,
    /// Start of the line (after its indentation, then the very start).
    Home,
    End,
    PageUp(usize),
    PageDown(usize),
    /// The start or end of the whole text.
    Top,
    Bottom,
    WordLeft,
    WordRight,
}

/// The text plus the editing state around it.
#[derive(Clone, Debug)]
pub struct Buffer {
    lines: Vec<String>,
    cursor: Pos,
    /// The other end of the selection, when there is one.
    anchor: Option<Pos>,
    /// The column (in characters) up/down movements aim for.
    goal: Option<usize>,
    undo: Vec<(Vec<String>, Pos)>,
    redo: Vec<(Vec<String>, Pos)>,
    /// Whether the last change typed characters (so typing merges into one
    /// undo step).
    typing: bool,
}

const UNDO_DEPTH: usize = 200;

impl Default for Buffer {
    fn default() -> Buffer {
        Buffer::new("")
    }
}

impl Buffer {
    pub fn new(text: &str) -> Buffer {
        Buffer {
            lines: split(text),
            cursor: Pos::default(),
            anchor: None,
            goal: None,
            undo: Vec::new(),
            redo: Vec::new(),
            typing: false,
        }
    }

    /// Replace the whole text (not undoable); the cursor goes to the top.
    pub fn set_text(&mut self, text: &str) {
        *self = Buffer::new(text);
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn line(&self, i: usize) -> &str {
        self.lines.get(i).map_or("", String::as_str)
    }

    pub fn cursor(&self) -> Pos {
        self.cursor
    }

    /// The selection, ordered, when it isn't empty.
    pub fn selection(&self) -> Option<(Pos, Pos)> {
        let a = self.anchor?;
        (a != self.cursor).then(|| (a.min(self.cursor), a.max(self.cursor)))
    }

    /// The selected byte range of line `i`, if any of it is selected. A
    /// selected line break is shown as a selected end: the range then ends
    /// at the line's length and `true` is returned.
    pub fn selected_in_line(&self, i: usize) -> Option<(usize, usize, bool)> {
        let (s, e) = self.selection()?;
        if i < s.line || i > e.line {
            return None;
        }
        let len = self.line(i).len();
        let from = if i == s.line { s.col } else { 0 };
        let (to, eol) = if i == e.line {
            (e.col, false)
        } else {
            (len, true)
        };
        Some((from, to, eol))
    }

    pub fn selected_text(&self) -> Option<String> {
        let (s, e) = self.selection()?;
        Some(self.slice(s, e))
    }

    fn slice(&self, s: Pos, e: Pos) -> String {
        if s.line == e.line {
            return self.line(s.line)[s.col..e.col].to_string();
        }
        let mut out = self.line(s.line)[s.col..].to_string();
        for l in &self.lines[s.line + 1..e.line] {
            out.push('\n');
            out.push_str(l);
        }
        out.push('\n');
        out.push_str(&self.line(e.line)[..e.col]);
        out
    }

    /// Put the cursor at `p` (clamped to the text); `extend` keeps or
    /// starts a selection from the old cursor.
    pub fn set_cursor(&mut self, p: Pos, extend: bool) {
        let p = self.clamp(p);
        if extend {
            self.anchor.get_or_insert(self.cursor);
        } else {
            self.anchor = None;
        }
        self.cursor = p;
        self.goal = None;
        self.typing = false;
    }

    pub fn select_all(&mut self) {
        self.anchor = Some(Pos::default());
        let last = self.lines.len() - 1;
        self.cursor = Pos::new(last, self.lines[last].len());
        self.goal = None;
    }

    /// Select the word (or run of other characters) around `p`.
    pub fn select_word(&mut self, p: Pos) {
        let p = self.clamp(p);
        let Some((start, end)) = word_around(self.line(p.line), p.col) else {
            self.set_cursor(p, false);
            return;
        };
        self.anchor = Some(Pos::new(p.line, start));
        self.cursor = Pos::new(p.line, end);
        self.goal = None;
    }

    fn clamp(&self, p: Pos) -> Pos {
        let line = p.line.min(self.lines.len() - 1);
        let text = &self.lines[line];
        let mut col = p.col.min(text.len());
        while !text.is_char_boundary(col) {
            col -= 1;
        }
        Pos::new(line, col)
    }

    /// Move the cursor; `extend` selects. Without `extend`, moving left or
    /// right off a selection lands on its edge.
    pub fn move_cursor(&mut self, m: Move, extend: bool) {
        self.typing = false;
        if !extend && let Some((s, e)) = self.selection() {
            match m {
                Move::Left => {
                    self.set_cursor(s, false);
                    return;
                }
                Move::Right => {
                    self.set_cursor(e, false);
                    return;
                }
                _ => {}
            }
        }
        let c = self.cursor;
        let goal = self.goal;
        let vertical = |b: &Buffer, line: usize| {
            let g = goal.unwrap_or_else(|| b.line(c.line)[..c.col].chars().count());
            let t = b.line(line);
            let col = t.char_indices().nth(g).map_or(t.len(), |(i, _)| i);
            (Pos::new(line, col), Some(g))
        };
        let (to, goal) = match m {
            Move::Left => (self.left_of(c), None),
            Move::Right => (self.right_of(c), None),
            Move::Up if c.line == 0 => (Pos::new(0, 0), None),
            Move::Up => vertical(self, c.line - 1),
            Move::Down if c.line + 1 == self.lines.len() => {
                (Pos::new(c.line, self.line(c.line).len()), None)
            }
            Move::Down => vertical(self, c.line + 1),
            Move::PageUp(n) => vertical(self, c.line.saturating_sub(n.max(1))),
            Move::PageDown(n) => vertical(self, (c.line + n.max(1)).min(self.lines.len() - 1)),
            Move::Home => {
                let t = self.line(c.line);
                let indent = t.len() - t.trim_start().len();
                (
                    Pos::new(c.line, if c.col == indent { 0 } else { indent }),
                    None,
                )
            }
            Move::End => (Pos::new(c.line, self.line(c.line).len()), None),
            Move::Top => (Pos::default(), None),
            Move::Bottom => {
                let last = self.lines.len() - 1;
                (Pos::new(last, self.lines[last].len()), None)
            }
            Move::WordLeft => (self.word_left(c), None),
            Move::WordRight => (self.word_right(c), None),
        };
        if extend {
            self.anchor.get_or_insert(c);
        } else {
            self.anchor = None;
        }
        self.cursor = to;
        self.goal = goal;
    }

    fn left_of(&self, p: Pos) -> Pos {
        if p.col > 0 {
            let t = self.line(p.line);
            let col = t[..p.col].char_indices().last().map_or(0, |(i, _)| i);
            Pos::new(p.line, col)
        } else if p.line > 0 {
            Pos::new(p.line - 1, self.line(p.line - 1).len())
        } else {
            p
        }
    }

    fn right_of(&self, p: Pos) -> Pos {
        let t = self.line(p.line);
        if p.col < t.len() {
            let col = t[p.col..]
                .chars()
                .next()
                .map_or(t.len(), |ch| p.col + ch.len_utf8());
            Pos::new(p.line, col)
        } else if p.line + 1 < self.lines.len() {
            Pos::new(p.line + 1, 0)
        } else {
            p
        }
    }

    fn word_left(&self, p: Pos) -> Pos {
        if p.col == 0 {
            return self.left_of(p);
        }
        Pos::new(p.line, word_left_in(self.line(p.line), p.col))
    }

    fn word_right(&self, p: Pos) -> Pos {
        if p.col == self.line(p.line).len() {
            return self.right_of(p);
        }
        Pos::new(p.line, word_right_in(self.line(p.line), p.col))
    }

    fn checkpoint(&mut self, typing: bool) {
        if !(typing && self.typing) {
            self.undo.push((self.lines.clone(), self.cursor));
            if self.undo.len() > UNDO_DEPTH {
                self.undo.remove(0);
            }
        }
        self.redo.clear();
        self.typing = typing;
    }

    /// Remove the selection, if any; returns whether there was one.
    fn delete_selection(&mut self) -> bool {
        let Some((s, e)) = self.selection() else {
            self.anchor = None;
            return false;
        };
        let tail = self.lines[e.line][e.col..].to_string();
        self.lines.drain(s.line + 1..=e.line);
        let l = &mut self.lines[s.line];
        l.truncate(s.col);
        l.push_str(&tail);
        self.cursor = s;
        self.anchor = None;
        true
    }

    /// Type or paste `text` over the selection.
    pub fn insert(&mut self, text: &str) {
        let typing = !text.contains('\n') && text.chars().count() == 1;
        self.checkpoint(typing && self.selection().is_none());
        self.delete_selection();
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        let c = self.cursor;
        let tail = self.lines[c.line][c.col..].to_string();
        self.lines[c.line].truncate(c.col);
        let mut parts = text.split('\n');
        if let Some(first) = parts.next() {
            self.lines[c.line].push_str(first);
        }
        let mut line = c.line;
        for p in parts {
            line += 1;
            self.lines.insert(line, p.to_string());
        }
        let col = self.lines[line].len();
        self.lines[line].push_str(&tail);
        self.cursor = Pos::new(line, col);
        self.goal = None;
    }

    /// A line break, keeping the current line's indentation.
    pub fn newline(&mut self) {
        let t = self.line(self.cursor.line);
        let indent: String = t.chars().take_while(|c| *c == ' ' || *c == '\t').collect();
        let indent = &indent[..indent.len().min(self.cursor.col)];
        self.insert(&format!("\n{indent}"));
        self.typing = false;
    }

    /// Backspace: the selection, else the character before the cursor (a
    /// whole indentation step in leading spaces).
    pub fn backspace(&mut self) {
        if self.selection().is_some() {
            self.checkpoint(false);
            self.delete_selection();
            return;
        }
        let c = self.cursor;
        if c == Pos::default() {
            return;
        }
        let before = &self.line(c.line)[..c.col];
        let to = if !before.is_empty() && before.chars().all(|ch| ch == ' ') {
            Pos::new(c.line, (c.col - 1) / INDENT * INDENT)
        } else {
            self.left_of(c)
        };
        self.checkpoint(true);
        self.anchor = Some(to);
        self.delete_selection();
        self.goal = None;
    }

    /// Delete: the selection, else the character after the cursor.
    pub fn delete(&mut self) {
        if self.selection().is_some() {
            self.checkpoint(false);
            self.delete_selection();
            return;
        }
        let to = self.right_of(self.cursor);
        if to == self.cursor {
            return;
        }
        self.checkpoint(true);
        self.anchor = Some(to);
        self.delete_selection();
        self.goal = None;
    }

    /// Delete from the cursor to the start of the line (or the selection).
    pub fn delete_to_line_start(&mut self) {
        if self.selection().is_none() {
            let c = self.cursor;
            if c.col == 0 {
                self.backspace();
                return;
            }
            self.anchor = Some(Pos::new(c.line, 0));
        }
        self.checkpoint(false);
        self.delete_selection();
    }

    /// Tab: indent the selected lines, else insert spaces up to the next
    /// indentation step.
    pub fn indent(&mut self) {
        if let Some((s, e)) = self.selection()
            && s.line != e.line
        {
            self.checkpoint(false);
            let last = if e.col == 0 { e.line - 1 } else { e.line };
            for l in &mut self.lines[s.line..=last] {
                l.insert_str(0, &" ".repeat(INDENT));
            }
            self.shift_selection(s.line, last, INDENT);
            return;
        }
        let chars = self.line(self.cursor.line)[..self.cursor.col]
            .chars()
            .count();
        self.insert(&" ".repeat(INDENT - chars % INDENT));
        self.typing = false;
    }

    /// Shift-Tab: take one indentation step off the selected lines (or the
    /// cursor's line).
    pub fn outdent(&mut self) {
        let (s, e) = self.selection().unwrap_or((self.cursor, self.cursor));
        let last = if e.col == 0 && e.line > s.line {
            e.line - 1
        } else {
            e.line
        };
        let removable = |l: &str| l.len() - l.trim_start_matches(' ').len();
        if (s.line..=last).all(|i| removable(self.line(i)) == 0) {
            return;
        }
        self.checkpoint(false);
        let mut first_removed = 0;
        let mut last_removed = 0;
        for i in s.line..=last {
            let n = removable(&self.lines[i]).min(INDENT);
            self.lines[i].drain(..n);
            if i == s.line {
                first_removed = n;
            }
            if i == e.line {
                last_removed = n;
            }
        }
        let fix = |p: Pos, n: usize| Pos::new(p.line, p.col.saturating_sub(n));
        match self.anchor {
            Some(a) if a != self.cursor => {
                let (na, nc) = if a < self.cursor {
                    (fix(a, first_removed), fix(self.cursor, last_removed))
                } else {
                    (fix(a, last_removed), fix(self.cursor, first_removed))
                };
                self.anchor = Some(na);
                self.cursor = nc;
            }
            _ => {
                self.anchor = None;
                self.cursor = fix(self.cursor, first_removed);
            }
        }
    }

    /// Move the selection's ends along with lines `first..=last` that were
    /// indented by `by` columns (an end at a line's start stays there).
    fn shift_selection(&mut self, first: usize, last: usize, by: usize) {
        let shift = |p: Pos| {
            if p.line < first || p.line > last || p.col == 0 {
                p
            } else {
                Pos::new(p.line, p.col + by)
            }
        };
        self.anchor = self.anchor.map(shift);
        self.cursor = shift(self.cursor);
    }

    /// Toggle `# ` comments on the selected lines (or the cursor's line).
    pub fn toggle_comment(&mut self) {
        let (s, e) = self.selection().unwrap_or((self.cursor, self.cursor));
        let last = if e.col == 0 && e.line > s.line {
            e.line - 1
        } else {
            e.line
        };
        let range = s.line..=last;
        let all_commented = range.clone().all(|i| {
            let t = self.line(i).trim_start();
            t.is_empty() || t.starts_with('#')
        });
        self.checkpoint(false);
        for i in range {
            let l = &mut self.lines[i];
            let indent = l.len() - l.trim_start().len();
            if all_commented {
                if l[indent..].starts_with("# ") {
                    l.replace_range(indent..indent + 2, "");
                } else if l[indent..].starts_with('#') {
                    l.remove(indent);
                }
            } else if !l.trim().is_empty() {
                l.insert_str(indent, "# ");
            }
        }
        self.anchor = None;
        self.cursor = self.clamp(self.cursor);
    }

    pub fn undo(&mut self) -> bool {
        let Some((lines, cur)) = self.undo.pop() else {
            return false;
        };
        self.redo
            .push((std::mem::replace(&mut self.lines, lines), self.cursor));
        self.cursor = self.clamp(cur);
        self.anchor = None;
        self.typing = false;
        true
    }

    pub fn redo(&mut self) -> bool {
        let Some((lines, cur)) = self.redo.pop() else {
            return false;
        };
        self.undo
            .push((std::mem::replace(&mut self.lines, lines), self.cursor));
        self.cursor = self.clamp(cur);
        self.anchor = None;
        self.typing = false;
        true
    }
}

/// Spaces per indentation step.
pub const INDENT: usize = 2;

/// What a word move stops at.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Where a move one word left from byte `col` of `t` lands: the start of
/// the word before it (spaces skipped), or one other character back.
fn word_left_in(t: &str, col: usize) -> usize {
    let trimmed = t[..col].trim_end();
    let start = trimmed
        .char_indices()
        .rev()
        .take_while(|&(_, c)| is_word(c))
        .last()
        .map(|(i, _)| i);
    match start {
        Some(i) => i,
        // Not a word: step over one other character.
        None => trimmed.char_indices().last().map_or(0, |(i, _)| i),
    }
}

/// Where a move one word right from byte `col` of `t` lands: the end of the
/// word after it (spaces skipped), or one other character on.
fn word_right_in(t: &str, col: usize) -> usize {
    let rest = &t[col..];
    let skip = rest.len() - rest.trim_start().len();
    let rest = &rest[skip..];
    let len = rest
        .char_indices()
        .find(|&(_, c)| !is_word(c))
        .map_or(rest.len(), |(i, _)| i);
    let len = if len == 0 {
        rest.chars().next().map_or(0, char::len_utf8)
    } else {
        len
    };
    col + skip + len
}

/// The word (with - for names like ctl-01), run of spaces or run of other
/// characters around byte `col` of `t`, as a byte range; `None` in an
/// empty text.
fn word_around(t: &str, col: usize) -> Option<(usize, usize)> {
    let class = |c: char| {
        if c.is_alphanumeric() || c == '_' || c == '-' {
            0
        } else if c.is_whitespace() {
            1
        } else {
            2
        }
    };
    let at = t[col..].chars().next().or(t[..col].chars().last())?;
    let same = |c: char| class(c) == class(at);
    let start = t[..col]
        .char_indices()
        .rev()
        .take_while(|&(_, c)| same(c))
        .last()
        .map_or(col, |(i, _)| i);
    let end = t[col..]
        .char_indices()
        .find(|&(_, c)| !same(c))
        .map_or(t.len(), |(i, _)| col + i);
    Some((start, end))
}

/// One line of text with a cursor and a selection: the editing logic behind
/// the app's text fields. Offsets are bytes on character boundaries.
///
/// The text may be a passphrase, so it is wiped when replaced or dropped
/// and no copies are kept (no undo). In an `opaque` line (a masked field)
/// words aren't told apart: word moves and double clicks take the whole
/// text, as they would otherwise reveal where the spaces are.
pub struct Line {
    text: Zeroizing<String>,
    cursor: usize,
    /// The other end of the selection, when there is one.
    anchor: Option<usize>,
    opaque: bool,
}

impl Line {
    pub fn new(opaque: bool) -> Line {
        Line {
            // Room for any sane passphrase: growing would leave copies behind.
            text: Zeroizing::new(String::with_capacity(if opaque { 256 } else { 0 })),
            cursor: 0,
            anchor: None,
            opaque,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Replace the text; the cursor goes to its end.
    pub fn set_text(&mut self, t: &str) {
        self.text.clear();
        self.text.push_str(t);
        self.cursor = self.text.len();
        self.anchor = None;
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The selection, ordered, when it isn't empty.
    pub fn selection(&self) -> Option<(usize, usize)> {
        let a = self.anchor?;
        (a != self.cursor).then(|| (a.min(self.cursor), a.max(self.cursor)))
    }

    pub fn selected_text(&self) -> Option<&str> {
        let (s, e) = self.selection()?;
        Some(&self.text[s..e])
    }

    fn clamp(&self, at: usize) -> usize {
        let mut at = at.min(self.text.len());
        while !self.text.is_char_boundary(at) {
            at -= 1;
        }
        at
    }

    /// Put the cursor at `at` (clamped to the text); `extend` keeps or
    /// starts a selection from the old cursor.
    pub fn set_cursor(&mut self, at: usize, extend: bool) {
        if extend {
            self.anchor.get_or_insert(self.cursor);
        } else {
            self.anchor = None;
        }
        self.cursor = self.clamp(at);
    }

    pub fn select_all(&mut self) {
        self.anchor = Some(0);
        self.cursor = self.text.len();
    }

    /// Select the word (or run of other characters) around `at`.
    pub fn select_word(&mut self, at: usize) {
        let at = self.clamp(at);
        let around = if self.opaque {
            Some((0, self.text.len()))
        } else {
            word_around(&self.text, at)
        };
        match around {
            Some((s, e)) => {
                self.anchor = Some(s);
                self.cursor = e;
            }
            None => self.set_cursor(at, false),
        }
    }

    /// Move the cursor; `extend` selects. Up and down go to the start and
    /// the end. Without `extend`, moving left or right off a selection
    /// lands on its edge.
    pub fn move_cursor(&mut self, m: Move, extend: bool) {
        if !extend && let Some((s, e)) = self.selection() {
            match m {
                Move::Left => return self.set_cursor(s, false),
                Move::Right => return self.set_cursor(e, false),
                _ => {}
            }
        }
        let (c, t, len) = (self.cursor, self.text.as_str(), self.text.len());
        let to = match m {
            Move::Left => t[..c].char_indices().last().map_or(0, |(i, _)| i),
            Move::Right => t[c..].chars().next().map_or(c, |ch| c + ch.len_utf8()),
            Move::Home | Move::Up | Move::PageUp(_) | Move::Top => 0,
            Move::End | Move::Down | Move::PageDown(_) | Move::Bottom => len,
            Move::WordLeft if self.opaque || c == 0 => 0,
            Move::WordLeft => word_left_in(t, c),
            Move::WordRight if self.opaque || c == len => len,
            Move::WordRight => word_right_in(t, c),
        };
        self.set_cursor(to, extend);
    }

    /// Remove the selection, if any; returns whether there was one.
    fn delete_selection(&mut self) -> bool {
        let Some((s, e)) = self.selection() else {
            self.anchor = None;
            return false;
        };
        self.text.replace_range(s..e, "");
        self.cursor = s;
        self.anchor = None;
        true
    }

    /// Type or paste `text` over the selection: only its first line, without
    /// control characters.
    pub fn insert(&mut self, text: &str) {
        self.delete_selection();
        let first = text.split(['\n', '\r']).next().unwrap_or("");
        // Character by character: no temporary copy of a pasted passphrase.
        for ch in first.chars().filter(|c| !c.is_control()) {
            self.text.insert(self.cursor, ch);
            self.cursor += ch.len_utf8();
        }
    }

    /// Delete the selection, else from the cursor to where `m` moves it.
    fn delete_to(&mut self, m: Move) {
        if self.selection().is_none() {
            self.move_cursor(m, true);
        }
        self.delete_selection();
    }

    /// Backspace: the selection, else the character before the cursor.
    pub fn backspace(&mut self) {
        self.delete_to(Move::Left);
    }

    /// Delete: the selection, else the character after the cursor.
    pub fn delete(&mut self) {
        self.delete_to(Move::Right);
    }

    /// The selection, else the word before the cursor.
    pub fn delete_word_left(&mut self) {
        self.delete_to(Move::WordLeft);
    }

    /// The selection, else the word after the cursor.
    pub fn delete_word_right(&mut self) {
        self.delete_to(Move::WordRight);
    }

    /// The selection, else everything before the cursor.
    pub fn delete_to_start(&mut self) {
        self.delete_to(Move::Home);
    }
}

fn split(text: &str) -> Vec<String> {
    // Line breaks of every kind, like `Buffer::insert`: a lone CR left in a
    // line would be drawn and saved as part of it.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<String> = text.split('\n').map(String::from).collect();
    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

/// How a line of TOML is colored: its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Blank,
    Comment,
    /// `[table]` or `[[array]]`.
    Header,
    /// `key = value`; the key's byte length.
    KeyValue(usize),
    Other,
}

/// Classify a line for highlighting (good enough for the files `show`
/// prints; multi-line strings show as `Other`).
pub fn line_kind(line: &str) -> LineKind {
    let t = line.trim_start();
    if t.is_empty() {
        LineKind::Blank
    } else if t.starts_with('#') {
        LineKind::Comment
    } else if t.starts_with('[') {
        LineKind::Header
    } else if let Some(eq) = line.find('=') {
        let key = line[..eq].trim_end();
        let bare = key.trim_start();
        if !bare.is_empty()
            && bare
                .chars()
                .all(|c| c.is_alphanumeric() || "_-.\"' ".contains(c))
        {
            LineKind::KeyValue(key.len())
        } else {
            LineKind::Other
        }
    } else {
        LineKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_and_newlines() {
        let mut b = Buffer::new("");
        for c in "abc".chars() {
            b.insert(&c.to_string());
        }
        b.newline();
        b.insert("d");
        assert_eq!(b.text(), "abc\nd");
        assert_eq!(b.cursor(), Pos::new(1, 1));
        // One undo step for the typed run, one for the newline...
        assert!(b.undo());
        assert_eq!(b.text(), "abc\n");
        assert!(b.undo());
        assert_eq!(b.text(), "abc");
        assert!(b.undo());
        assert_eq!(b.text(), "");
        assert!(!b.undo());
        assert!(b.redo());
        assert_eq!(b.text(), "abc");
    }

    #[test]
    fn newline_keeps_indentation() {
        let mut b = Buffer::new("  key = 1");
        b.move_cursor(Move::End, false);
        b.newline();
        b.insert("x");
        assert_eq!(b.text(), "  key = 1\n  x");
    }

    #[test]
    fn selection_paste_and_delete() {
        let mut b = Buffer::new("one\ntwo\nthree");
        b.set_cursor(Pos::new(0, 1), false);
        b.set_cursor(Pos::new(2, 2), true);
        assert_eq!(b.selected_text().as_deref(), Some("ne\ntwo\nth"));
        assert_eq!(b.selected_in_line(1), Some((0, 3, true)));
        assert_eq!(b.selected_in_line(2), Some((0, 2, false)));
        b.insert("X\nY");
        assert_eq!(b.text(), "oX\nYree");
        assert_eq!(b.cursor(), Pos::new(1, 1));
        b.backspace();
        b.backspace();
        assert_eq!(b.text(), "oXree");
        b.move_cursor(Move::End, false);
        b.delete();
        assert_eq!(b.text(), "oXree", "delete at the very end does nothing");
        b.select_all();
        b.delete();
        assert_eq!(b.text(), "");
    }

    #[test]
    fn multibyte_characters() {
        let mut b = Buffer::new("a→b");
        b.move_cursor(Move::End, false);
        b.move_cursor(Move::Left, false);
        assert_eq!(b.cursor(), Pos::new(0, 4));
        b.move_cursor(Move::Left, false);
        assert_eq!(b.cursor(), Pos::new(0, 1));
        b.delete();
        assert_eq!(b.text(), "ab");
        b.set_cursor(Pos::new(0, 99), false);
        assert_eq!(b.cursor(), Pos::new(0, 2), "clamped");
    }

    #[test]
    fn vertical_moves_keep_the_column() {
        let mut b = Buffer::new("abcdef\nab\nabcdef");
        b.set_cursor(Pos::new(0, 5), false);
        b.move_cursor(Move::Down, false);
        assert_eq!(b.cursor(), Pos::new(1, 2));
        b.move_cursor(Move::Down, false);
        assert_eq!(b.cursor(), Pos::new(2, 5), "back at the goal column");
        b.move_cursor(Move::Down, false);
        assert_eq!(b.cursor(), Pos::new(2, 6), "past the last line: its end");
        b.move_cursor(Move::Up, true);
        assert_eq!(b.selected_text().as_deref(), Some("\nabcdef"));
        b.move_cursor(Move::Left, false);
        assert_eq!(
            b.cursor(),
            Pos::new(1, 2),
            "left lands on the selection's start"
        );
        b.move_cursor(Move::Top, false);
        b.move_cursor(Move::PageDown(10), false);
        assert_eq!(b.cursor().line, 2);
    }

    #[test]
    fn home_toggles_between_indent_and_start() {
        let mut b = Buffer::new("    x = 1");
        b.move_cursor(Move::End, false);
        b.move_cursor(Move::Home, false);
        assert_eq!(b.cursor(), Pos::new(0, 4));
        b.move_cursor(Move::Home, false);
        assert_eq!(b.cursor(), Pos::new(0, 0));
    }

    #[test]
    fn words() {
        let mut b = Buffer::new("seeds = [\"ctl-01\"]");
        b.move_cursor(Move::WordRight, false);
        assert_eq!(b.cursor(), Pos::new(0, 5));
        b.move_cursor(Move::WordRight, false);
        assert_eq!(b.cursor(), Pos::new(0, 7), "over the space to the =");
        b.move_cursor(Move::End, false);
        b.move_cursor(Move::WordLeft, false);
        assert_eq!(b.cursor(), Pos::new(0, 17));
        b.select_word(Pos::new(0, 12));
        assert_eq!(b.selected_text().as_deref(), Some("ctl-01"));
    }

    #[test]
    fn indent_outdent_and_comments() {
        let mut b = Buffer::new("a = 1\nb = 2");
        b.indent();
        assert_eq!(b.text(), "  a = 1\nb = 2");
        b.select_all();
        b.indent();
        assert_eq!(b.text(), "    a = 1\n  b = 2");
        b.outdent();
        assert_eq!(b.text(), "  a = 1\nb = 2");
        assert_eq!(b.selected_text().as_deref(), Some("  a = 1\nb = 2"));
        b.toggle_comment();
        assert_eq!(b.text(), "  # a = 1\n# b = 2");
        b.select_all();
        b.toggle_comment();
        assert_eq!(b.text(), "  a = 1\nb = 2");
        b.set_cursor(Pos::new(0, 2), false);
        b.backspace();
        assert_eq!(
            b.text(),
            "a = 1\nb = 2",
            "backspace in indentation: one step"
        );
        b.set_cursor(Pos::new(1, 2), false);
        b.delete_to_line_start();
        assert_eq!(b.text(), "a = 1\n= 2");
    }

    #[test]
    fn highlighting() {
        assert_eq!(line_kind(""), LineKind::Blank);
        assert_eq!(line_kind("  # x"), LineKind::Comment);
        assert_eq!(line_kind("[[policy.rule]]"), LineKind::Header);
        assert_eq!(line_kind("default = \"deny\""), LineKind::KeyValue(7));
        assert_eq!(line_kind("  kcp = 1"), LineKind::KeyValue(5));
        assert_eq!(line_kind("MIIBkTCB+wIJAKH/xyz=="), LineKind::Other);
    }

    #[test]
    fn line_selection_and_editing() {
        let mut l = Line::new(false);
        l.insert("hello wörld\nignored");
        assert_eq!(l.text(), "hello wörld", "only the first line is pasted");
        assert_eq!(l.cursor(), l.text().len());
        l.move_cursor(Move::WordLeft, true);
        assert_eq!(l.selected_text(), Some("wörld"));
        l.move_cursor(Move::Left, false);
        assert_eq!(l.cursor(), 6, "left lands on the selection's start");
        l.move_cursor(Move::Right, true);
        l.move_cursor(Move::Right, true);
        assert_eq!(l.selected_text(), Some("wö"));
        l.insert("W");
        assert_eq!(l.text(), "hello Wrld");
        l.set_cursor(2, false);
        l.set_cursor(4, true);
        l.backspace();
        assert_eq!(l.text(), "heo Wrld");
        l.backspace();
        assert_eq!(l.text(), "ho Wrld");
        l.move_cursor(Move::End, false);
        l.delete_word_left();
        assert_eq!(l.text(), "ho ");
        l.move_cursor(Move::Home, false);
        l.delete_word_right();
        assert_eq!(l.text(), " ");
        l.set_text("a-b c");
        l.select_word(1);
        assert_eq!(l.selected_text(), Some("a-b"));
        l.set_cursor(99, false);
        assert_eq!(l.cursor(), 5, "clamped");
        l.delete_to_start();
        assert_eq!(l.text(), "");
        l.select_word(0);
        assert_eq!(l.selection(), None, "nothing to select");
        l.insert("x\u{7}y");
        assert_eq!(l.text(), "xy", "control characters are dropped");
        l.select_all();
        l.delete();
        assert_eq!(l.text(), "");
    }

    #[test]
    fn opaque_lines_hide_word_boundaries() {
        let mut l = Line::new(true);
        l.insert("two words");
        l.move_cursor(Move::WordLeft, false);
        assert_eq!(l.cursor(), 0);
        l.move_cursor(Move::WordRight, true);
        assert_eq!(l.selected_text(), Some("two words"));
        l.select_word(1);
        assert_eq!(l.selected_text(), Some("two words"));
        l.set_cursor(9, false);
        l.delete_word_left();
        assert_eq!(l.text(), "");
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        /// Text built from pieces that stress byte offsets: multi-byte
        /// characters (2, 3 and 4 bytes, a combining mark), indentation,
        /// comments, line breaks of both kinds.
        fn text() -> impl Strategy<Value = String> {
            let pieces = vec![
                "a", "Z", "_", "-", "=", " ", "  ", "\t", "#", "# ", "[", "\"", "é", "中", "🙂",
                "e\u{301}", "\n", "\r\n", "\r", "key = ", "ctl-01",
            ];
            proptest::collection::vec(proptest::sample::select(pieces), 0..12)
                .prop_map(|v| v.concat())
        }

        fn movement() -> impl Strategy<Value = Move> {
            prop_oneof![
                Just(Move::Left),
                Just(Move::Right),
                Just(Move::Up),
                Just(Move::Down),
                Just(Move::Home),
                Just(Move::End),
                (0usize..4).prop_map(Move::PageUp),
                (0usize..4).prop_map(Move::PageDown),
                Just(Move::Top),
                Just(Move::Bottom),
                Just(Move::WordLeft),
                Just(Move::WordRight),
            ]
        }

        #[derive(Clone, Debug)]
        enum Edit {
            Insert(String),
            Newline,
            Backspace,
            Delete,
            DeleteToLineStart,
            Indent,
            Outdent,
            ToggleComment,
            Undo,
            Redo,
            Move(Move, bool),
            /// Any line and byte offset, on a character boundary or not.
            SetCursor(usize, usize, bool),
            SelectWord(usize, usize),
            SelectAll,
        }

        fn edit() -> impl Strategy<Value = Edit> {
            prop_oneof![
                3 => text().prop_map(Edit::Insert),
                1 => Just(Edit::Newline),
                2 => Just(Edit::Backspace),
                1 => Just(Edit::Delete),
                1 => Just(Edit::DeleteToLineStart),
                1 => Just(Edit::Indent),
                1 => Just(Edit::Outdent),
                1 => Just(Edit::ToggleComment),
                1 => Just(Edit::Undo),
                1 => Just(Edit::Redo),
                3 => (movement(), any::<bool>()).prop_map(|(m, x)| Edit::Move(m, x)),
                2 => (0usize..6, 0usize..40, any::<bool>())
                    .prop_map(|(l, c, x)| Edit::SetCursor(l, c, x)),
                1 => (0usize..6, 0usize..40).prop_map(|(l, c)| Edit::SelectWord(l, c)),
                1 => Just(Edit::SelectAll),
            ]
        }

        fn apply(b: &mut Buffer, e: &Edit) {
            match e {
                Edit::Insert(t) => b.insert(t),
                Edit::Newline => b.newline(),
                Edit::Backspace => b.backspace(),
                Edit::Delete => b.delete(),
                Edit::DeleteToLineStart => b.delete_to_line_start(),
                Edit::Indent => b.indent(),
                Edit::Outdent => b.outdent(),
                Edit::ToggleComment => b.toggle_comment(),
                Edit::Undo => {
                    b.undo();
                }
                Edit::Redo => {
                    b.redo();
                }
                Edit::Move(m, x) => b.move_cursor(*m, *x),
                Edit::SetCursor(l, c, x) => b.set_cursor(Pos::new(*l, *c), *x),
                Edit::SelectWord(l, c) => b.select_word(Pos::new(*l, *c)),
                Edit::SelectAll => b.select_all(),
            }
        }

        fn on_boundary(b: &Buffer, p: Pos) -> bool {
            p.line < b.lines().len() && b.line(p.line).is_char_boundary(p.col)
        }

        /// Everything the editor widget reads from a buffer: a byte offset
        /// that isn't on a character boundary would panic there.
        fn check(b: &Buffer) -> Result<(), TestCaseError> {
            prop_assert!(!b.lines().is_empty());
            prop_assert!(on_boundary(b, b.cursor()), "cursor {:?}", b.cursor());
            if let Some((s, e)) = b.selection() {
                prop_assert!(on_boundary(b, s) && on_boundary(b, e), "{s:?}..{e:?}");
                prop_assert!(b.selected_text().is_some());
            }
            for (i, l) in b.lines().iter().enumerate() {
                prop_assert!(!l.contains(['\n', '\r']), "line break inside line {i}");
                if let Some((from, to, _)) = b.selected_in_line(i) {
                    prop_assert!(from <= to && l.is_char_boundary(from) && l.is_char_boundary(to));
                }
                if let LineKind::KeyValue(k) = line_kind(l) {
                    prop_assert!(l.is_char_boundary(k));
                }
            }
            Ok(())
        }

        proptest! {
            #[test]
            fn buffer_edits_keep_offsets_on_characters(
                start in text(),
                edits in proptest::collection::vec(edit(), 0..40),
            ) {
                let mut b = Buffer::new(&start);
                check(&b)?;
                for e in &edits {
                    apply(&mut b, e);
                    check(&b)?;
                }
                // Every change was undoable: undoing them all gives back the
                // start (CRs folded into line breaks, as `new` does).
                while b.undo() {
                    check(&b)?;
                }
                prop_assert_eq!(b.text(), Buffer::new(&start).text());
            }

            #[test]
            fn line_edits_keep_offsets_on_characters(
                opaque in any::<bool>(),
                start in text(),
                edits in proptest::collection::vec(edit(), 0..40),
            ) {
                let mut l = Line::new(opaque);
                l.set_text(&start);
                for e in &edits {
                    match e {
                        Edit::Insert(t) => l.insert(t),
                        Edit::Backspace => l.backspace(),
                        Edit::Delete => l.delete(),
                        Edit::DeleteToLineStart => l.delete_to_start(),
                        Edit::Indent => l.delete_word_left(),
                        Edit::Outdent => l.delete_word_right(),
                        Edit::Move(m, x) => l.move_cursor(*m, *x),
                        Edit::SetCursor(_, c, x) => l.set_cursor(*c, *x),
                        Edit::SelectWord(_, c) => l.select_word(*c),
                        Edit::SelectAll => l.select_all(),
                        _ => {}
                    }
                    let t = l.text();
                    prop_assert!(t.is_char_boundary(l.cursor()), "cursor {}", l.cursor());
                    if let Some((s, e)) = l.selection() {
                        prop_assert!(t.is_char_boundary(s) && t.is_char_boundary(e));
                        prop_assert!(l.selected_text().is_some());
                    }
                }
            }
        }
    }
}
