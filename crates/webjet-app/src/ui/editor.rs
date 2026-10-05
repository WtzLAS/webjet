//! A multi-line TOML editor: the configuration files of the Config tab.
//! Editing logic is in `crate::text::Buffer`; this draws it (line numbers,
//! highlighting, selection, cursor) and turns keys and the mouse into
//! buffer operations.

use super::theme;
use crate::text::{Buffer, LineKind, Move, Pos, line_kind};
use gpui::{
    App, Bounds, ClipboardItem, Context, EventEmitter, FocusHandle, Focusable, KeyDownEvent,
    ListHorizontalSizingBehavior, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels,
    ScrollStrategy, ShapedLine, TextRun, UniformListScrollHandle, Window, canvas, div, fill, point,
    prelude::*, px, rgb, rgba, uniform_list,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// A fixed-width font that exists on each platform.
pub const MONO: &str = if cfg!(target_os = "macos") {
    "Menlo"
} else if cfg!(windows) {
    "Consolas"
} else {
    "DejaVu Sans Mono"
};

const LINE_H: f32 = 19.0;
const FONT: f32 = 12.5;
/// A generous estimate of a character's width in [`MONO`] at [`FONT`]
/// (0.6 em), so long lines scroll sideways instead of being cut.
const CHAR_W: f32 = 7.6;
/// Lines a page up/down moves.
const PAGE: usize = 20;

/// Sent when the text changed (not for cursor moves).
pub struct Changed;

pub struct Editor {
    focus: FocusHandle,
    buf: Buffer,
    read_only: bool,
    scroll: UniformListScrollHandle,
    /// Each painted line's text origin (x) and shaping, for the mouse.
    layouts: Rc<RefCell<HashMap<usize, (Pixels, ShapedLine)>>>,
    /// A mouse selection in progress.
    selecting: bool,
}

impl EventEmitter<Changed> for Editor {}

impl Editor {
    pub fn new(cx: &mut Context<Self>, read_only: bool) -> Editor {
        Editor {
            focus: cx.focus_handle(),
            buf: Buffer::default(),
            read_only,
            scroll: UniformListScrollHandle::new(),
            layouts: Rc::new(RefCell::new(HashMap::new())),
            selecting: false,
        }
    }

    pub fn text(&self) -> String {
        self.buf.text()
    }

    /// Replace the text (a fresh buffer: no undo past this), at the top.
    pub fn set_text(&mut self, text: &str, cx: &mut Context<Self>) {
        if self.buf.text() == text {
            return;
        }
        self.buf.set_text(text);
        self.layouts.borrow_mut().clear();
        self.scroll.scroll_to_item(0, ScrollStrategy::Top);
        cx.emit(Changed);
        cx.notify();
    }

    /// Change the text, unless read-only.
    fn edit(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut Buffer)) {
        if self.read_only {
            return;
        }
        f(&mut self.buf);
        cx.emit(Changed);
    }

    fn key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let k = &ev.keystroke;
        let m = &k.modifiers;
        // ⌘ on macOS, Ctrl elsewhere.
        let cmd = m.platform || m.control;
        let (shift, alt) = (m.shift, m.alt);
        let mv = |this: &mut Self, mo: Move| this.buf.move_cursor(mo, shift);
        match k.key.as_str() {
            "left" if cmd => mv(self, Move::Home),
            "left" if alt => mv(self, Move::WordLeft),
            "left" => mv(self, Move::Left),
            "right" if cmd => mv(self, Move::End),
            "right" if alt => mv(self, Move::WordRight),
            "right" => mv(self, Move::Right),
            "up" if cmd => mv(self, Move::Top),
            "up" => mv(self, Move::Up),
            "down" if cmd => mv(self, Move::Bottom),
            "down" => mv(self, Move::Down),
            "home" if cmd => mv(self, Move::Top),
            "home" => mv(self, Move::Home),
            "end" if cmd => mv(self, Move::Bottom),
            "end" => mv(self, Move::End),
            "pageup" => mv(self, Move::PageUp(PAGE)),
            "pagedown" => mv(self, Move::PageDown(PAGE)),
            "escape" => {
                let c = self.buf.cursor();
                self.buf.set_cursor(c, false);
            }
            "enter" => self.edit(cx, Buffer::newline),
            "tab" if shift => self.edit(cx, Buffer::outdent),
            "tab" => self.edit(cx, Buffer::indent),
            "backspace" if cmd => self.edit(cx, Buffer::delete_to_line_start),
            "backspace" if alt => self.edit(cx, |b| {
                if b.selection().is_none() {
                    b.move_cursor(Move::WordLeft, true);
                }
                b.backspace();
            }),
            "backspace" => self.edit(cx, Buffer::backspace),
            "delete" => self.edit(cx, Buffer::delete),
            "a" if cmd => self.buf.select_all(),
            "c" if cmd => {
                if let Some(t) = self.buf.selected_text() {
                    cx.write_to_clipboard(ClipboardItem::new_string(t));
                }
            }
            "x" if cmd => {
                if let Some(t) = self.buf.selected_text()
                    && !self.read_only
                {
                    cx.write_to_clipboard(ClipboardItem::new_string(t));
                    self.edit(cx, Buffer::delete);
                }
            }
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.edit(cx, |b| b.insert(&t));
                }
            }
            "z" if cmd && shift => self.edit(cx, |b| {
                b.redo();
            }),
            "z" if cmd => self.edit(cx, |b| {
                b.undo();
            }),
            "y" if cmd => self.edit(cx, |b| {
                b.redo();
            }),
            "/" if cmd => self.edit(cx, Buffer::toggle_comment),
            _ => {
                if cmd {
                    // Not ours (⌘Q, …).
                    return;
                }
                match &k.key_char {
                    Some(c) if !c.chars().any(char::is_control) => {
                        let c = c.clone();
                        self.edit(cx, |b| b.insert(&c));
                    }
                    _ => return,
                }
            }
        }
        self.scroll
            .scroll_to_item(self.buf.cursor().line, ScrollStrategy::Top);
        cx.stop_propagation();
        cx.notify();
    }

    /// The position in line `line` under window x coordinate `x`.
    fn pos_at(&self, line: usize, x: Pixels) -> Pos {
        let col = self
            .layouts
            .borrow()
            .get(&line)
            .map_or(0, |(left, l)| l.closest_index_for_x(x - *left));
        Pos::new(line, col)
    }

    fn mouse_down(
        &mut self,
        line: usize,
        ev: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.focus.focus(window);
        let p = self.pos_at(line, ev.position.x);
        match ev.click_count {
            2 => self.buf.select_word(p),
            n if n >= 3 => {
                self.buf.set_cursor(Pos::new(line, 0), false);
                self.buf.move_cursor(Move::Down, true);
                if self.buf.cursor().line == line {
                    self.buf.move_cursor(Move::End, true);
                } else {
                    self.buf.set_cursor(Pos::new(line + 1, 0), true);
                }
            }
            _ => {
                self.buf.set_cursor(p, ev.modifiers.shift);
                self.selecting = true;
            }
        }
        cx.notify();
    }

    fn mouse_move(&mut self, line: usize, ev: &MouseMoveEvent, cx: &mut Context<Self>) {
        if !self.selecting || ev.pressed_button != Some(MouseButton::Left) {
            return;
        }
        let p = self.pos_at(line, ev.position.x);
        if p != self.buf.cursor() {
            self.buf.set_cursor(p, true);
            cx.notify();
        }
    }

    /// One line: its number and its text.
    fn row(
        &self,
        i: usize,
        focused: bool,
        gutter: f32,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let text = self.buf.line(i).to_string();
        let width = CHAR_W * (text.chars().count() + 2) as f32;
        let sel = self.buf.selected_in_line(i);
        let cursor = self.buf.cursor();
        let caret = (focused && cursor.line == i && !self.read_only).then_some(cursor.col);
        let layouts = self.layouts.clone();
        let current = cursor.line == i && !self.read_only;
        div()
            .id(("line", i))
            .h(px(LINE_H))
            .flex()
            .when(current, |d| d.bg(rgba(0xffffff08)))
            .child(
                div()
                    .w(px(gutter))
                    .flex_shrink_0()
                    .pr_2()
                    .flex()
                    .justify_end()
                    .text_color(rgb(if current { theme::TEXT } else { theme::MUTED }))
                    .child((i + 1).to_string()),
            )
            .child(
                canvas(
                    |_, _, _| (),
                    move |b: Bounds<Pixels>, _, window, cx| {
                        let style = window.text_style();
                        let size = style.font_size.to_pixels(window.rem_size());
                        let runs = highlight(&text, &style.font());
                        let line = window
                            .text_system()
                            .shape_line(text.into(), size, &runs, None);
                        if let Some((from, to, eol)) = sel {
                            let x0 = line.x_for_index(from);
                            let x1 = line.x_for_index(to) + if eol { px(6.) } else { px(0.) };
                            window.paint_quad(fill(
                                Bounds::from_corners(
                                    point(b.left() + x0, b.top()),
                                    point(b.left() + x1, b.bottom()),
                                ),
                                rgba(0x4c8dff55),
                            ));
                        }
                        let _ = line.paint(b.origin, px(LINE_H), window, cx);
                        if let Some(col) = caret {
                            let x = line.x_for_index(col);
                            window.paint_quad(fill(
                                Bounds::new(
                                    point(b.left() + x, b.top() + px(2.)),
                                    gpui::size(px(2.), px(LINE_H - 4.)),
                                ),
                                rgb(theme::ACCENT),
                            ));
                        }
                        layouts.borrow_mut().insert(i, (b.left(), line));
                    },
                )
                .flex_1()
                .min_w(px(width))
                .h_full(),
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, ev: &MouseDownEvent, window, cx| {
                    this.mouse_down(i, ev, window, cx)
                }),
            )
            .on_mouse_move(
                cx.listener(move |this, ev: &MouseMoveEvent, _, cx| this.mouse_move(i, ev, cx)),
            )
    }
}

/// Colored runs for one line of TOML.
fn highlight(text: &str, font: &gpui::Font) -> Vec<TextRun> {
    let run = |len: usize, color: u32| TextRun {
        len,
        font: font.clone(),
        color: rgb(color).into(),
        background_color: None,
        underline: None,
        strikethrough: None,
    };
    let mut runs = match line_kind(text) {
        LineKind::Blank | LineKind::Other => vec![run(text.len(), theme::TEXT)],
        LineKind::Comment => vec![run(text.len(), theme::MUTED)],
        LineKind::Header => vec![run(text.len(), theme::CONTROL)],
        LineKind::KeyValue(k) => {
            let rest = &text[k..];
            let value = rest.trim_start_matches([' ', '=']);
            let eq = rest.len() - value.len();
            let v = value.trim_start();
            let color = if v.starts_with('"') || v.starts_with('\'') {
                0xc3e88d
            } else if v.starts_with('[') || v.starts_with('{') {
                theme::TEXT
            } else {
                0xf78c6c
            };
            vec![
                run(k, 0x82aaff),
                run(eq, theme::MUTED),
                run(value.len(), color),
            ]
        }
    };
    runs.retain(|r| r.len > 0);
    if runs.is_empty() {
        runs.push(run(0, theme::TEXT));
    }
    runs
}

impl Focusable for Editor {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Editor {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let count = self.buf.lines().len();
        let gutter = 16.0 + 8.0 * count.to_string().len().max(2) as f32;
        // The widest line sets the width the list scrolls sideways over.
        let widest = (0..count)
            .max_by_key(|&i| self.buf.line(i).chars().count())
            .unwrap_or(0);
        div()
            .id("editor")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::key))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.selecting = false),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.selecting = false),
            )
            .cursor(gpui::CursorStyle::IBeam)
            .flex()
            .flex_col()
            .flex_1()
            .min_h(px(0.))
            .py_1()
            .rounded_md()
            .border_1()
            .border_color(rgb(if focused {
                theme::ACCENT
            } else {
                theme::BORDER
            }))
            .bg(rgb(theme::INPUT))
            .font_family(MONO)
            .text_size(px(FONT))
            .line_height(px(LINE_H))
            .child(
                uniform_list(
                    "editor-lines",
                    count,
                    cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                        range
                            .map(|i| this.row(i, focused, gutter, cx))
                            .collect::<Vec<_>>()
                    }),
                )
                .with_width_from_item(Some(widest))
                .with_horizontal_sizing_behavior(ListHorizontalSizingBehavior::Unconstrained)
                .track_scroll(self.scroll.clone())
                .flex_1()
                .min_h(px(0.)),
            )
    }
}
