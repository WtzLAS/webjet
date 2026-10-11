//! A small single-line text field: typing, a cursor and a selection (keys
//! and mouse), copy/cut/paste, and masking for passphrases. Enough for the
//! app's forms without a widget library. The editing logic is
//! `crate::text::Line`.

use crate::text::{Line, Move};
use gpui::{
    App, Bounds, ClipboardItem, Context, DispatchPhase, FocusHandle, Focusable, KeyDownEvent,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, ShapedLine, SharedString,
    Window, canvas, div, fill, point, prelude::*, px, rgb, rgba,
};
use std::cell::RefCell;
use std::rc::Rc;

pub struct Field {
    focus: FocusHandle,
    /// A secret field's text is wiped when it is replaced or dropped.
    line: Line,
    placeholder: SharedString,
    secret: bool,
    /// The painted text's left edge and shaping, for the mouse.
    layout: Rc<RefCell<Option<(Pixels, ShapedLine)>>>,
    /// A mouse selection in progress.
    selecting: bool,
}

impl Field {
    pub fn new(cx: &mut Context<Self>, placeholder: &str, secret: bool) -> Field {
        Field {
            focus: cx.focus_handle(),
            line: Line::new(secret),
            placeholder: placeholder.to_string().into(),
            secret,
            layout: Rc::new(RefCell::new(None)),
            selecting: false,
        }
    }

    pub fn text(&self) -> &str {
        self.line.text()
    }

    pub fn set_text(&mut self, t: &str, cx: &mut Context<Self>) {
        self.line.set_text(t);
        cx.notify();
    }

    pub fn clear(&mut self, cx: &mut Context<Self>) {
        self.set_text("", cx);
    }

    pub fn focus(&self, window: &mut Window) {
        self.focus.focus(window);
    }

    /// The text as shown: one `*` per character when secret.
    fn shown(&self) -> String {
        if self.secret {
            "*".repeat(self.line.text().chars().count())
        } else {
            self.line.text().to_string()
        }
    }

    /// A byte offset in the text → the same place in [`Self::shown`].
    fn shown_offset(&self, at: usize) -> usize {
        if self.secret {
            self.line.text()[..at].chars().count()
        } else {
            at
        }
    }

    /// A byte offset in [`Self::shown`] → the same place in the text.
    fn text_offset(&self, at: usize) -> usize {
        let t = self.line.text();
        if self.secret {
            t.char_indices().nth(at).map_or(t.len(), |(i, _)| i)
        } else {
            at
        }
    }

    /// The place in the text under window x coordinate `x`.
    fn offset_at(&self, x: Pixels) -> usize {
        let at = self
            .layout
            .borrow()
            .as_ref()
            .map_or(0, |(left, l)| l.closest_index_for_x(x - *left));
        if self.line.text().is_empty() {
            // The placeholder is shown.
            0
        } else {
            self.text_offset(at)
        }
    }

    fn key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let k = &ev.keystroke;
        let m = &k.modifiers;
        // ⌘ on macOS, Ctrl elsewhere.
        let cmd = m.platform || m.control;
        let (shift, alt) = (m.shift, m.alt);
        let line = &mut self.line;
        let mut mv = |mo: Move| line.move_cursor(mo, shift);
        match k.key.as_str() {
            "left" if cmd => mv(Move::Home),
            "left" if alt => mv(Move::WordLeft),
            "left" => mv(Move::Left),
            "right" if cmd => mv(Move::End),
            "right" if alt => mv(Move::WordRight),
            "right" => mv(Move::Right),
            "up" | "home" => mv(Move::Home),
            "down" | "end" => mv(Move::End),
            "escape" if self.line.selection().is_some() => {
                let c = self.line.cursor();
                self.line.set_cursor(c, false);
            }
            "backspace" if cmd => self.line.delete_to_start(),
            "backspace" if alt => self.line.delete_word_left(),
            "backspace" => self.line.backspace(),
            "delete" if alt => self.line.delete_word_right(),
            "delete" => self.line.delete(),
            "a" if cmd => self.line.select_all(),
            "c" | "x" if cmd && self.secret => {
                // A passphrase never goes to the clipboard.
            }
            "c" if cmd => {
                if let Some(t) = self.line.selected_text() {
                    cx.write_to_clipboard(ClipboardItem::new_string(t.to_string()));
                }
            }
            "x" if cmd => {
                if let Some(t) = self.line.selected_text() {
                    cx.write_to_clipboard(ClipboardItem::new_string(t.to_string()));
                    self.line.delete();
                }
            }
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.line.insert(&t);
                }
            }
            _ => {
                if cmd {
                    // Not ours (⌘Q, …).
                    return;
                }
                match &k.key_char {
                    Some(c) if !c.chars().any(char::is_control) => self.line.insert(c),
                    // Enter, Tab, Escape…: for the form around the field.
                    _ => return,
                }
            }
        }
        cx.notify();
    }

    fn mouse_down(&mut self, ev: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.focus.focus(window);
        let at = self.offset_at(ev.position.x);
        match ev.click_count {
            2 => self.line.select_word(at),
            n if n >= 3 => self.line.select_all(),
            _ => {
                self.line.set_cursor(at, ev.modifiers.shift);
                self.selecting = true;
            }
        }
        cx.notify();
    }

    fn drag_to(&mut self, ev: &MouseMoveEvent, cx: &mut Context<Self>) {
        if ev.pressed_button != Some(MouseButton::Left) {
            // The button went up outside the window.
            self.selecting = false;
            cx.notify();
            return;
        }
        let at = self.offset_at(ev.position.x);
        if at != self.line.cursor() {
            self.line.set_cursor(at, true);
            cx.notify();
        }
    }
}

impl Focusable for Field {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Field {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let empty = self.line.text().is_empty();
        let (shown, color) = if empty {
            (self.placeholder.to_string(), rgb(super::theme::MUTED))
        } else {
            (self.shown(), rgb(super::theme::TEXT))
        };
        let selection = self
            .line
            .selection()
            .filter(|_| focused)
            .map(|(s, e)| (self.shown_offset(s), self.shown_offset(e)));
        let caret = focused.then(|| self.shown_offset(self.line.cursor()));
        let layout = self.layout.clone();
        let selecting = self.selecting;
        let this = cx.entity().downgrade();
        // Behind the text: the selection and the cursor. The text itself
        // is an ordinary child, so the field sizes itself as before.
        let marks = {
            let shown = shown.clone();
            canvas(
                |_, _, _| (),
                move |b: Bounds<Pixels>, _, window, _cx| {
                    let style = window.text_style();
                    let size = style.font_size.to_pixels(window.rem_size());
                    let run = style.to_run(shown.len());
                    let line = window
                        .text_system()
                        .shape_line(shown.into(), size, &[run], None);
                    if let Some((from, to)) = selection {
                        window.paint_quad(fill(
                            Bounds::from_corners(
                                point(b.left() + line.x_for_index(from), b.top()),
                                point(b.left() + line.x_for_index(to), b.bottom()),
                            ),
                            rgba(0x4c8dff66),
                        ));
                    }
                    if let Some(at) = caret {
                        let at = if empty { 0 } else { at };
                        window.paint_quad(fill(
                            Bounds::new(
                                point(b.left() + line.x_for_index(at), b.top() + px(1.)),
                                gpui::size(px(1.5), b.size.height - px(2.)),
                            ),
                            rgb(super::theme::ACCENT),
                        ));
                    }
                    *layout.borrow_mut() = Some((b.left(), line));
                    if selecting {
                        // Window-wide, so dragging past the field's ends
                        // still selects.
                        let moved = this.clone();
                        window.on_mouse_event(move |e: &MouseMoveEvent, phase, _, cx| {
                            if phase == DispatchPhase::Bubble {
                                let _ = moved.update(cx, |f, cx| f.drag_to(e, cx));
                            }
                        });
                        let up = this;
                        window.on_mouse_event(move |e: &MouseUpEvent, phase, _, cx| {
                            if phase == DispatchPhase::Bubble && e.button == MouseButton::Left {
                                let _ = up.update(cx, |f, cx| {
                                    f.selecting = false;
                                    cx.notify();
                                });
                            }
                        });
                    }
                },
            )
            .absolute()
            .top_0()
            .left_0()
            .size_full()
        };
        div()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::key))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::mouse_down))
            .cursor(gpui::CursorStyle::IBeam)
            .px_2()
            .py_1()
            .min_w(px(220.))
            .rounded_md()
            .border_1()
            .border_color(rgb(if focused {
                super::theme::ACCENT
            } else {
                super::theme::BORDER
            }))
            .bg(rgb(super::theme::INPUT))
            .text_color(color)
            .child(
                div()
                    .relative()
                    // Room for the cursor at the end.
                    .pr(px(2.))
                    .child(marks)
                    .child(div().whitespace_nowrap().child(shown)),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{Modifiers, MouseDownEvent, MouseUpEvent, TestAppContext, point};

    /// A press at `x`, `clicks` times, in the middle of the field's line.
    fn click(cx: &mut gpui::VisualTestContext, x: f32, clicks: usize) {
        let at = point(px(x), px(14.));
        for n in 1..=clicks {
            cx.simulate_event(MouseDownEvent {
                button: MouseButton::Left,
                position: at,
                click_count: n,
                ..Default::default()
            });
            cx.simulate_event(MouseUpEvent {
                button: MouseButton::Left,
                position: at,
                click_count: n,
                ..Default::default()
            });
        }
    }

    #[gpui::test]
    fn text_can_be_selected_with_the_mouse_and_keys(cx: &mut TestAppContext) {
        let (field, cx) = cx.add_window_view(|_, cx| Field::new(cx, "find", false));
        field.update(cx, |f, cx| f.set_text("alpha beta-2 gamma", cx));
        cx.run_until_parked();
        let selected = |cx: &mut gpui::VisualTestContext| {
            field.read_with(cx, |f, _| f.line.selected_text().map(str::to_string))
        };
        // Drag from the start to past the end: all of it.
        cx.simulate_mouse_down(
            point(px(2.), px(14.)),
            MouseButton::Left,
            Modifiers::default(),
        );
        cx.run_until_parked();
        cx.simulate_mouse_move(
            point(px(900.), px(14.)),
            MouseButton::Left,
            Modifiers::default(),
        );
        cx.simulate_mouse_up(
            point(px(900.), px(14.)),
            MouseButton::Left,
            Modifiers::default(),
        );
        cx.run_until_parked();
        assert_eq!(selected(cx).as_deref(), Some("alpha beta-2 gamma"));
        // A double click on the middle word selects it.
        let mid = field.read_with(cx, |f, _| {
            let layout = f.layout.borrow();
            let (left, line) = layout.as_ref().expect("painted");
            f32::from(*left + line.x_for_index(9))
        });
        click(cx, mid, 2);
        cx.run_until_parked();
        assert_eq!(selected(cx).as_deref(), Some("beta-2"));
        // Typing replaces the selection; shift-arrows select.
        cx.simulate_input("x");
        cx.simulate_keystrokes("shift-left shift-left");
        assert_eq!(selected(cx).as_deref(), Some(" x"));
        cx.simulate_keystrokes("cmd-a backspace");
        assert_eq!(field.read_with(cx, |f, _| f.text().to_string()), "");
    }
}
