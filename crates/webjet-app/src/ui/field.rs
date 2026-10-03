//! A small single-line text field: typing, backspace, paste, and masking
//! for passphrases. Enough for the app's forms without a widget library.

use gpui::{
    App, ClipboardItem, Context, FocusHandle, Focusable, KeyDownEvent, SharedString, Window, div,
    prelude::*, px, rgb,
};

pub struct Field {
    focus: FocusHandle,
    text: String,
    placeholder: SharedString,
    secret: bool,
}

impl Field {
    pub fn new(cx: &mut Context<Self>, placeholder: &str, secret: bool) -> Field {
        Field {
            focus: cx.focus_handle(),
            text: String::new(),
            placeholder: placeholder.to_string().into(),
            secret,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn set_text(&mut self, t: &str, cx: &mut Context<Self>) {
        self.text = t.to_string();
        cx.notify();
    }

    pub fn clear(&mut self, cx: &mut Context<Self>) {
        self.set_text("", cx);
    }

    pub fn focus(&self, window: &mut Window) {
        self.focus.focus(window);
    }

    fn key(&mut self, ev: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let k = &ev.keystroke;
        let cmd = k.modifiers.platform || k.modifiers.control;
        match k.key.as_str() {
            "backspace" => {
                if cmd {
                    self.text.clear();
                } else {
                    self.text.pop();
                }
            }
            "v" if cmd => {
                if let Some(t) = cx.read_from_clipboard().and_then(|c| c.text()) {
                    self.text.push_str(t.lines().next().unwrap_or(""));
                }
            }
            "c" if cmd && !self.secret => {
                cx.write_to_clipboard(ClipboardItem::new_string(self.text.clone()))
            }
            _ => {
                if cmd {
                    return;
                }
                match &k.key_char {
                    Some(c) if !c.chars().any(char::is_control) => self.text.push_str(c),
                    _ => return,
                }
            }
        }
        cx.notify();
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
        let (shown, color) = if self.text.is_empty() {
            (self.placeholder.to_string(), rgb(super::theme::MUTED))
        } else if self.secret {
            (
                "*".repeat(self.text.chars().count()),
                rgb(super::theme::TEXT),
            )
        } else {
            (self.text.clone(), rgb(super::theme::TEXT))
        };
        div()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::key))
            .on_mouse_down(
                gpui::MouseButton::Left,
                cx.listener(|this, _, window, _| this.focus.focus(window)),
            )
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
            .child(format!("{shown}{}", if focused { "▏" } else { "" }))
    }
}
