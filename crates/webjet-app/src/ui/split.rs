//! Movable separators between panes. Drag one to share the room
//! differently; double-click it to go back to the default.

use super::*;
use gpui::{ClickEvent, CursorStyle, DragMoveEvent, MouseButton, MouseDownEvent, Pixels, Point};

/// Thickness of a separator, which is also the gap between its panes.
pub(super) const HANDLE: f32 = 12.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Axis {
    /// Panes side by side, the separator a vertical line.
    Row,
    /// Panes above each other, the separator a horizontal line.
    Column,
}

/// One movable separator. The pane it sizes keeps its size when the
/// window changes (giving way only when the other runs out of room); the
/// other pane takes the rest.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) struct Split {
    pub id: &'static str,
    pub axis: Axis,
    /// The sized pane is the first one (left or top), else the second.
    pub sized_first: bool,
    /// Size of the sized pane, in pixels, until the user moves it.
    pub default: f32,
    /// The least the sized pane gets when dragging.
    pub min: f32,
    /// The least room dragging leaves to the other pane.
    pub rest_min: f32,
}

/// A separator pressed: where, and the pane's size then.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Grab {
    id: &'static str,
    at: f32,
    size: f32,
}

/// Pane sizes the user chose, by separator id, and the drag in progress.
#[derive(Default, Debug)]
pub(super) struct Splits {
    sizes: BTreeMap<&'static str, f32>,
    grab: Option<Grab>,
}

impl Splits {
    pub fn size(&self, s: &Split) -> f32 {
        self.sizes.get(s.id).copied().unwrap_or(s.default)
    }

    /// The separator was pressed at `at` (along its axis).
    pub fn grab(&mut self, s: &Split, at: f32) {
        self.grab = Some(Grab {
            id: s.id,
            at,
            size: self.size(s),
        });
    }

    /// The pointer moved to `at` while dragging, in a container `extent`
    /// long. Returns whether `s` is the separator being dragged.
    pub fn drag(&mut self, s: &Split, at: f32, extent: f32) -> bool {
        let Some(g) = self.grab.filter(|g| g.id == s.id) else {
            return false;
        };
        let max = (extent - HANDLE - s.rest_min).max(s.min);
        // A pane the window squeezed starts from what it shows.
        let from = g.size.min(max);
        let delta = at - g.at;
        let want = if s.sized_first {
            from + delta
        } else {
            from - delta
        };
        self.sizes.insert(s.id, want.clamp(s.min, max));
        true
    }

    pub fn reset(&mut self, s: &Split) {
        self.sizes.remove(s.id);
    }

    /// Whether `s` is held right now.
    fn held(&self, s: &Split, cx: &App) -> bool {
        cx.has_active_drag() && self.grab.is_some_and(|g| g.id == s.id)
    }
}

fn along(axis: Axis, p: Point<Pixels>) -> f32 {
    f32::from(match axis {
        Axis::Row => p.x,
        Axis::Column => p.y,
    })
}

/// What GPUI carries while a separator is dragged. It draws nothing.
#[derive(Clone)]
struct Resize(&'static str);

impl Render for Resize {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        gpui::Empty
    }
}

impl WebjetApp {
    /// Two panes with a movable separator between them. The panes fill
    /// what they're given (build them with `flex_1`, not a fixed size).
    /// The caller sizes the returned container itself.
    pub(super) fn split(
        &self,
        s: Split,
        first: impl IntoElement,
        second: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let size = self.splits.size(&s);
        let row = s.axis == Axis::Row;
        let pane = |sized: bool| {
            let d = div().flex().flex_col().overflow_hidden();
            let d = if row {
                d.min_h(px(0.))
            } else {
                d.min_w(px(0.))
            };
            if sized {
                let d = d.flex_none().flex_shrink().flex_basis(px(size));
                if row {
                    d.min_w(px(s.min))
                } else {
                    d.min_h(px(s.min))
                }
            } else if row {
                d.flex_1().min_w(px(s.rest_min))
            } else {
                d.flex_1().min_h(px(s.rest_min))
            }
        };
        let container = div()
            .flex()
            .when(!row, |d| d.flex_col())
            .on_drag_move(cx.listener(move |this, e: &DragMoveEvent<Resize>, _, cx| {
                let extent = match s.axis {
                    Axis::Row => e.bounds.size.width,
                    Axis::Column => e.bounds.size.height,
                };
                if e.drag(cx).0 == s.id
                    && this
                        .splits
                        .drag(&s, along(s.axis, e.event.position), f32::from(extent))
                {
                    cx.notify();
                }
            }));
        container
            .child(pane(s.sized_first).child(first))
            .child(self.split_handle(s, cx))
            .child(pane(!s.sized_first).child(second))
    }

    fn split_handle(&self, s: Split, cx: &mut Context<Self>) -> impl IntoElement {
        let row = s.axis == Axis::Row;
        let group = SharedString::from(format!("split-{}", s.id));
        let held = self.splits.held(&s, cx);
        // A short grip, the whole line while hovered or dragged.
        let line = div()
            .rounded_full()
            .bg(rgb(if held { theme::ACCENT } else { theme::BORDER }));
        let line = if row {
            line.w(px(2.)).h(if held {
                gpui::relative(1.)
            } else {
                px(36.).into()
            })
        } else {
            line.h(px(2.)).w(if held {
                gpui::relative(1.)
            } else {
                px(36.).into()
            })
        };
        let line = line.group_hover(group.clone(), |st| {
            let st = st.bg(rgb(theme::ACCENT));
            if row {
                st.h(gpui::relative(1.))
            } else {
                st.w(gpui::relative(1.))
            }
        });
        let id = s.id;
        div()
            .id(group.clone())
            .group(group)
            .debug_selector(move || format!("split-{id}"))
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .map(|d| {
                if row {
                    d.w(px(HANDLE)).h_full()
                } else {
                    d.h(px(HANDLE)).w_full()
                }
            })
            .cursor(if row {
                CursorStyle::ResizeColumn
            } else {
                CursorStyle::ResizeRow
            })
            .child(line)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, _, _| {
                    this.splits.grab(&s, along(s.axis, e.position));
                }),
            )
            .on_drag(Resize(s.id), |r, _, _, cx| cx.new(|_| r.clone()))
            .on_click(cx.listener(move |this, e: &ClickEvent, _, cx| {
                if e.click_count() >= 2 {
                    this.splits.reset(&s);
                    cx.notify();
                }
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIDE: Split = Split {
        id: "side",
        axis: Axis::Row,
        sized_first: false,
        default: 400.0,
        min: 200.0,
        rest_min: 300.0,
    };

    #[test]
    fn dragging_resizes_within_limits() {
        let mut s = Splits::default();
        assert_eq!(s.size(&SIDE), 400.0);
        // Not grabbed: nothing moves.
        assert!(!s.drag(&SIDE, 500.0, 1000.0));
        s.grab(&SIDE, 600.0);
        // The pane is on the right: dragging left widens it.
        assert!(s.drag(&SIDE, 550.0, 1000.0));
        assert_eq!(s.size(&SIDE), 450.0);
        // Never below its minimum, never squeezing the other pane.
        s.drag(&SIDE, 990.0, 1000.0);
        assert_eq!(s.size(&SIDE), 200.0);
        s.drag(&SIDE, 0.0, 1000.0);
        assert_eq!(s.size(&SIDE), 1000.0 - HANDLE - 300.0);
        // Another separator isn't moved by this drag.
        let other = Split {
            id: "other",
            sized_first: true,
            ..SIDE
        };
        assert!(!s.drag(&other, 0.0, 1000.0));
        assert_eq!(s.size(&other), 400.0);
        s.reset(&SIDE);
        assert_eq!(s.size(&SIDE), 400.0);
    }

    #[test]
    fn a_squeezed_pane_moves_from_what_it_shows() {
        let mut s = Splits::default();
        s.grab(&SIDE, 0.0);
        s.drag(&SIDE, -300.0, 2000.0);
        assert_eq!(s.size(&SIDE), 700.0);
        // In a smaller window the pane shows at most 600 − 12 − 300 = 288;
        // a small drag moves from there, not from 700.
        s.grab(&SIDE, 100.0);
        s.drag(&SIDE, 110.0, 600.0);
        assert_eq!(s.size(&SIDE), 600.0 - HANDLE - 300.0 - 10.0);
    }
}
