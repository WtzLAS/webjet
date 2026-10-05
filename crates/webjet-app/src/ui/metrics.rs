//! Metrics: the OpenMetrics families the agent exports (§12.5) — this
//! node's own report, or on a controller every node's latest report, the
//! same text Prometheus scrapes.

use super::split::{Axis, Split};
use super::*;

/// The family list beside the selected family.
const METRICS: Split = Split {
    id: "metrics",
    axis: Axis::Row,
    sized_first: true,
    default: 380.0,
    min: 240.0,
    rest_min: 300.0,
};

/// At most this many samples are listed for one family.
const SAMPLES_SHOWN: usize = 500;

impl WebjetApp {
    pub(super) fn render_metrics(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        if let Err(e) = &s.metrics {
            return panel()
                .child(heading("Metrics"))
                .child(muted(format!("The agent didn't send its metrics: {e}")))
                .into_any_element();
        }
        let families = self.families.clone();
        let filter = self.metric_filter.read(cx).text().to_string();
        let shown: Vec<&Family> = families.iter().filter(|f| f.matches(&filter)).collect();
        let samples: usize = families.iter().map(|f| f.samples.len()).sum();

        // ---- top line: scope switch and counts
        let mut top = div()
            .flex()
            .items_center()
            .gap_3()
            .child(self.metric_filter.clone())
            .child(muted(format!(
                "{} of {} families · {samples} samples",
                shown.len(),
                families.len()
            )));
        if s.is_controller() {
            let mut sw = div().flex().gap_1();
            for (i, seg) in segmented(
                "metrics-scope",
                &["this node", "every node"],
                usize::from(self.metrics_all),
            )
            .into_iter()
            .enumerate()
            {
                sw = sw.child(seg.on_click(cx.listener(move |this, _, _, cx| {
                    let all = i == 1;
                    if this.metrics_all != all {
                        this.metrics_all = all;
                        this.refresh(cx);
                    }
                })));
            }
            top = top.child(sw);
        } else {
            top = top.child(
                muted("this node's report · every node's reports are on the controllers").text_xs(),
            );
        }

        // ---- family list
        let mut list = scroll("families").gap(px(1.));
        for (i, f) in shown.iter().enumerate() {
            let sel = self.family.as_deref() == Some(f.name.as_str());
            let name = f.name.clone();
            list = list.child(
                div()
                    .id(("family", i))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py(px(2.))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .child(cell(240., f.name.trim_start_matches("webjet_").to_string()))
                    .child(cell(56., f.kind.clone()).text_xs().text_color(rgb(
                        if f.kind == "counter" {
                            theme::TX
                        } else {
                            theme::RX
                        },
                    )))
                    .child(cell(40., f.samples.len().to_string()).text_color(rgb(theme::MUTED)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.family = Some(name.clone());
                        cx.notify();
                    })),
            );
        }
        if shown.is_empty() {
            list = list.child(muted("No family matches the filter."));
        }
        let left = panel()
            .flex_1()
            .min_h(px(0.))
            .child(header_row(&[
                (240., "family"),
                (56., "type"),
                (40., "samples"),
            ]))
            .child(list);

        // ---- the selected family
        let chosen = self
            .family
            .as_ref()
            .and_then(|n| families.iter().find(|f| &f.name == n));
        let right = match chosen {
            None => panel()
                .flex_1()
                .child(heading("Metrics"))
                .child(muted("Select a family to see its samples."))
                .child(div().pt_2().child(muted(
                    "Prometheus scrapes the same text from the controllers (`webjetctl local metrics --all`).",
                )))
                .into_any_element(),
            Some(f) => {
                // Labels every sample shares are shown once, above the table.
                let common: Vec<(String, String)> = f
                    .samples
                    .first()
                    .map(|first| {
                        first
                            .labels
                            .iter()
                            .filter(|l| f.samples.iter().all(|s| s.labels.contains(l)))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let skip: Vec<&str> = common.iter().map(|(k, _)| k.as_str()).collect();
                let mut rows = scroll("samples").gap(px(1.));
                for (i, smp) in f.samples.iter().take(SAMPLES_SHOWN).enumerate() {
                    let labels = smp.labels_text(&skip);
                    rows = rows.child(
                        div()
                            .id(("sample", i))
                            .flex()
                            .gap_2()
                            .px_2()
                            .py(px(2.))
                            .rounded_sm()
                            .hover(|s| s.bg(rgb(theme::RAISED)))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.))
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .text_ellipsis()
                                    .child(if labels.is_empty() { "—".to_string() } else { labels }),
                            )
                            .child(
                                cell(130., openmetrics::value_text(&f.name, smp.value))
                                    .flex()
                                    .justify_end(),
                            )
                            .child(
                                cell(
                                    90.,
                                    smp.ts_ms
                                        .map(|t| model::relative(t, now_ms()))
                                        .unwrap_or_default(),
                                )
                                .text_xs()
                                .text_color(rgb(theme::MUTED)),
                            ),
                    );
                }
                let mut p = panel()
                    .flex_1()
                    .min_h(px(0.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(heading(&f.name))
                            .child(chip(&f.kind, theme::MUTED)),
                    )
                    .child(muted(f.help.clone()));
                if !common.is_empty() {
                    p = p.child(
                        muted(
                            common
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join("  "),
                        )
                        .text_xs(),
                    );
                }
                if f.samples.len() > 1 && f.kind == "counter" {
                    p = p.child(label_value(
                        "Sum",
                        openmetrics::value_text(&f.name, f.total()),
                    ));
                }
                if f.samples.len() > SAMPLES_SHOWN {
                    p = p.child(chip(
                        &format!("showing {SAMPLES_SHOWN} of {} samples", f.samples.len()),
                        theme::WARN,
                    ));
                }
                p.child(div().pt_1().child(header_row(&[(300., "labels"), (130., "value"), (90., "taken")])))
                    .child(rows)
                    .into_any_element()
            }
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(top)
            .child(self.split(METRICS, left, right, cx).flex_1().min_h(px(0.)))
            .into_any_element()
    }
}
