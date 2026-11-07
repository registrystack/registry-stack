// SPDX-License-Identifier: Apache-2.0
//! Exposition format, escaping, ordering, number formatting, histogram
//! arithmetic, and cardinality bounds of the metrics primitive.

use registry_platform_metrics::{
    CounterVec, Exposition, HistogramSnapshot, HistogramVec, LabelSpace, MetricKind, MetricsError,
    SumCountOrder, CONTENT_TYPE,
};

#[test]
fn the_content_type_names_text_format_0_0_4() {
    assert_eq!(CONTENT_TYPE, "text/plain; version=0.0.4");
}

#[test]
fn a_header_writes_help_then_type_and_help_is_optional() {
    let mut out = Exposition::new();
    out.header("a_total", Some("Things."), MetricKind::Counter)
        .unwrap();
    out.header("b", None, MetricKind::Gauge).unwrap();
    out.header("c", Some("Latency."), MetricKind::Histogram)
        .unwrap();
    assert_eq!(
        out.finish(),
        "# HELP a_total Things.\n# TYPE a_total counter\n# TYPE b gauge\n# HELP c Latency.\n# TYPE c histogram\n"
    );
}

#[test]
fn help_text_escapes_backslash_and_newline_only() {
    let mut out = Exposition::new();
    out.header(
        "a",
        Some("back\\slash\nnewline \"quoted\""),
        MetricKind::Gauge,
    )
    .unwrap();
    assert_eq!(
        out.finish(),
        "# HELP a back\\\\slash\\nnewline \"quoted\"\n# TYPE a gauge\n"
    );
}

#[test]
fn label_values_escape_backslash_quote_and_newline() {
    let mut out = Exposition::new();
    out.sample("m", &[("source", "a\"b\\c\nd")], 1_u64).unwrap();
    assert_eq!(out.finish(), "m{source=\"a\\\"b\\\\c\\nd\"} 1\n");
}

#[test]
fn braces_and_non_ascii_in_label_values_pass_through() {
    let mut out = Exposition::new();
    out.sample(
        "m",
        &[("route", "/v1/messages/{message_id}"), ("n", "é")],
        1_u64,
    )
    .unwrap();
    assert_eq!(
        out.finish(),
        "m{route=\"/v1/messages/{message_id}\",n=\"é\"} 1\n"
    );
}

#[test]
fn an_unlabelled_sample_has_no_braces() {
    let mut out = Exposition::new();
    out.sample("m", &[], 7_u64).unwrap();
    assert_eq!(out.finish(), "m 7\n");
}

#[test]
fn labels_keep_the_order_the_caller_gave() {
    let mut out = Exposition::new();
    out.sample("m", &[("z", "1"), ("a", "2")], 1_u64).unwrap();
    assert_eq!(out.finish(), "m{z=\"1\",a=\"2\"} 1\n");
}

#[test]
fn numbers_format_as_integers_or_shortest_floats() {
    let mut out = Exposition::new();
    out.sample("u", &[], 18_446_744_073_709_551_615_u64)
        .unwrap();
    out.sample("i", &[], -3_i64).unwrap();
    out.sample("z", &[], 0_usize).unwrap();
    out.sample("b", &[], u8::from(true)).unwrap();
    out.sample("f0", &[], 0.0_f64).unwrap();
    out.sample("f1", &[], 1.0_f64).unwrap();
    out.sample("f2", &[], 90.5_f64).unwrap();
    out.sample("f3", &[], 0.005_f64).unwrap();
    out.sample("f4", &[], 0.1_f64 + 0.2_f64).unwrap();
    out.sample("f5", &[], 1e21_f64).unwrap();
    out.sample("nan", &[], f64::NAN).unwrap();
    out.sample("pinf", &[], f64::INFINITY).unwrap();
    out.sample("ninf", &[], f64::NEG_INFINITY).unwrap();
    assert_eq!(
        out.finish(),
        "u 18446744073709551615\ni -3\nz 0\nb 1\nf0 0\nf1 1\nf2 90.5\nf3 0.005\nf4 0.30000000000000004\nf5 1000000000000000000000\nnan NaN\npinf +Inf\nninf -Inf\n"
    );
}

#[test]
fn invalid_names_are_refused() {
    let mut out = Exposition::new();
    for name in ["", "1abc", "a-b", "a b", "a\"b", "é"] {
        assert!(
            matches!(
                out.header(name, None, MetricKind::Gauge),
                Err(MetricsError::InvalidMetricName(_))
            ),
            "{name:?}"
        );
        assert!(matches!(
            out.sample(name, &[], 1_u64),
            Err(MetricsError::InvalidMetricName(_))
        ));
    }
    assert!(out.sample("ok:name_1", &[], 1_u64).is_ok());
    for label in ["", "1a", "a-b", "a:b", "__reserved"] {
        assert!(
            out.sample("m", &[(label, "v")], 1_u64).is_err(),
            "{label:?}"
        );
    }
    assert!(matches!(
        out.sample("m", &[("a", "1"), ("a", "2")], 1_u64),
        Err(MetricsError::DuplicateLabelName(_))
    ));
}

#[test]
fn a_refused_sample_writes_nothing() {
    let mut out = Exposition::new();
    out.sample("m", &[("a", "1"), ("a", "2")], 1_u64)
        .unwrap_err();
    assert_eq!(out.as_str(), "");
}

#[test]
fn a_histogram_writes_cumulative_buckets_inf_sum_and_count() {
    let bounds = [0.005, 0.01, 0.025, 1.0, 5.0];
    let snapshot = HistogramSnapshot {
        cumulative: vec![0, 0, 1, 1, 1],
        count: 1,
        sum: 0.03,
    };
    let mut out = Exposition::new();
    out.histogram(
        "h_seconds",
        &[("route", "/x")],
        &bounds,
        &snapshot,
        SumCountOrder::SumThenCount,
    )
    .unwrap();
    assert_eq!(
        out.finish(),
        "h_seconds_bucket{route=\"/x\",le=\"0.005\"} 0\n\
         h_seconds_bucket{route=\"/x\",le=\"0.01\"} 0\n\
         h_seconds_bucket{route=\"/x\",le=\"0.025\"} 1\n\
         h_seconds_bucket{route=\"/x\",le=\"1\"} 1\n\
         h_seconds_bucket{route=\"/x\",le=\"5\"} 1\n\
         h_seconds_bucket{route=\"/x\",le=\"+Inf\"} 1\n\
         h_seconds_sum{route=\"/x\"} 0.03\n\
         h_seconds_count{route=\"/x\"} 1\n"
    );
}

#[test]
fn a_histogram_can_write_count_before_sum() {
    let snapshot = HistogramSnapshot {
        cumulative: vec![1],
        count: 1,
        sum: 0.5,
    };
    let mut out = Exposition::new();
    out.histogram("h", &[], &[1.0], &snapshot, SumCountOrder::CountThenSum)
        .unwrap();
    assert_eq!(
        out.finish(),
        "h_bucket{le=\"1\"} 1\nh_bucket{le=\"+Inf\"} 1\nh_count 1\nh_sum 0.5\n"
    );
}

#[test]
fn a_histogram_refuses_a_malformed_shape() {
    let snapshot = HistogramSnapshot {
        cumulative: vec![1, 1],
        count: 1,
        sum: 0.5,
    };
    let mut out = Exposition::new();
    assert!(matches!(
        out.histogram("h", &[], &[1.0], &snapshot, SumCountOrder::SumThenCount),
        Err(MetricsError::InvalidHistogram)
    ));
    assert!(matches!(
        out.histogram(
            "h",
            &[("le", "1")],
            &[1.0, 2.0],
            &snapshot,
            SumCountOrder::SumThenCount
        ),
        Err(MetricsError::ReservedLabelName(_))
    ));
    assert_eq!(out.as_str(), "");
}

#[test]
fn histogram_vec_buckets_are_cumulative_and_bounds_are_inclusive() {
    let histogram = HistogramVec::new(
        "h",
        "Latency.",
        &[0.01, 0.025, 0.05],
        LabelSpace::bounded(&["route"], 4).unwrap(),
    )
    .unwrap();
    histogram.observe(&["/a"], 0.025).unwrap();
    histogram.observe(&["/a"], 0.03).unwrap();
    histogram.observe(&["/a"], 9.0).unwrap();
    let snapshots = histogram.snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].0, vec!["/a".to_owned()]);
    assert_eq!(snapshots[0].1.cumulative, vec![0, 1, 2]);
    assert_eq!(snapshots[0].1.count, 3);
    assert!((snapshots[0].1.sum - 9.055).abs() < 1e-12);
}

#[test]
fn histogram_vec_refuses_bad_bounds_and_observations() {
    let space = || LabelSpace::bounded(&[], 1).unwrap();
    for bounds in [
        &[][..],
        &[1.0, 1.0][..],
        &[2.0, 1.0][..],
        &[f64::NAN][..],
        &[f64::INFINITY][..],
    ] {
        assert!(matches!(
            HistogramVec::new("h", "x", bounds, space()),
            Err(MetricsError::InvalidHistogram)
        ));
    }
    let histogram = HistogramVec::new("h", "x", &[1.0], space()).unwrap();
    assert!(matches!(
        histogram.observe(&[], f64::NAN),
        Err(MetricsError::NonFiniteObservation)
    ));
    assert!(matches!(
        histogram.observe(&[], f64::INFINITY),
        Err(MetricsError::NonFiniteObservation)
    ));
    assert!(histogram.snapshots().is_empty());
}

#[test]
fn bounded_series_render_in_sorted_label_order() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::bounded(&["route", "method"], 8).unwrap(),
    )
    .unwrap();
    counter.inc(&["/b", "GET"]).unwrap();
    counter.inc(&["/a", "POST"]).unwrap();
    counter.inc(&["/a", "GET"]).unwrap();
    counter.inc(&["/a", "GET"]).unwrap();
    let mut out = Exposition::new();
    counter.write(&mut out).unwrap();
    assert_eq!(
        out.finish(),
        "# HELP c_total Count.\n# TYPE c_total counter\n\
         c_total{route=\"/a\",method=\"GET\"} 2\n\
         c_total{route=\"/a\",method=\"POST\"} 1\n\
         c_total{route=\"/b\",method=\"GET\"} 1\n"
    );
}

#[test]
fn a_bounded_space_refuses_new_series_past_its_limit_and_keeps_counting_existing_ones() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::bounded(&["route"], 2).unwrap(),
    )
    .unwrap();
    counter.inc(&["/a"]).unwrap();
    counter.inc(&["/b"]).unwrap();
    assert!(matches!(
        counter.inc(&["/c"]),
        Err(MetricsError::SeriesLimit { max: 2 })
    ));
    counter.inc(&["/a"]).unwrap();
    assert_eq!(counter.get(&["/a"]), Some(2));
    assert_eq!(counter.get(&["/c"]), None);
    assert_eq!(counter.refused(), 1);
    let mut out = Exposition::new();
    counter.write_samples(&mut out).unwrap();
    assert!(!out.as_str().contains("/c"));
}

#[test]
fn refusals_never_echo_label_values() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::bounded(&["route"], 1).unwrap(),
    )
    .unwrap();
    counter.inc(&["/a"]).unwrap();
    let error = counter.inc(&["/personal-canary"]).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("personal-canary"));
    let long = "x".repeat(300);
    let error = counter.inc(&[long.as_str()]).unwrap_err();
    assert!(matches!(error, MetricsError::LabelValueTooLong { .. }));
    assert!(!format!("{error} {error:?}").contains(&long));
}

#[test]
fn a_wrong_number_of_label_values_is_refused() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::bounded(&["a", "b"], 2).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        counter.inc(&["only-one"]),
        Err(MetricsError::LabelCount {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn a_closed_zero_filled_space_exposes_every_declared_series_in_declared_order() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::closed_zero_filled(
            &["outcome"],
            &[
                &["accepted"],
                &["transient"],
                &["permanent"],
                &["maybe-sent"],
            ],
        )
        .unwrap(),
    )
    .unwrap();
    counter.inc(&["maybe-sent"]).unwrap();
    assert!(matches!(
        counter.inc(&["undeclared"]),
        Err(MetricsError::UnknownSeries)
    ));
    let mut out = Exposition::new();
    counter.write_samples(&mut out).unwrap();
    assert_eq!(
        out.finish(),
        "c_total{outcome=\"accepted\"} 0\nc_total{outcome=\"transient\"} 0\nc_total{outcome=\"permanent\"} 0\nc_total{outcome=\"maybe-sent\"} 1\n"
    );
    assert_eq!(counter.refused(), 1);
}

#[test]
fn a_closed_sparse_space_exposes_only_seen_series_in_declared_order() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::closed(&["outcome"], &[&["success"], &["cancelled"], &["timeout"]]).unwrap(),
    )
    .unwrap();
    counter.inc(&["timeout"]).unwrap();
    counter.inc(&["success"]).unwrap();
    let mut out = Exposition::new();
    counter.write_samples(&mut out).unwrap();
    assert_eq!(
        out.finish(),
        "c_total{outcome=\"success\"} 1\nc_total{outcome=\"timeout\"} 1\n"
    );
}

#[test]
fn an_unlabelled_counter_is_one_closed_series() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::closed_zero_filled(&[], &[&[]]).unwrap(),
    )
    .unwrap();
    counter.add(&[], 4).unwrap();
    let mut out = Exposition::new();
    counter.write(&mut out).unwrap();
    assert_eq!(
        out.finish(),
        "# HELP c_total Count.\n# TYPE c_total counter\nc_total 4\n"
    );
}

#[test]
fn space_construction_validates_names_declarations_and_limits() {
    assert!(matches!(
        LabelSpace::bounded(&["a-b"], 1),
        Err(MetricsError::InvalidLabelName(_))
    ));
    assert!(matches!(
        LabelSpace::bounded(&["a", "a"], 1),
        Err(MetricsError::DuplicateLabelName(_))
    ));
    assert!(matches!(
        LabelSpace::bounded(&[], 0),
        Err(MetricsError::InvalidSeriesLimit)
    ));
    assert!(matches!(
        LabelSpace::bounded(&[], 10_001),
        Err(MetricsError::InvalidSeriesLimit)
    ));
    assert!(matches!(
        LabelSpace::closed(&["a"], &[&["x"], &["x"]]),
        Err(MetricsError::DuplicateSeries)
    ));
    assert!(matches!(
        LabelSpace::closed(&["a"], &[&["x", "y"]]),
        Err(MetricsError::LabelCount { .. })
    ));
}

#[test]
fn counters_saturate_instead_of_wrapping() {
    let counter = CounterVec::new(
        "c_total",
        "Count.",
        LabelSpace::closed_zero_filled(&[], &[&[]]).unwrap(),
    )
    .unwrap();
    counter.add(&[], u64::MAX).unwrap();
    counter.inc(&[]).unwrap();
    assert_eq!(counter.get(&[]), Some(u64::MAX));
}

#[test]
fn counters_count_exactly_across_threads() {
    let counter = std::sync::Arc::new(
        CounterVec::new("c_total", "Count.", LabelSpace::bounded(&["k"], 1).unwrap()).unwrap(),
    );
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let counter = std::sync::Arc::clone(&counter);
            std::thread::spawn(move || {
                for _ in 0..100 {
                    counter.inc(&["x"]).unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(counter.get(&["x"]), Some(800));
}
