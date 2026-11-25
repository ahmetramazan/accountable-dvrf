//! Turns `results/timings.csv` into Markdown tables, one per scheme, with one
//! row per committee size and one column per step (milliseconds).
//!
//! Usage: `cargo run --release --bin timings_report -- <timings.csv> <timings.md>`

use std::collections::BTreeMap;
use std::fmt::Write as _;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let csv = std::fs::read_to_string(&args[1]).unwrap();
    // scheme -> (steps in order, n -> (t, q, step -> us))
    let mut order: Vec<String> = Vec::new();
    let mut steps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut data: BTreeMap<(String, usize), (usize, usize, BTreeMap<String, f64>)> = BTreeMap::new();
    for line in csv.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != 6 {
            continue;
        }
        let (scheme, step) = (f[0].to_string(), f[1].to_string());
        let (n, t, q): (usize, usize, usize) = (f[2].parse().unwrap(), f[3].parse().unwrap(), f[4].parse().unwrap());
        let us: f64 = f[5].parse().unwrap();
        if !order.contains(&scheme) {
            order.push(scheme.clone());
        }
        let s = steps.entry(scheme.clone()).or_default();
        if !s.contains(&step) {
            s.push(step.clone());
        }
        data.entry((scheme, n)).or_insert((t, q, BTreeMap::new())).2.insert(step, us);
    }
    let mut md = String::from("# Off-chain timings (ms, median)\n");
    for scheme in &order {
        let st = &steps[scheme];
        write!(md, "\n## {scheme}\n\n| n | t | S |").unwrap();
        for s in st {
            write!(md, " {s} |").unwrap();
        }
        md.push_str("\n|---:|---:|---:|");
        md.push_str(&"---:|".repeat(st.len()));
        md.push('\n');
        for ((sc, n), (t, q, m)) in &data {
            if sc != scheme {
                continue;
            }
            write!(md, "| {n} | {t} | {q} |").unwrap();
            for s in st {
                match m.get(s) {
                    Some(us) => write!(md, " {:.2} |", us / 1e3).unwrap(),
                    None => md.push_str(" - |"),
                }
            }
            md.push('\n');
        }
    }
    std::fs::write(&args[2], &md).unwrap();
    print!("{md}");
}
