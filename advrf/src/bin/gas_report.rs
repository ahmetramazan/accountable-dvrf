//! Matches the receipts of a `forge script` broadcast with the labels written
//! by `Measure.s.sol` and splits the gas of every verification transaction
//! into intrinsic, calldata and execution gas.
//!
//! Usage: `cargo run --release --bin gas_report -- <run-latest.json> <labels.csv> <out_dir>`
//!
//! Gas accounting (EIP-2028, EIP-7623): with `tokens = zero_bytes + 4 *
//! nonzero_bytes`, a call transaction uses
//! `21000 + max(4 * tokens + execution, 10 * tokens)`. The calldata gas is
//! `4 * tokens`, and the execution gas is what remains, unless the floor
//! applies, which the report marks.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn hex_u64(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

struct Row {
    scheme: String,
    mode: String,
    n: usize,
    t: usize,
    q: usize,
    kind: String,
    bytes: usize,
    zeros: usize,
    calldata_gas: u64,
    floor: bool,
    exec: u64,
    total: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run: Value = serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let labels = std::fs::read_to_string(&args[2]).unwrap();
    let out = std::path::Path::new(&args[3]);
    let txs = run["transactions"].as_array().unwrap();
    let receipts = run["receipts"].as_array().unwrap();
    let labels: Vec<Vec<String>> =
        labels.lines().skip(1).filter(|l| !l.is_empty()).map(|l| l.split(',').map(String::from).collect()).collect();
    assert_eq!(labels.len(), txs.len(), "labels and transactions differ in number");

    let mut rows = Vec::new();
    for ((l, tx), rc) in labels.iter().zip(txs).zip(receipts) {
        assert_eq!(rc["status"].as_str().unwrap(), "0x1", "failed transaction {l:?}");
        let input = hex::decode(tx["transaction"]["input"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let zeros = input.iter().filter(|&&b| b == 0).count();
        let tokens = (zeros + 4 * (input.len() - zeros)) as u64;
        let total = hex_u64(&rc["gasUsed"]);
        let calldata_gas = 4 * tokens;
        let floor = total == 21000 + 10 * tokens;
        let exec = total.saturating_sub(21000 + calldata_gas);
        rows.push(Row {
            scheme: l[0].clone(),
            mode: l[1].clone(),
            n: l[2].parse().unwrap(),
            t: l[3].parse().unwrap(),
            q: l[4].parse().unwrap(),
            kind: l[5].clone(),
            bytes: input.len(),
            zeros,
            calldata_gas,
            floor,
            exec,
            total,
        });
    }

    let mut csv = String::from(
        "scheme,mode,n,t,quorum,kind,calldata_bytes,zero_bytes,calldata_gas,floor_applies,execution_gas,total_gas\n",
    );
    for r in &rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            r.scheme, r.mode, r.n, r.t, r.q, r.kind, r.bytes, r.zeros, r.calldata_gas, r.floor, r.exec, r.total
        )
        .unwrap();
    }
    std::fs::write(out.join("gas.csv"), &csv).unwrap();

    // Markdown summary: total gas of the cheapest mode per scheme and n.
    let mut best: BTreeMap<(String, usize), &Row> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.kind == "verify") {
        let e = best.entry((r.scheme.clone(), r.n)).or_insert(r);
        if r.total < e.total {
            *e = r;
        }
    }
    let schemes = ["GLOW-DVRF", "GLOW-A MSP-pop", "GLOW-A ASM-pop", "DDH-DVRF", "Icy-DVRF", "Icy-A", "Icy-N"];
    let mut ns: Vec<(usize, usize, usize)> = rows.iter().map(|r| (r.n, r.t, r.q)).collect();
    ns.sort();
    ns.dedup();
    let mut md = String::from("## Verification transaction, total gas (thousands), cheapest mode\n\n| n | t | S |");
    for s in schemes {
        write!(md, " {s} |").unwrap();
    }
    md.push_str("\n|---|---|---|");
    md.push_str(&"---:|".repeat(schemes.len()));
    md.push('\n');
    for &(n, t, q) in &ns {
        write!(md, "| {n} | {t} | {q} |").unwrap();
        for s in schemes {
            match best.get(&(s.to_string(), n)) {
                Some(r) => write!(md, " {:.1} ({}) |", r.total as f64 / 1e3, r.mode).unwrap(),
                None => md.push_str(" - |"),
            }
        }
        md.push('\n');
    }
    md.push_str("\n## All verification transactions\n\n| scheme | mode | n | calldata bytes | calldata gas | execution gas | total gas |\n|---|---|---:|---:|---:|---:|---:|\n");
    for r in rows.iter().filter(|r| r.kind == "verify") {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {}{} | {} |",
            r.scheme,
            r.mode,
            r.n,
            r.bytes,
            r.calldata_gas,
            r.exec,
            if r.floor { " (floor)" } else { "" },
            r.total
        )
        .unwrap();
    }
    md.push_str("\n## Deployment\n\n| scheme | n | total gas |\n|---|---:|---:|\n");
    for r in rows.iter().filter(|r| r.kind == "deploy") {
        writeln!(md, "| {} | {} | {} |", r.scheme, r.n, r.total).unwrap();
    }
    std::fs::write(out.join("gas.md"), &md).unwrap();
    print!("{md}");
}
