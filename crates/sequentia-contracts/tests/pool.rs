//! The pool split table hash and payouts against `templates/pool_split/tables.json`.

use sequentia_contracts::pool;
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn table_hash_and_payouts_agree_with_their_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../templates/pool_split/tables.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    let payouts = v["payouts"].as_array().unwrap();
    assert!(!entries.is_empty() && !payouts.is_empty());
    for e in entries {
        let rows: Vec<(Vec<u8>, u32)> = e["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    unhex(r["script"].as_str().unwrap()),
                    r["numerator"].as_u64().unwrap() as u32,
                )
            })
            .collect();
        let got = sequentia_contracts::hex(&pool::table_hash(&rows));
        assert_eq!(got, e["table"].as_str().unwrap(), "{}", e["name"]);
    }
    for p in payouts {
        let nums: Vec<u32> = p["numerators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u32)
            .collect();
        let got = pool::payouts(
            &nums,
            p["denom"].as_u64().unwrap() as u32,
            p["withhold_cap_bp"].as_u64().unwrap() as u16,
            p["collected"].as_str().unwrap().parse().unwrap(),
            p["withheld"].as_str().unwrap().parse().unwrap(),
        );
        match p.get("refused") {
            Some(why) => {
                let e = got.expect_err(p["name"].as_str().unwrap());
                assert!(e.contains(why.as_str().unwrap()), "{}: {e}", p["name"]);
            }
            None => {
                let want: Vec<String> = p["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect();
                let got: Vec<String> = got.unwrap().iter().map(u64::to_string).collect();
                assert_eq!(got, want, "{}", p["name"]);
            }
        }
    }
}
