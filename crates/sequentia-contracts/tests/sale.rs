//! The capped sale's allocation tree and payment against
//! `templates/capped_sale/allocations.json`.

use sequentia_contracts::sale::{self, Entry};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn entries(v: &Value) -> Vec<Entry> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| Entry {
            key: unhex(x["key"].as_str().unwrap()).try_into().unwrap(),
            cap: x["cap"].as_str().unwrap().parse().unwrap(),
            bought: x["bought"].as_str().unwrap().parse().unwrap(),
        })
        .collect()
}

fn num(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn allocation_tree_and_payment_agree_with_their_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../templates/capped_sale/allocations.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(v["depth"].as_u64().unwrap() as usize, sale::DEPTH);
    let trees = v["trees"].as_array().unwrap();
    assert!(!trees.is_empty());
    for t in trees {
        let e = entries(&t["entries"]);
        assert_eq!(hex(&sale::root(&e).unwrap()), t["root"].as_str().unwrap());
        for p in t["proofs"].as_array().unwrap() {
            let i = p["index"].as_u64().unwrap() as usize;
            assert_eq!(
                hex(&sale::leaf(&e[i]).unwrap()),
                p["leaf"].as_str().unwrap()
            );
            let got = sale::proof(&e, i).unwrap();
            let want = p["proof"].as_array().unwrap();
            assert_eq!(got.len(), want.len());
            for (g, w) in got.iter().zip(want) {
                assert_eq!(hex(&g.0), w["sibling"].as_str().unwrap());
                assert_eq!(g.1, w["sibling_is_left"].as_bool().unwrap());
            }
        }
    }
    for p in v["payments"].as_array().unwrap() {
        let got = sale::payment(num(&p["amount"]), num(&p["num"]), num(&p["den"])).unwrap();
        assert_eq!(got.to_string(), p["payment"].as_str().unwrap());
    }
    let refusals = v["refusals"].as_array().unwrap();
    assert!(!refusals.is_empty());
    for r in refusals {
        let err = sale::root(&entries(&r["entries"])).unwrap_err();
        assert!(err.contains(r["reason"].as_str().unwrap()), "{err}");
    }
    for r in v["payment_refusals"].as_array().unwrap() {
        let err = sale::payment(num(&r["amount"]), num(&r["num"]), num(&r["den"])).unwrap_err();
        assert!(err.contains(r["reason"].as_str().unwrap()), "{err}");
    }
}
