//! The Pignus vault's liquidation rule against `templates/pignus_vault/rules.json`.

use sequentia_contracts::vault::{self, Ratios};
use serde_json::Value;

fn n(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

fn small(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

#[test]
fn liquidation_rule_agrees_with_its_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../templates/pignus_vault/rules.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let list = |k: &str| v[k].as_array().unwrap().clone();
    for k in ["healthy", "max_seizure", "max_repay", "liquidation"] {
        assert!(!list(k).is_empty(), "{k}");
    }
    for e in list("healthy") {
        let got = vault::healthy(
            n(&e["collateral"]),
            n(&e["debt"]),
            n(&e["price"]),
            small(&e["precision"]) as u8,
            small(&e["liq_bp"]) as u32,
        )
        .unwrap();
        assert_eq!(got, e["healthy"].as_bool().unwrap(), "{}", e["name"]);
    }
    for e in list("max_seizure") {
        let got = vault::max_seizure(
            n(&e["repaid"]),
            n(&e["price"]),
            small(&e["precision"]) as u8,
            small(&e["bonus_bp"]) as u32,
        )
        .unwrap();
        assert_eq!(
            got.to_string(),
            e["max_seizure"].as_str().unwrap(),
            "{}",
            e["name"]
        );
    }
    for e in list("max_repay") {
        let got = vault::max_repay(
            n(&e["collateral"]),
            n(&e["debt"]),
            n(&e["price"]),
            small(&e["precision"]) as u8,
            small(&e["target_bp"]) as u32,
            small(&e["bonus_bp"]) as u32,
        )
        .unwrap();
        assert_eq!(
            got.to_string(),
            e["max_repay"].as_str().unwrap(),
            "{}",
            e["name"]
        );
    }
    for e in list("liquidation") {
        let got = vault::liquidation(
            n(&e["collateral"]),
            n(&e["debt"]),
            small(&e["last_time"]) as u32,
            small(&e["time"]) as u32,
            n(&e["price"]),
            Ratios {
                precision: small(&e["precision"]) as u8,
                liq_bp: small(&e["liq_bp"]) as u32,
                target_bp: small(&e["target_bp"]) as u32,
                bonus_bp: small(&e["bonus_bp"]) as u32,
            },
            n(&e["paid"]),
            n(&e["kept"]),
            e["matured"].as_bool().unwrap(),
        );
        match e.get("refused") {
            Some(why) => assert_eq!(got.unwrap_err(), why.as_str().unwrap(), "{}", e["name"]),
            None => {
                let l = got.unwrap_or_else(|why| panic!("{}: {why}", e["name"]));
                let r = &e["result"];
                assert_eq!(l.repaid, n(&r["repaid"]), "{}", e["name"]);
                assert_eq!(l.seized, n(&r["seized"]), "{}", e["name"]);
                assert_eq!(l.closes, r["closes"].as_bool().unwrap(), "{}", e["name"]);
                assert_eq!(l.debt_after, n(&r["debt_after"]), "{}", e["name"]);
                assert_eq!(
                    l.last_time_after as u64,
                    small(&r["last_time_after"]),
                    "{}",
                    e["name"]
                );
            }
        }
    }
}
