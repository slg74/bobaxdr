use std::collections::HashMap;
use std::env;
use std::process;
use std::time::Duration;

use serde_json::Value;

// ANSI
const BOLD:   &str = "\x1b[1m";
const DIM:    &str = "\x1b[2m";
const GREEN:  &str = "\x1b[32m";
const RED:    &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN:   &str = "\x1b[36m";
const RESET:  &str = "\x1b[0m";

const POLLER_PLATFORMS: &[&str] = &["aws", "docker", "kubernetes", "sensor"];

fn get(client: &reqwest::blocking::Client, base: &str, key: &str, path: &str) -> Vec<Value> {
    let url = format!("{}{}", base, path);
    client
        .get(&url)
        .header("x-api-key", key)
        .send()
        .ok()
        .and_then(|r| if r.status().is_success() { r.json().ok() } else { None })
        .and_then(|v: Value| v.as_array().cloned())
        .unwrap_or_default()
}

fn sev_rank(s: &str) -> u8 {
    match s { "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0 }
}

fn sev_color(s: &str) -> &'static str {
    match s { "critical" | "high" => RED, "medium" => YELLOW, _ => CYAN }
}

fn clear()   -> String { format!("{}✓ clear{}", GREEN, RESET) }
fn offline() -> String { format!("{}✗ offline{}", DIM, RESET) }

fn alert_status(n: usize, max_sev: &str) -> String {
    format!("{}! {} alert{}{}", sev_color(max_sev), n, if n != 1 { "s" } else { "" }, RESET)
}

fn max_severity<'a>(alerts: &'a [Value]) -> &'a str {
    alerts
        .iter()
        .map(|a| a["severity"].as_str().unwrap_or("low"))
        .max_by_key(|s| sev_rank(s))
        .unwrap_or("low")
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}…", &s[..n - 1]) } else { s.to_string() }
}

fn rule(width: usize) { println!("  {}", "─".repeat(width)); }

fn main() {
    let server = env::var("BOBAXDR_SERVER")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    let key = env::var("BOBAXDR_API_KEY").unwrap_or_else(|_| {
        let home = env::var("HOME").unwrap_or_default();
        std::fs::read_to_string(".api_key")
            .or_else(|_| std::fs::read_to_string(format!("{}/.api_key", home)))
            .or_else(|_| std::fs::read_to_string(format!("{}/bobaxdr/.api_key", home)))
            .unwrap_or_default()
            .trim()
            .to_string()
    });

    if key.is_empty() {
        eprintln!("error: set BOBAXDR_API_KEY or place .api_key in current directory");
        process::exit(1);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let endpoints = get(&client, &server, &key, "/api/endpoints");
    let alerts    = get(&client, &server, &key, "/api/alerts?acknowledged=false&limit=500");
    let instances = get(&client, &server, &key, "/api/cloud/instances");
    let pods      = get(&client, &server, &key, "/api/k8s/pods");

    // alert map: hostname -> alerts
    let mut alert_map: HashMap<String, Vec<Value>> = HashMap::new();
    for a in &alerts {
        let h = a["endpoint_hostname"].as_str().unwrap_or("").to_string();
        alert_map.entry(h).or_default().push(a.clone());
    }

    println!("\n{BOLD}{CYAN}sls — BobaxDR Security Status{RESET}  {DIM}{server}{RESET}\n");

    // ── Endpoints ─────────────────────────────────────────────────────────────
    let agents: Vec<&Value> = endpoints.iter()
        .filter(|e| !POLLER_PLATFORMS.contains(&e["platform"].as_str().unwrap_or("")))
        .collect();

    println!("{BOLD}{CYAN}ENDPOINTS{RESET}");
    println!("  {:<26} {:<10} {:<18} {}", "NAME", "PLATFORM", "IP", "STATUS");
    rule(68);

    for ep in &agents {
        let name     = ep["hostname"].as_str().unwrap_or("?");
        let platform = ep["platform"].as_str().unwrap_or("?");
        let ip       = ep["ip_address"].as_str().unwrap_or("?");
        let online   = ep["online"].as_bool().unwrap_or(false);
        let ep_alerts = alert_map.get(name).map_or(&[][..], |v| v.as_slice());

        let status = if !online {
            offline()
        } else if ep_alerts.is_empty() {
            clear()
        } else {
            alert_status(ep_alerts.len(), max_severity(ep_alerts))
        };

        println!("  {:<26} {:<10} {:<18} {}", truncate(name, 25), platform, ip, status);
    }

    // ── AWS ───────────────────────────────────────────────────────────────────
    if !instances.is_empty() {
        println!("\n{BOLD}{CYAN}AWS{RESET}");
        println!("  {:<22} {:<12} {:<12} {:<16} {}", "INSTANCE", "TYPE", "STATE", "IP", "STATUS");
        rule(72);

        for inst in &instances {
            let id     = inst["instance_id"].as_str().unwrap_or("?");
            let itype  = inst["instance_type"].as_str().unwrap_or("?");
            let state  = inst["state"].as_str().unwrap_or("?");
            let ip     = inst["public_ip"].as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| inst["private_ip"].as_str())
                .unwrap_or("—");
            let sg_issues = inst["sg_issues"].as_array().map_or(0, |v| v.len());

            let status = if sg_issues == 0 {
                clear()
            } else {
                format!("{}! {} sg issue{}{}", YELLOW, sg_issues,
                    if sg_issues != 1 { "s" } else { "" }, RESET)
            };

            println!("  {:<22} {:<12} {:<12} {:<16} {}", truncate(id, 21), itype, state, ip, status);
        }
    }

    // ── Kubernetes ────────────────────────────────────────────────────────────
    if !pods.is_empty() {
        let context = endpoints.iter()
            .find(|e| e["platform"].as_str().unwrap_or("") == "kubernetes")
            .and_then(|e| e["hostname"].as_str())
            .unwrap_or("kubernetes");

        // show user pods + any pod with issues or non-Running phase
        let visible: Vec<&Value> = pods.iter()
            .filter(|p| {
                let system     = p["system"].as_bool().unwrap_or(false);
                let has_issues = p["issues"].as_array().map_or(false, |v| !v.is_empty());
                let phase      = p["phase"].as_str().unwrap_or("Unknown");
                !system || has_issues || phase != "Running"
            })
            .collect();

        println!("\n{BOLD}{CYAN}KUBERNETES{RESET}  ({context})");
        println!("  {:<30} {:<16} {:<12} {}", "POD", "NAMESPACE", "PHASE", "STATUS");
        rule(74);

        if visible.is_empty() {
            println!("  {}✓ all pods running, no issues{}", GREEN, RESET);
        } else {
            for pod in &visible {
                let name     = pod["name"].as_str().unwrap_or("?");
                let ns       = pod["namespace"].as_str().unwrap_or("?");
                let phase    = pod["phase"].as_str().unwrap_or("?");
                let restarts = pod["restarts"].as_u64().unwrap_or(0);
                let issues   = pod["issues"].as_array().map_or(0, |v| v.len());

                let status = if phase == "CrashLoopBackOff" {
                    format!("{}✗ crashloop ({}r){}", RED, restarts, RESET)
                } else if issues > 0 {
                    let max_sev = pod["issues"].as_array().unwrap()
                        .iter()
                        .map(|i| i["severity"].as_str().unwrap_or("low"))
                        .max_by_key(|s| sev_rank(s))
                        .unwrap_or("low");
                    alert_status(issues, max_sev)
                } else if restarts > 5 {
                    format!("{}⚠ {} restarts{}", YELLOW, restarts, RESET)
                } else {
                    clear()
                };

                println!("  {:<30} {:<16} {:<12} {}",
                    truncate(name, 29), ns, phase, status);
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    let n = alerts.len();
    let summary = if n == 0 {
        format!("{}0 active alerts{}", GREEN, RESET)
    } else {
        format!("{}{} active alert{}{}", RED, n, if n != 1 { "s" } else { "" }, RESET)
    };
    println!("\n  {summary}\n");
}
