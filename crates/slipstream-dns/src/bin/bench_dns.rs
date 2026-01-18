use slipstream_dns::{
    build_qname_with_limit, decode_query, decode_response, encode_query, encode_response,
    max_payload_len_for_domain_with_limit, QueryParams, Question, ResponseParams, CLASS_IN, RR_TXT,
};
use std::env;
use std::time::Instant;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

fn main() {
    init_logging();
    let mut iterations = 10_000usize;
    let mut payload_len = 256usize;
    let mut domain = "test.com".to_string();
    let mut max_qname_len = 253usize;

    for arg in env::args().skip(1) {
        if let Some(value) = arg.strip_prefix("--iterations=") {
            iterations = value.parse().unwrap_or(iterations);
        } else if let Some(value) = arg.strip_prefix("--payload-len=") {
            payload_len = value.parse().unwrap_or(payload_len);
        } else if let Some(value) = arg.strip_prefix("--domain=") {
            domain = value.to_string();
        } else if let Some(value) = arg.strip_prefix("--max-qname-len=") {
            match value.parse::<usize>() {
                Ok(value) if (1..=253).contains(&value) => max_qname_len = value,
                Ok(_) => {
                    error!("Max QNAME length must be between 1 and 253.");
                    std::process::exit(1);
                }
                Err(_) => {
                    error!("Max QNAME length must be a positive integer.");
                    std::process::exit(1);
                }
            }
        } else if arg == "--help" {
            print_usage();
            return;
        }
    }

    let max_payload = match max_payload_len_for_domain_with_limit(&domain, max_qname_len) {
        Ok(limit) => limit,
        Err(err) => {
            error!("Invalid domain: {}", err);
            std::process::exit(1);
        }
    };
    if max_payload == 0 {
        error!("Domain leaves no room for payload labels.");
        std::process::exit(1);
    }
    if payload_len > max_payload {
        warn!(
            "Payload length {} exceeds max {} for domain {}; clamping.",
            payload_len, max_payload, domain
        );
        payload_len = max_payload;
    }

    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();
    let qname = match build_qname_with_limit(&payload, &domain, max_qname_len) {
        Ok(name) => name,
        Err(err) => {
            error!("Failed to build qname: {}", err);
            std::process::exit(1);
        }
    };
    let query_params = QueryParams {
        id: 0x1234,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    };
    let query = encode_query(&query_params).expect("encode query");

    let question = Question {
        name: qname.clone(),
        qtype: RR_TXT,
        qclass: CLASS_IN,
    };
    let response_params = ResponseParams {
        id: 0x1234,
        rd: true,
        cd: false,
        question: &question,
        payload: Some(&payload),
        rcode: None,
    };
    let response = encode_response(&response_params).expect("encode response");

    bench("build_qname", iterations, payload_len, || {
        let _ = build_qname_with_limit(&payload, &domain, max_qname_len).expect("build qname");
    });
    bench("encode_query", iterations, query.len(), || {
        let _ = encode_query(&query_params).expect("encode query");
    });
    bench("decode_query", iterations, query.len(), || {
        let _ = decode_query(&query, &domain).expect("decode query");
    });
    bench("encode_response", iterations, response.len(), || {
        let _ = encode_response(&response_params).expect("encode response");
    });
    bench("decode_response", iterations, response.len(), || {
        let _ = decode_response(&response).expect("decode response");
    });
}

fn bench(label: &str, iterations: usize, bytes_per_iter: usize, mut f: impl FnMut()) {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let per_iter = secs / iterations.max(1) as f64;
    if bytes_per_iter > 0 {
        let total_bytes = bytes_per_iter as f64 * iterations as f64;
        let mib_s = total_bytes / (1024.0 * 1024.0) / secs.max(1e-9);
        println!(
            "{label}: {secs:.3}s total, {per_iter:.3}us/iter, {mib_s:.2} MiB/s",
            per_iter = per_iter * 1_000_000.0
        );
    } else {
        println!(
            "{label}: {secs:.3}s total, {per_iter:.3}us/iter",
            per_iter = per_iter * 1_000_000.0
        );
    }
}

fn print_usage() {
    println!(
        "Usage: bench_dns [--iterations=N] [--payload-len=N] [--domain=NAME] [--max-qname-len=N]"
    );
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
