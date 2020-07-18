use std::io::Write;

use clap::{App, Arg};
use ton_client_rs::{Ed25519KeyPair, TonAddress, TonClient};

fn main() {
    let matches = App::new("tongen")
        .version("1.0")
        .setting(clap::AppSettings::AllowLeadingHyphen)
        .arg(
            Arg::with_name("ADDRESS")
                .help("Wallet address")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("METHOD")
                .help("Contract method")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::with_name("PARAMS")
                .help("Method params")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::with_name("ABI_PATH")
                .help("Path to ABI file")
                .required(true)
                .index(4),
        )
        .arg(
            Arg::with_name("KEYS_PATH")
                .help("Path to keys file")
                .required(true)
                .index(5),
        )
        .arg(
            Arg::with_name("output")
                .help("Output result to specified file")
                .short("o")
                .long("output")
                .value_name("FILE")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("base64")
                .help("Whether to output in base64 (raw by default)")
                .long("base64"),
        )
        .get_matches();

    if let Err(e) = run(matches) {
        eprintln!("[error] {}", e);
        std::process::exit(1);
    }
}

fn run(matches: clap::ArgMatches) -> Result<(), String> {
    let message = generate_message(
        matches.value_of("ADDRESS").unwrap(),
        matches.value_of("ABI_PATH").unwrap(),
        matches.value_of("METHOD").unwrap(),
        matches.value_of("PARAMS").unwrap(),
        matches.value_of("KEYS_PATH").unwrap(),
        30 * 60000,
    )?;

    let message = if matches.occurrences_of("base64") > 0 {
        base64::encode(message).into_bytes()
    } else {
        message
    };

    match matches.value_of("output") {
        Some(file) => {
            let mut file = std::fs::File::create(file)
                .map_err(|e| format!("failed to create output file: {}", e.to_string()))?;
            file.write_all(&message)
                .map_err(|e| format!("failed to write message to file: {}", e.to_string()))?;
        }
        None => {
            std::io::stdout().write_all(&message).unwrap();
        }
    }

    Ok(())
}

fn generate_message(
    address: &str,
    abi: &str,
    method: &str,
    params: &str,
    keys: &str,
    lifetime: u32,
) -> Result<Vec<u8>, String> {
    let ton = TonClient::default()
        .map_err(|e| format!("failed to create tonclient: {}", e.to_string()))?;

    let address = TonAddress::from_str(address)
        .map_err(|e| format!("failed to parse address: {}", e.to_string()))?;

    let abi = std::fs::read_to_string(abi)
        .map_err(|e| format!("failed to read abi: {}", e.to_string()))?;

    let expire_at = lifetime
        + std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

    let header = serde_json::json!({ "expire": expire_at });

    let keys = read_keys(&keys)?;

    let msg = ton
        .contracts
        .create_run_message(
            &address,
            abi.into(),
            method,
            Some(header.into()),
            params.into(),
            Some(&keys),
            None,
        )
        .map_err(|e| format!("failed to create inbound message: {}", e.to_string()))?;

    Ok(msg.message_body)
}

fn read_keys(filename: &str) -> Result<Ed25519KeyPair, String> {
    let keys_str = std::fs::read_to_string(filename)
        .map_err(|e| format!("failed to read keypair file: {}", e.to_string()))?;
    let keys = serde_json::from_str::<Ed25519KeyPair>(&keys_str)
        .map_err(|e| format!("failed to parse keypair file: {}", e.to_string()))?;
    Ok(keys)
}
