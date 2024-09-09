mod bgp;
mod cidr;
mod rirstat;

use rirstat::Database;

fn setup_logger() {
    let config = simplelog::ConfigBuilder::new()
        .set_time_format_rfc3339()
        .build();
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        config,
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )
    .expect("Failed to initialize logger");
}

fn main() {
    setup_logger();
    let country = "apnic:CN".parse().unwrap();
    let mut db = Database::new(vec![country]);
    db.update_all().unwrap();
    println!("{:?}", db.get_cidr6(country));
    db.update_all().unwrap();
}
