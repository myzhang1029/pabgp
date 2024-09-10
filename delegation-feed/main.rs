mod arg;
mod rirstat;
mod session;

use clap::Parser;
use rirstat::{Database, DatabaseDiff};
use session::Feeder;
use tokio::sync::broadcast;

fn setup_logger(level: log::LevelFilter) {
    let config = simplelog::ConfigBuilder::new()
        .set_time_format_rfc3339()
        .build();
    simplelog::TermLogger::init(
        level,
        config,
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )
    .expect("Failed to initialize logger");
}

async fn handle_session(
    init_db: Database,
    recv_updates: broadcast::Receiver<DatabaseDiff>,
    socket: tokio::net::TcpStream,
    local_as: u32,
    local_id: std::net::Ipv4Addr,
    next_hop: std::net::IpAddr,
) {
    let (ipv4_routes, ipv6_routes) = init_db.into_prefixes();
    let init_ipv4_routes = Some(ipv4_routes.into_values().flatten().into());
    let init_ipv6_routes = Some(ipv6_routes.into_values().flatten().into());
    let mut session = Feeder::new(
        init_ipv4_routes,
        init_ipv6_routes,
        recv_updates,
        socket,
        local_as,
        local_id,
        next_hop,
    );
    if let Err(e) = session.idle().await {
        log::error!("Session error: {:?}", e);
    }
}

fn updater(
    mut init_db: Database,
    send_updates: &broadcast::Sender<DatabaseDiff>,
    update_interval: std::time::Duration,
) {
    loop {
        let diff = init_db.update_with_diff().unwrap_or_else(|e| {
            log::error!("Database update failed: {:?}", e);
            DatabaseDiff::default()
        });
        if send_updates.send(diff).is_err() {
            log::error!("Failed to send update to session");
            // `tokio` says the only way to fail is if all receivers are dropped,
            // which implies that the main loop has exited. We should exit too.
            break;
        }
        std::thread::sleep(update_interval);
    }
}

#[tokio::main]
async fn main() {
    let args = arg::DelegationFeed::parse();
    setup_logger(if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });
    let mut db = Database::new(args.countries.clone(), args.enable_ipv4, args.enable_ipv6);
    let local_as = args.local_as;
    let local_id = args.local_id;
    let next_hop = args.next_hop.unwrap_or_else(|| local_id.into());
    let update_interval = std::time::Duration::from_secs(args.update_interval * 60);
    let socket = tokio::net::TcpListener::bind((args.listen_addr, args.listen_port))
        .await
        .expect("Failed to bind to listen address");
    let (send_updates, mut recv_updates) = broadcast::channel(16);
    let updater_copy = dbg!(db.clone());
    tokio::task::spawn_blocking(move || {
        updater(updater_copy, &send_updates, update_interval);
    });
    loop {
        let sub_recv_updates = recv_updates.resubscribe();
        tokio::select! {
            Ok((socket, _)) = socket.accept() => {
                tokio::spawn(handle_session(db.clone(), sub_recv_updates, socket, local_as, local_id, next_hop));
            }
            diff = recv_updates.recv() => {
                if let Ok(diff) = diff {
                    diff.apply_to(&mut db);
                }
            }
        }
    }
}
