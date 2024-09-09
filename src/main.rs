mod arg;
mod bgp;
mod cidr;
mod rirstat;
mod session;

use clap::Parser;
use rirstat::{Database, DatabaseDiff};
use session::Feeder;
use tokio::sync::{broadcast, oneshot};

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

async fn handle_session(
    initial_db: Database,
    recv_updates: broadcast::Receiver<DatabaseDiff>,
    socket: tokio::net::TcpStream,
    local_as: u32,
    local_id: std::net::Ipv4Addr,
    next_hop: std::net::IpAddr,
) {
    let mut session = Feeder::new(
        initial_db,
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
    mut updater_task_should_exit_rx: oneshot::Receiver<()>,
    update_interval: std::time::Duration,
) {
    loop {
        match updater_task_should_exit_rx.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                break;
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }
        let diff = init_db.update_with_diff().expect("TODO: handle error");
        send_updates.send(diff).expect("TODO: handle error");
        std::thread::sleep(update_interval);
    }
}

#[tokio::main]
async fn main() {
    setup_logger();
    let args = arg::DelegationFeed::parse();
    let mut db = Database::new(args.countries.clone());
    let local_as = args.local_as;
    let local_id = args.local_id;
    let next_hop = args.next_hop.unwrap_or_else(|| local_id.into());
    let update_interval = std::time::Duration::from_secs(args.update_interval * 60);
    db.update_all().expect("Initial database update failed");
    let socket = tokio::net::TcpListener::bind((args.listen_addr, args.listen_port))
        .await
        .expect("Failed to bind to listen address");
    let (send_updates, mut recv_updates) = broadcast::channel(16);
    let (updater_task_should_exit_tx, updater_task_should_exit_rx) = oneshot::channel::<()>();
    let updater_copy = db.clone();
    tokio::task::spawn_blocking(move || {
        updater(
            updater_copy,
            &send_updates,
            updater_task_should_exit_rx,
            update_interval,
        );
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
