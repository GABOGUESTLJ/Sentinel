use crate::{
    event::{self, BuildContext, Origin},
    history, report,
    scan_files::Entries,
};
use notify::{
    Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher, event::EventKind,
};
use std::{
    io::{self, BufRead},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Options {
    pub interval: Duration,
    pub hardscan: bool,
    pub verbose: bool,
    pub silent: bool,
    pub history_policy: crate::retention::Policy,
    pub output: crate::presentation::Options,
}

enum Message {
    Command(String),
    Event(notify::Result<Event>),
}

fn commands(sender: SyncSender<Message>, output: crate::presentation::Options) {
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            match line {
                Ok(line) => {
                    if sender.send(Message::Command(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = output.diagnostic(
                        "fim",
                        "error",
                        &format!("Failed to read commands; monitoring continues: {error}"),
                    );
                    break;
                }
            }
        }
    });
}

fn watcher_callback(
    sender: SyncSender<Message>,
    overflow: Arc<AtomicBool>,
) -> impl FnMut(notify::Result<Event>) + Send + 'static {
    move |result| match sender.try_send(Message::Event(result)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => overflow.store(true, Ordering::Release),
        Err(TrySendError::Disconnected(_)) => {}
    }
}

fn start_watcher(
    root: &Path,
    options: &Options,
    sender: SyncSender<Message>,
    overflow: Arc<AtomicBool>,
) -> notify::Result<Box<dyn Watcher>> {
    let config = Config::default().with_follow_symlinks(false);
    if options.hardscan {
        // FIM itself hashes every regular file on every interval. Avoid a
        // second content hash inside PollWatcher.
        let mut watcher = PollWatcher::new(
            watcher_callback(sender, overflow),
            config.with_poll_interval(options.interval),
        )?;
        watcher.watch(root, RecursiveMode::Recursive)?;
        Ok(Box::new(watcher))
    } else {
        let mut watcher = RecommendedWatcher::new(watcher_callback(sender, overflow), config)?;
        watcher.watch(root, RecursiveMode::Recursive)?;
        Ok(Box::new(watcher))
    }
}

fn apply_command(
    line: &str,
    silent: &mut bool,
    output: &crate::presentation::Options,
) -> io::Result<()> {
    match line.trim() {
        "--silent" => {
            *silent = true;
            output.message(
                "fim",
                "status",
                "Output silenced. Enter -d or --desilent to enable it.",
                "Output silenced. Enter -d or --desilent to enable it.",
                &serde_json::json!({"silent":true}),
            )?;
        }
        "-d" | "--desilent" => {
            *silent = false;
            output.message(
                "fim",
                "status",
                "Output enabled.",
                "Output enabled.",
                &serde_json::json!({"silent":false}),
            )?;
        }
        "" => {}
        _ => output.diagnostic(
            "fim",
            "warning",
            "Unknown command. Enter --silent or -d/--desilent.",
        )?,
    }
    Ok(())
}

pub fn run(
    root: &Path,
    baseline_path: &Path,
    trusted: Entries,
    options: Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::sync_channel(256);
    let overflow = Arc::new(AtomicBool::new(false));
    let _watcher = start_watcher(root, &options, sender.clone(), Arc::clone(&overflow))?;
    let mut previous = crate::scan_files::scan(root)?;
    let mut history = history::Writer::open(root, options.history_policy)?;
    let mut sequence = 0;
    let mut pending_history =
        crate::history_queue::HistoryQueue::with_output(options.output.clone());
    let startup_events = {
        let mut context = BuildContext {
            root_hex: history.root_hex(),
            run_id: history.run_id(),
            next_sequence: &mut sequence,
            origin: Origin::Startup,
        };
        event::build(&trusted, &previous, &trusted, &mut context)
    };
    pending_history.record(&startup_events, |events| history.append(events))?;
    let mut silent = options.silent;
    if !silent {
        report::initial(
            &mut io::stdout().lock(),
            &options.output,
            root,
            baseline_path,
            history.path(),
            &previous,
            options.hardscan,
            options.verbose,
        )?;
        if startup_events.is_empty() && options.output.mode != crate::presentation::Mode::Legacy {
            report::events(
                &mut io::stdout().lock(),
                &options.output,
                &startup_events,
                options.verbose,
                None,
                false,
            )?;
        } else {
            report::live_events(
                &mut io::stdout().lock(),
                &options.output,
                &startup_events,
                options.verbose,
            )?;
        }
    }
    commands(sender, options.output.clone());
    let mut last_scan = Instant::now();
    let mut pending_event: Option<Instant> = None;
    let mut event_count = 0usize;
    loop {
        let now = Instant::now();
        let overflowed = overflow.swap(false, Ordering::AcqRel);
        let periodic_due = now.duration_since(last_scan) >= options.interval;
        let event_due = pending_event.is_some_and(|deadline| now >= deadline);
        if overflowed || periodic_due || event_due {
            if overflowed {
                options.output.diagnostic(
                    "fim",
                    "warning",
                    "Watcher event queue overflowed; reconciling the full tree",
                )?;
            }
            match crate::scan_files::scan(root) {
                Ok(current) => {
                    let audit_events = {
                        let mut context = BuildContext {
                            root_hex: history.root_hex(),
                            run_id: history.run_id(),
                            next_sequence: &mut sequence,
                            origin: Origin::Reconciliation,
                        };
                        event::build(&previous, &current, &trusted, &mut context)
                    };
                    pending_history.record(&audit_events, |events| history.append(events))?;
                    if !silent {
                        report::live_events(
                            &mut io::stdout().lock(),
                            &options.output,
                            &audit_events,
                            options.verbose,
                        )?;
                        if audit_events.is_empty() && event_count > 0 && !options.hardscan {
                            let message = format!(
                                "ACTIVITY {event_count} filesystem event(s); no state difference at reconciliation"
                            );
                            options.output.message(
                                "fim",
                                "activity",
                                &message,
                                &message,
                                &serde_json::json!({"filesystem_events":event_count,"changes":0}),
                            )?;
                        }
                    }
                    previous = current;
                }
                Err(error) => options.output.diagnostic(
                    "fim",
                    "error",
                    &format!("Incomplete scan; keeping the previous state: {error}"),
                )?,
            }
            // Every mode gets another complete FIM scan after the interval,
            // including when the last scan failed and PollWatcher goes quiet.
            last_scan = Instant::now();
            pending_event = None;
            event_count = 0;
            continue;
        }

        let mut timeout = Duration::from_millis(200).min(
            options
                .interval
                .saturating_sub(now.duration_since(last_scan)),
        );
        if let Some(deadline) = pending_event {
            timeout = timeout.min(deadline.saturating_duration_since(now));
        }
        match receiver.recv_timeout(timeout) {
            Ok(Message::Command(line)) => apply_command(&line, &mut silent, &options.output)?,
            Ok(Message::Event(Ok(event))) => {
                let needs_rescan = event.need_rescan();
                // Reading files for reconciliation can itself produce access events.
                if matches!(event.kind, EventKind::Access(_)) && !needs_rescan {
                    continue;
                }
                event_count = event_count.saturating_add(1);
                let delay = if needs_rescan {
                    Duration::ZERO
                } else {
                    Duration::from_millis(150)
                };
                let deadline = Instant::now() + delay;
                pending_event = Some(pending_event.map_or(deadline, |old| old.min(deadline)));
            }
            Ok(Message::Event(Err(error))) => {
                options.output.diagnostic(
                    "fim",
                    "error",
                    &format!("Watcher error; reconciling: {error}"),
                )?;
                pending_event = Some(Instant::now());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("Watcher and command input disconnected".into());
            }
        }
    }
}
