//! Milestone 4, first step: Alpine Linux's own userland, unmodified, in a
//! cell. The cell's root is Alpine's minirootfs (read off its own disk,
//! with a copy-on-write upper layer). `/bin/busybox` there is a dynamically
//! linked PIE, so every run goes through `ld-musl` (`PT_INTERP`), and the
//! shell's children are exec'd the same way.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use frame::task::TaskOptions;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

const CELL_PAGES: u64 = 8192;

/// `(argv, expected exit code)`. argv[0] selects the busybox applet.
const RUNS: &[(&[&str], i32)] = &[
    (&["cat", "/etc/alpine-release"], 0),
    (
        &[
            "sh",
            "-c",
            "apk add --no-network /mirror/tree-2.1.1-r0.apk /mirror/oniguruma-6.9.9-r0.apk \
             /mirror/jq-1.7.1-r0.apk && apk info -e tree jq oniguruma >/dev/null && \
             tree /etc/apk >/dev/null && [ \"$(echo '{\"a\":[1,2,3]}' | jq '.a|add')\" = 6 ] && \
             echo alpine: apk installed tree and jq from the local mirror",
        ],
        0,
    ),
    (&["sh", "-c", "echo alpine sh: $((2+3))"], 0),
    (
        &[
            "sh",
            "-c",
            "set -e; [ \"$(readlink /proc/self/exe)\" = /bin/busybox ]; \
             [ \"$(cat /proc/self/comm)\" = cat ]; \
             sleep 5 & s=$!; grep -q sleep /proc/$s/cmdline; ps | grep -q '[s]leep 5'; kill $s; \
             [ \"$(echo x | cat /dev/stdin)\" = x ]; [ \"$(echo y >/dev/stdout)\" = y ]; \
             (cd /proc && grep -q ^Tgid self/status); ls /dev/fd/ | grep -q 2; \
             head -1 /proc/meminfo | grep -q MemTotal && ls /proc/self | grep -q maps && echo alpine: /proc works",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "grep -h ^NAME /etc/os-release | cut -d= -f2 | tr -d '\"'",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "/bin/true && echo alpine: fork, exec via ld-musl, wait ok",
        ],
        0,
    ),
    (
        &["sh", "-c", "echo hi > /tmp/f && cat /tmp/f && rm /tmp/f"],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "{ echo out1; echo err >&2; echo out2; } >/tmp/o 2>&1; \
             [ \"$(wc -l < /tmp/o)\" = 3 ] && [ \"$(sed -n 2p /tmp/o)\" = err ] && \
             echo 'alpine: 2>&1 shares one offset'",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "rm -f /tmp/ap; (for i in $(seq 200); do echo aaaaaaaa; done >>/tmp/ap) & \
             (for i in $(seq 200); do echo bbbbbbbb; done >>/tmp/ap) & wait; \
             [ \"$(wc -l < /tmp/ap)\" = 400 ] && [ \"$(grep -c a /tmp/ap)\" = 200 ] && \
             echo alpine: two appenders kept every line",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "touch /tmp/l; flock -x /tmp/l -c 'flock -n -x /tmp/l -c true'; [ $? = 1 ] && \
             flock -n /tmp/l -c true && echo alpine: flock excludes, then releases",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "rm -f /tmp/pg /tmp/ids; \
             setsid sh -c 'read l </proc/self/stat; echo $l | cut -d\" \" -f1,5,6 >/tmp/ids; \
             sleep 30 & sleep 30 & echo $$ >/tmp/pg; wait' & \
             while [ ! -s /tmp/pg ]; do sleep 0.05; done; \
             kill -s TERM -$(cat /tmp/pg); wait; \
             set -- $(cat /tmp/ids); [ \"$1\" = \"$2\" ] && [ \"$2\" = \"$3\" ] && \
             echo alpine: kill -pgid ended the whole group",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "ulimit -n 64 && [ \"$(ulimit -n)\" = 64 ] && ulimit -s 512 && \
             [ \"$(sh -c 'ulimit -s')\" = 512 ] && ! ulimit -n 4096 2>/dev/null && \
             echo alpine: ulimit survives fork and exec",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(awk '/^MemTotal/ {print $2}' /proc/meminfo)\" = 32768 ] && \
             read a b c d e </proc/loadavg && [ \"${d#*/}\" -ge 1 ] && [ \"$e\" -gt 1 ] && \
             [ \"$(awk '/^VmSize/ {print ($2 > 0)}' /proc/self/status)\" = 1 ] && \
             echo alpine: /proc shows cell memory and threads",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(date +%s)\" -gt 1700000000 ] && touch /tmp/t &&              [ \"$(stat -c %Y /tmp/t)\" -gt 1700000000 ] &&              [ \"$(head -c 16 /dev/urandom | od -An -tx1)\" != \"$(head -c 16 /dev/urandom | od -An -tx1)\" ] &&              echo alpine: wall clock, file times and urandom are real",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "cd /tmp && echo one >a && ln a b && [ \"$(stat -c %h a)\" = 2 ] &&              [ \"$(stat -c %i a)\" = \"$(stat -c %i b)\" ] && rm a && [ \"$(cat b)\" = one ] &&              [ \"$(stat -c %h b)\" = 1 ] && mkdir -p d/e d/f && [ \"$(stat -c %h d)\" = 4 ] &&              dd if=/dev/zero of=big bs=1M count=0 seek=100 2>/dev/null &&              [ \"$(stat -c %s big)\" = 104857600 ] && echo x >>big && rm big b && rm -r d &&              echo alpine: hard links, directory link counts, sparse 100 MiB file",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(stat -c %U:%G /etc/shadow)\" = root:shadow ] &&              [ \"$(stat -c %Y /etc/alpine-release)\" -gt 1700000000 ] &&              echo alpine: the image carries owners and times",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "adduser -D -u 1000 bob && adduser -D -u 1001 carol && [ \"$(su bob -c 'id -u; id -g')\" = \"$(printf '1000\n1000')\" ] &&              ! su bob -c 'cat /etc/shadow' 2>/dev/null &&              ! su bob -c 'touch /root/x' 2>/dev/null &&              su bob -c 'echo hi > ~/f' && [ \"$(stat -c %U ~bob/f)\" = bob ] &&              su bob -c 'touch /tmp/b' && ! su carol -c 'rm /tmp/b' 2>/dev/null && [ -e /tmp/b ] &&              su bob -c 'chmod 600 ~/f' && ! su carol -c 'cat ~bob/f' 2>/dev/null &&              { sleep 30 & sp=$!; ! su bob -c \"kill $sp\" 2>/dev/null; kill $sp; wait $sp; true; } &&              echo alpine: users and permissions are enforced",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(free | awk '/^Mem:/ {print $2}')\" = 32768 ] && uptime | grep -q load && \
             echo alpine: sysinfo shows the cell",
        ],
        0,
    ),
];

/// Installs milestone 5's servers from the local mirror.
const NET_INSTALL: &str = "apk add --no-network /mirror/pcre-8.45-r3.apk \
     /mirror/nginx-1.26.3-r0.apk /mirror/redis-7.2.9-r0.apk >/dev/null && \
     mkdir -p /srv/www && echo 'hello from nginx in an Ichor cell' >/srv/www/index.html && \
     printf 'server {\\n listen 80 default_server;\\n root /srv/www;\\n location / { try_files $uri $uri/ =404; }\\n}\\n' \
       >/etc/nginx/http.d/default.conf && nginx -t 2>/dev/null && \
     echo alpine: nginx and redis installed from the local mirror";

/// The server cell: nginx and redis until the client cell is done (and,
/// with `$1` = 1, until the host has fetched a page through the published
/// port), then a clean shutdown of both.
const NET_SERVER: &str = "nginx -g 'daemon off; error_log /tmp/nginx-notice.log notice;' & n=$!; \
     redis-server --port 6379 --save '' --appendonly no --protected-mode no >/tmp/redis.log 2>&1 & r=$!; \
     while [ ! -e /tmp/ichor-net-done ]; do sleep 0.1; done; \
     if [ \"$1\" = 1 ]; then \
       i=0; until grep -q '^10.0.2.2 ' /var/log/nginx/access.log 2>/dev/null; do \
         i=$((i+1)); [ $i -gt 1200 ] && { echo alpine: the host never fetched; \
           tail -5 /var/log/nginx/access.log; tail -20 /var/log/nginx/error.log; kill $n $r; wait; exit 1; }; sleep 0.1; done; \
       echo alpine: nginx served the host through the published port; fi; \
     kill $n $r; wait $n; a=$?; wait $r; b=$?; \
     [ $a = 0 ] || [ $a = 143 ]; [ $b = 0 ] || [ $b = 143 ] || { cat /tmp/redis.log; exit 1; }; \
     w=$(grep -c 'start worker process' /tmp/nginx-notice.log); \
     [ \"$w\" -ge 1 ] && grep -q 'exit$' /tmp/nginx-notice.log || { cat /tmp/nginx-notice.log; exit 1; }; \
     echo \"alpine: nginx's master ran $w workers over AF_UNIX channels and stopped them\"; \
     echo alpine: nginx and redis stopped";

/// The client cell: `$1` is the server cell's address.
const NET_CLIENT: &str = "trap 'touch /tmp/ichor-net-done' EXIT; s=$1; \
     i=0; until wget -qO /tmp/page http://$s/ 2>/dev/null; do \
       i=$((i+1)); [ $i -gt 600 ] && { echo alpine: nginx never answered; exit 1; }; sleep 0.1; done; \
     grep -q 'hello from nginx in an Ichor cell' /tmp/page || { echo alpine: wrong page; exit 1; }; \
     for k in 1 2 3 4 5; do wget -qO /tmp/page http://$s/ 2>/dev/null && \
       grep -q 'hello from nginx' /tmp/page || { echo alpine: request $k after the first failed; exit 1; }; done; \
     wget -q -O /dev/null http://$s/missing 2>/dev/null && { echo alpine: no 404; exit 1; }; \
     i=0; until [ \"$(redis-cli -h $s ping 2>/dev/null)\" = PONG ]; do \
       i=$((i+1)); [ $i -gt 600 ] && { echo alpine: redis never answered; exit 1; }; sleep 0.1; done; \
     redis-cli -h $s set greeting hello >/dev/null && [ \"$(redis-cli -h $s get greeting)\" = hello ] && \
     [ \"$(redis-cli -h $s incrby n 41)\" = 41 ] && [ \"$(redis-cli -h $s incr n)\" = 42 ] && \
     [ \"$(redis-cli -h $s rpush l a b c)\" = 3 ] && [ \"$(redis-cli -h $s lrange l 0 -1 | tr '\\n' ,)\" = a,b,c, ] || \
       { echo alpine: redis commands failed; exit 1; }; \
     redis-benchmark -h $s -q -n 1000 -c 4 -t set,get 2>&1 | tr '\\r' '\\n' | grep 'requests per second' | \
       sed 's/^/alpine: redis-benchmark: /'; \
     echo \"alpine: nginx served six pages and redis answered from cell $s\"";

fn read(vfs: &Vfs, path: &str) -> Vec<u8> {
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(ROOT, path, true)
        .unwrap_or_else(|_| fail("alpine: missing file"));
    let size = fs.stat(ino).map(|s| s.size).unwrap_or(0) as usize;
    let mut v = alloc::vec![0u8; size];
    let n = fs.read(ino, 0, &mut v).unwrap_or(0);
    v.truncate(n);
    v
}

pub(crate) fn run(vfs: &Arc<Vfs>) {
    let release = read(vfs, "/etc/alpine-release");
    println!(
        "ichor: alpine: root disk holds Alpine {}",
        String::from_utf8_lossy(&release).trim()
    );
    let busybox = read(vfs, "/bin/busybox");
    let interp_path = match loader::interp_path(&crate::file::Bytes(&busybox)) {
        Ok(Some(p)) => p,
        _ => fail("alpine: /bin/busybox is not dynamically linked"),
    };
    let interp = read(vfs, &interp_path);
    println!(
        "ichor: alpine: /bin/busybox is dynamic, interpreter {interp_path} ({} KiB)",
        interp.len() / 1024
    );
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("no system cell"));
    for (argv, want) in RUNS {
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no alpine cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let (code, syscalls) = run_linux(p, &busybox, Some(&interp), argv);
        if code != *want {
            println!("ichor: alpine: {argv:?} exited {code}, expected {want}");
            fail("alpine applet");
        }
        println!("ichor: alpine: {} ok ({syscalls} syscalls)", argv[0]);
    }
    servers(vfs, &busybox, &interp);
    println!("ichor: alpine: all runs passed");
}

/// Milestone 5: nginx and redis serve traffic from a cell to another cell
/// through the cell switch, and nginx to the host through a published port
/// when the harness forwards one (`net_publish`).
fn servers(vfs: &Arc<Vfs>, busybox: &[u8], interp: &[u8]) {
    const SERVER_PAGES: u64 = 32768;
    let system = System::new(SERVER_PAGES * 3).unwrap_or_else(|| fail("no system cell"));
    let new_cell =
        || Cell::new(&system.root_account, SERVER_PAGES).unwrap_or_else(|| fail("no server cell"));
    let sh = |cell: Arc<Cell>, args: &[&str]| -> i32 {
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let mut argv: Vec<&str> = alloc::vec!["sh", "-c"];
        argv.extend_from_slice(args);
        run_linux(p, busybox, Some(interp), &argv).0
    };
    if sh(new_cell(), &[NET_INSTALL]) != 0 {
        fail("alpine: installing nginx and redis");
    }
    let (server, client) = (new_cell(), new_cell());
    let server_id = server.id();
    let Some(addr) = crate::netstack::stack_for(&server).addr() else {
        fail("alpine: the server cell has no address");
    };
    let publish = crate::nettest::publish_port();
    let published = publish != 0
        && crate::switch::has_uplink()
        && crate::switch::publish(net::wire::PROTO_TCP, publish, server.id(), 80);
    let done = Arc::new(SpinLock::new(None));
    {
        let (vfs, busybox, interp, slot) =
            (vfs.clone(), busybox.to_vec(), interp.to_vec(), done.clone());
        let flag = if published { "1" } else { "0" };
        TaskOptions::new(move || {
            let p = LinuxProcess::new(server, vfs).unwrap_or_else(|| fail("no process"));
            let code = run_linux(
                p,
                &busybox,
                Some(&interp),
                &["sh", "-c", NET_SERVER, "sh", flag],
            )
            .0;
            *slot.lock() = Some(code);
        })
        .spawn()
        .unwrap_or_else(|| fail("alpine: no task for the server cell"));
    }
    let a = alloc::format!("{addr}");
    if sh(client, &[NET_CLIENT, "sh", &a]) != 0 {
        fail("alpine: the client cell");
    }
    let diag = || {
        let s = crate::switch::stats(server_id);
        let u = crate::switch::uplink_stats();
        println!(
            "ichor: alpine: server cell switch stats (sent, received, dropped) {s:?}; uplink {u:?}"
        );
    };
    // The script bounds its own waits; this only catches a hang.
    let deadline = frame::time::now() + Duration::from_secs(600);
    let code = loop {
        if let Some(c) = *done.lock() {
            break c;
        }
        if frame::time::now() > deadline {
            diag();
            fail("alpine: the server cell never stopped");
        }
        frame::task::yield_now();
    };
    if published {
        crate::switch::unpublish(net::wire::PROTO_TCP, publish);
    }
    if code != 0 {
        diag();
        fail("alpine: the server cell");
    }
}
