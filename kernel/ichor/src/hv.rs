//! The connection to a Hyper-V host, made when the first driver asks.

use alloc::sync::Arc;

use frame::println;
use frame::sync::Mutex;
use hyperv::Bus;

/// `None`: not asked for yet.
static BUS: Mutex<Option<Option<Arc<Bus>>>> = Mutex::new(None);

/// The host's devices; `None` on other machines.
pub(crate) fn bus() -> Option<Arc<Bus>> {
    let mut bus = BUS.lock();
    bus.get_or_insert_with(|| match hyperv::connect()? {
        Ok(b) => Some(b),
        Err(e) => {
            println!("ichor: vmbus: {e:?}");
            None
        }
    })
    .clone()
}
