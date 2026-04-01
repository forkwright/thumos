#![no_std]
//! Input drivers for the AGM M7: GPIO keypad matrix scan, mtk-tpd touchscreen, event queue.

// WHY: The test harness links std, but no_std crates must opt in
// explicitly at the crate root so that std macros (vec!, format!, etc.)
// are available in all test modules.
#[cfg(test)]
extern crate std;

pub mod gpio;
pub mod input;
pub mod touch;
