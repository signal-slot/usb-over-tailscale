//! `tsnode`: a small userspace Tailscale node for constrained `std` targets.
//!
//! Layers, bottom up:
//! - [`crypto`], [`noise`], [`keys`]: primitives.
//! - [`controlbase`], [`hpack`]/[`h2`], [`control`]: the ts2021 control-plane client.
//! - [`wireguard`], [`disco`], [`derp`], [`stun`], [`magicsock`]: the data plane.
//! - [`netstack`]: smoltcp-based TCP termination on the node's tailnet addresses.
//! - [`node`]: glue that runs everything on plain threads.

pub mod control;
pub mod controlbase;
pub mod crypto;
pub mod derp;
pub mod disco;
pub mod filter;
pub mod h2;
pub mod http1;
pub mod keys;
pub mod magicsock;
pub mod net;
pub mod netstack;
pub mod node;
pub mod noise;
pub mod stun;
pub mod types;
pub mod wireguard;
