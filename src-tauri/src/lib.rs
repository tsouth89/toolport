pub mod approval;
#[cfg(feature = "desktop")]
mod approval_broker;
#[cfg(feature = "desktop")]
mod desktop;
pub mod audit;
pub mod catalog;
pub mod clients;
pub mod codemode;
pub mod downstream;
pub mod gateway_publish;
pub mod inspect;
pub mod integrity;
pub mod oauth;
pub mod registry;
pub mod remote;
pub mod router;
pub mod savings;
pub mod searchtrace;
pub mod semantic;
pub mod shaping;
pub mod secrets;
pub mod stacks;
pub mod teams;
pub mod usage_report;
pub mod vendors;

pub(crate) use registry::{arg_looks_secret, redact_url_userinfo};

#[cfg(feature = "desktop")]
pub fn run() {
    desktop::run();
}
