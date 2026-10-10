use std::{collections::HashMap, future::pending, io, net::IpAddr};

use lan_mouse_ipc::{ClientConfig, ClientHandle, DiscoveredDevice};
use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE_TYPE: &str = "_lanmouse._udp.local.";

pub(crate) struct Discovery {
    daemon: ServiceDaemon,
    events: Receiver<ServiceEvent>,
    own_fingerprint: String,
    own_name: String,
    own_fullname: String,
    devices: HashMap<String, DiscoveredDevice>,
}

impl Discovery {
    pub(crate) fn new(fingerprint: String, port: u16) -> io::Result<Self> {
        let daemon = ServiceDaemon::new().map_err(io::Error::other)?;
        let events = daemon.browse(SERVICE_TYPE).map_err(io::Error::other)?;
        let own_name = gethostname::gethostname().to_string_lossy().into_owned();
        let instance: String = fingerprint
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(16)
            .collect();
        let mut discovery = Self {
            daemon,
            events,
            own_fullname: format!("{instance}.{SERVICE_TYPE}"),
            own_fingerprint: fingerprint,
            own_name,
            devices: Default::default(),
        };
        discovery.advertise(port)?;
        Ok(discovery)
    }

    pub(crate) fn advertise(&mut self, port: u16) -> io::Result<()> {
        let host: String = self
            .own_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let properties = HashMap::from([
            ("fp".to_owned(), self.own_fingerprint.clone()),
            ("name".to_owned(), self.own_name.clone()),
        ]);
        let instance = self
            .own_fullname
            .trim_end_matches(SERVICE_TYPE)
            .trim_end_matches('.');
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            &format!("{host}.local."),
            "",
            port,
            properties,
        )
        .map_err(io::Error::other)?
        .enable_addr_auto();
        let _ = self.daemon.unregister(&self.own_fullname);
        self.daemon.register(info).map_err(io::Error::other)
    }

    pub(crate) fn devices(&self) -> Vec<DiscoveredDevice> {
        let mut devices: Vec<_> = self.devices.values().cloned().collect();
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        devices
    }

    pub(crate) async fn changed(&mut self) {
        loop {
            let Ok(event) = self.events.recv_async().await else {
                return pending().await;
            };
            let changed = match event {
                ServiceEvent::ServiceResolved(info) => self.resolved(&info),
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    self.devices.remove(&fullname).is_some()
                }
                _ => false,
            };
            if changed {
                return;
            }
        }
    }

    fn resolved(&mut self, info: &mdns_sd::ResolvedService) -> bool {
        let Some(fingerprint) = info.get_property_val_str("fp") else {
            return false;
        };
        if fingerprint == self.own_fingerprint {
            return false;
        }
        let mut ips: Vec<IpAddr> = info
            .get_addresses_v4()
            .into_iter()
            .filter(|ip| !ip.is_loopback())
            .map(Into::into)
            .collect();
        ips.sort();
        let device = DiscoveredDevice {
            name: info
                .get_property_val_str("name")
                .unwrap_or(info.get_hostname())
                .to_owned(),
            ips,
            port: info.get_port(),
            fingerprint: fingerprint.to_owned(),
            configured: false,
        };
        let fullname = info.get_fullname().to_owned();
        self.devices.insert(fullname, device.clone()) != Some(device)
    }
}

pub(crate) fn is_configured(
    clients: &[(ClientHandle, ClientConfig)],
    device: &DiscoveredDevice,
) -> bool {
    clients.iter().any(|(_, c)| {
        names_match(c, &device.name) || device.ips.iter().any(|ip| c.fix_ips.contains(ip))
    })
}

pub(crate) fn follow_target(
    clients: &[(ClientHandle, ClientConfig)],
    authorized: &HashMap<String, String>,
    device: &DiscoveredDevice,
) -> Option<ClientHandle> {
    let description = authorized.get(&device.fingerprint)?;
    if device.ips.is_empty() {
        return None;
    }
    clients
        .iter()
        .find(|(_, c)| {
            (names_match(c, &device.name) || names_match(c, description))
                && !device.ips.iter().any(|ip| c.fix_ips.contains(ip))
        })
        .map(|(handle, _)| *handle)
}

fn names_match(client: &ClientConfig, name: &str) -> bool {
    client
        .hostname
        .as_deref()
        .is_some_and(|h| h.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(hostname: &str, ip: &str) -> (ClientHandle, ClientConfig) {
        let config = ClientConfig {
            hostname: Some(hostname.to_owned()),
            fix_ips: vec![ip.parse().unwrap()],
            ..Default::default()
        };
        (3, config)
    }

    fn device(name: &str, ip: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_owned(),
            ips: vec![ip.parse().unwrap()],
            port: 4242,
            fingerprint: "aa:bb".to_owned(),
            configured: false,
        }
    }

    fn authorized() -> HashMap<String, String> {
        HashMap::from([("aa:bb".to_owned(), "desktop".to_owned())])
    }

    #[test]
    fn follows_changed_ip_of_authorized_device() {
        let clients = [client("DESKTOP-G2207OF", "192.168.1.5")];
        let moved = device("desktop-g2207of", "192.168.1.6");
        assert_eq!(follow_target(&clients, &authorized(), &moved), Some(3));
    }

    #[test]
    fn ignores_unchanged_ip_unauthorized_and_unrelated_devices() {
        let clients = [client("DESKTOP-G2207OF", "192.168.1.5")];
        let same = device("DESKTOP-G2207OF", "192.168.1.5");
        assert_eq!(follow_target(&clients, &authorized(), &same), None);
        let moved = device("DESKTOP-G2207OF", "192.168.1.6");
        assert_eq!(follow_target(&clients, &HashMap::new(), &moved), None);
        let other = device("laptop", "192.168.1.9");
        assert_eq!(follow_target(&clients, &authorized(), &other), None);
    }

    #[test]
    fn configured_by_name_or_ip() {
        let clients = [client("desktop", "192.168.1.5")];
        assert!(is_configured(&clients, &device("DESKTOP", "10.0.0.1")));
        assert!(is_configured(&clients, &device("x", "192.168.1.5")));
        assert!(!is_configured(&clients, &device("x", "10.0.0.1")));
    }
}
