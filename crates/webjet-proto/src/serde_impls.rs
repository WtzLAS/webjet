//! JSON forms of the fixed-size structs, for the control channel and the
//! tools: ids, keys and signatures as hex strings, addresses as `ip`,
//! `ip:port` and `ip/prefix`. Deserializing also accepts the generated
//! struct form (`{"b0": …}`, `{"family": …}`) that 0.6 and earlier printed,
//! so newer tools keep reading older agents.

use crate::{Cidr, Id16, IpAddress, Key32, Sig64, SockAddr};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};

/// A type with a text form and a legacy struct form of `u64` fields.
trait TextForm: Sized {
    const EXPECTING: &'static str;
    fn to_text(&self) -> String;
    fn from_text(s: &str) -> Option<Self>;
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self>;
}

struct TextVisitor<T>(PhantomData<T>);

impl<'de, T: TextForm> Visitor<'de> for TextVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(T::EXPECTING)
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<T, E> {
        T::from_text(s).ok_or_else(|| E::custom(format!("{s:?} is not {}", T::EXPECTING)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<T, A::Error> {
        let mut f = HashMap::new();
        while let Some((k, v)) = m.next_entry::<String, u64>()? {
            f.insert(k, v);
        }
        T::from_fields(&f).ok_or_else(|| de::Error::custom(format!("not {}", T::EXPECTING)))
    }
}

macro_rules! text_serde {
    ($($t:ty),*) => {$(
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_text())
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_any(TextVisitor::<$t>(PhantomData))
            }
        }
    )*};
}

text_serde!(Key32, Sig64, Id16, IpAddress, SockAddr, Cidr);

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    hex::decode_to_slice(s, &mut b).ok()?;
    Some(b)
}

fn words<const W: usize>(f: &HashMap<String, u64>) -> Option<[u64; W]> {
    let mut w = [0u64; W];
    for (i, x) in w.iter_mut().enumerate() {
        *x = *f.get(&format!("b{i}"))?;
    }
    Some(w)
}

impl TextForm for Key32 {
    const EXPECTING: &'static str = "a 32-byte id in hex";
    fn to_text(&self) -> String {
        hex::encode(self.to_bytes())
    }
    fn from_text(s: &str) -> Option<Self> {
        hex_array::<32>(s).map(|b| Key32::from_bytes(&b))
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let [b0, b1, b2, b3] = words::<4>(f)?;
        Some(Key32 { b0, b1, b2, b3 })
    }
}

impl TextForm for Sig64 {
    const EXPECTING: &'static str = "a 64-byte signature in hex";
    fn to_text(&self) -> String {
        hex::encode(self.to_bytes())
    }
    fn from_text(s: &str) -> Option<Self> {
        hex_array::<64>(s).map(|b| Sig64::from_bytes(&b))
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = words::<8>(f)?;
        Some(Sig64 {
            b0,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
        })
    }
}

impl TextForm for Id16 {
    const EXPECTING: &'static str = "a 16-byte id in hex";
    fn to_text(&self) -> String {
        hex::encode(self.to_bytes())
    }
    fn from_text(s: &str) -> Option<Self> {
        hex_array::<16>(s).map(|b| Id16::from_bytes(&b))
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let [b0, b1] = words::<2>(f)?;
        Some(Id16 { b0, b1 })
    }
}

fn family_fields(f: &HashMap<String, u64>) -> Option<(u8, u64, u64)> {
    Some((
        u8::try_from(*f.get("family")?).ok()?,
        *f.get("a0")?,
        *f.get("a1")?,
    ))
}

// An unset address (family 0, as `Default` makes it) is the empty string.

impl TextForm for IpAddress {
    const EXPECTING: &'static str = "an IP address";
    fn to_text(&self) -> String {
        self.to_ip().map(|ip| ip.to_string()).unwrap_or_default()
    }
    fn from_text(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(IpAddress::default());
        }
        s.parse::<IpAddr>().ok().map(IpAddress::from_ip)
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let (family, a0, a1) = family_fields(f)?;
        Some(IpAddress { family, a0, a1 })
    }
}

impl TextForm for SockAddr {
    const EXPECTING: &'static str = "an address with port (ip:port)";
    fn to_text(&self) -> String {
        self.to_sock().map(|a| a.to_string()).unwrap_or_default()
    }
    fn from_text(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(SockAddr::default());
        }
        s.parse::<SocketAddr>().ok().map(SockAddr::from_sock)
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let (family, a0, a1) = family_fields(f)?;
        Some(SockAddr {
            family,
            port: u16::try_from(*f.get("port")?).ok()?,
            a0,
            a1,
        })
    }
}

impl TextForm for Cidr {
    const EXPECTING: &'static str = "an address prefix (ip/prefix)";
    fn to_text(&self) -> String {
        self.addr()
            .map(|ip| format!("{ip}/{}", self.prefix))
            .unwrap_or_default()
    }
    fn from_text(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(Cidr::default());
        }
        let (ip, prefix) = s.split_once('/')?;
        let ip: IpAddr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > if ip.is_ipv4() { 32 } else { 128 } {
            return None;
        }
        Some(Cidr::new(ip, prefix))
    }
    fn from_fields(f: &HashMap<String, u64>) -> Option<Self> {
        let (family, a0, a1) = family_fields(f)?;
        Some(Cidr {
            family,
            prefix: u8::try_from(*f.get("prefix")?).ok()?,
            a0,
            a1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_forms_roundtrip() {
        let mut b = [0u8; 32];
        b[0] = 0xaf;
        b[31] = 0x9f;
        let k = Key32::from_bytes(&b);
        let v = serde_json::to_value(k).unwrap();
        assert_eq!(v, json!(hex::encode(b)));
        assert_eq!(serde_json::from_value::<Key32>(v).unwrap(), k);

        let sa = SockAddr::from_sock("[2001:db8::1]:443".parse().unwrap());
        let v = serde_json::to_value(sa).unwrap();
        assert_eq!(v, json!("[2001:db8::1]:443"));
        assert_eq!(serde_json::from_value::<SockAddr>(v).unwrap(), sa);

        let c = Cidr::new("10.4.0.0".parse().unwrap(), 16);
        let v = serde_json::to_value(c).unwrap();
        assert_eq!(v, json!("10.4.0.0/16"));
        assert_eq!(serde_json::from_value::<Cidr>(v).unwrap(), c);

        let ip = IpAddress::from_ip("10.4.1.1".parse().unwrap());
        assert_eq!(serde_json::to_value(ip).unwrap(), json!("10.4.1.1"));
        let id = Id16::from_bytes(&[7; 16]);
        assert_eq!(
            serde_json::from_value::<Id16>(serde_json::to_value(id).unwrap()).unwrap(),
            id
        );
        let s = Sig64::from_bytes(&[9; 64]);
        assert_eq!(
            serde_json::from_value::<Sig64>(serde_json::to_value(s).unwrap()).unwrap(),
            s
        );
    }

    #[test]
    fn unset_addresses_are_empty_strings() {
        assert_eq!(
            serde_json::to_value(SockAddr::default()).unwrap(),
            json!("")
        );
        assert_eq!(
            serde_json::from_value::<Cidr>(json!("")).unwrap(),
            Cidr::default()
        );
    }

    #[test]
    fn legacy_struct_forms_still_read() {
        let k = Key32 {
            b0: 1,
            b1: 2,
            b2: 3,
            b3: u64::MAX,
        };
        let v = json!({"b0": 1, "b1": 2, "b2": 3, "b3": u64::MAX});
        assert_eq!(serde_json::from_value::<Key32>(v).unwrap(), k);
        let sa = SockAddr::from_sock("10.1.2.3:80".parse().unwrap());
        let v = json!({"family": sa.family, "port": 80, "a0": sa.a0, "a1": sa.a1});
        assert_eq!(serde_json::from_value::<SockAddr>(v).unwrap(), sa);
    }

    #[test]
    fn bad_text_is_rejected() {
        assert!(serde_json::from_value::<Key32>(json!("xyz")).is_err());
        assert!(serde_json::from_value::<Cidr>(json!("10.0.0.0/33")).is_err());
        assert!(serde_json::from_value::<SockAddr>(json!("10.0.0.1")).is_err());
    }
}
