//! Requests an admin signs for one node or controller rather than for the
//! replicated log: reading the operation log, exporting the controller
//! state, remote upgrades. Each is checked the same way first.

use anyhow::{Result, bail};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::store::View;
use webjet_proto::Decodable;

/// Decode a signed request of type `ty` and check that a valid admin
/// account (named by `account`) signed it with its current key. `what` is
/// what only admins may do, for the error ("only admins {what}"). The
/// caller checks the request's times.
pub fn signed_request<T: Decodable>(
    view: &View,
    raw: &[u8],
    ty: u16,
    what: &str,
    account: impl FnOnce(&T) -> Bytes32,
) -> Result<T> {
    let v = crypto::open_envelope(raw)?;
    if v.ty != ty {
        let name = webjet_proto::msg_type::name;
        bail!("expected a signed {}, got {}", name(ty), name(v.ty));
    }
    let req: T = v.decode()?;
    let Some(a) = view.accounts.get(&account(&req)) else {
        bail!("unknown account");
    };
    if !a.valid || !a.admin {
        bail!("only admins {what}");
    }
    // The signature, against the account's current key (not the one the
    // envelope names).
    crypto::open_expect(raw, ty, &[a.key])?;
    Ok(req)
}
