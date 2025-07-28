use alloc::vec::Vec;
use std::ops::Add;
use super::field::GF256;

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

#[cfg(feature = "zeroize_memory")]
use zeroize::Zeroize;
use crate::math;

/// A share used to reconstruct the secret. Can be serialized to and from a byte array.
///
/// Usage example:
/// ```
/// use sharks::{Sharks, Share};
/// use core::convert::TryFrom;
/// # use rand_chacha::rand_core::SeedableRng;
/// # fn send_to_printer(_: Vec<u8>) {}
/// # fn ask_shares() -> Vec<Vec<u8>> {vec![vec![1, 2], vec![2, 3], vec![3, 4]]}
///
/// // Transmit the share bytes to a printer
/// let sharks = Sharks(3);
/// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
/// let dealer = sharks.dealer_rng(&[1, 2, 3], &mut rng);
///
/// // Get 5 shares and print paper keys
/// for s in dealer.take(5) {
///     send_to_printer(Vec::from(&s));
/// };
///
/// // Get share bytes from an external source and recover secret
/// let shares_bytes: Vec<Vec<u8>> = ask_shares();
/// let shares: Vec<Share> = shares_bytes.iter().map(|s| Share::try_from(s.as_slice()).unwrap()).collect();
/// let secret = sharks.recover(&shares).unwrap();
#[derive(Clone)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary, Debug))]
#[cfg_attr(feature = "zeroize_memory", derive(Zeroize))]
#[cfg_attr(feature = "zeroize_memory", zeroize(drop))]
pub struct Share {
    pub x: GF256,
    pub y: Vec<GF256>,
}

impl Share {

    /// Renews a specific share based on the protocol proposed by Amir Herzberg’s in 1995 paper, 
    /// "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage." 
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # let sharks = Sharks(2);
    /// // Obtain an iterator over the shares for secret "a_secret"
    /// let dealer = sharks.dealer(b"a_secret");
    /// // Get 2 shares
    /// let mut shares: Vec<Share> = dealer.take(2).collect();
    /// let (shares_player1, shares_player2) = shares.split_at_mut(1);
    /// let share_player1 = & mut shares_player1[0];
    /// let share_player2 = & mut shares_player2[0];
    /// let proactive_player1 = sharks.proactive_dealer(share_player1);
    /// let renewal_shares_player1: Vec<Share> = proactive_player1.take(2).collect();
    ///  // Usually at this step, player1 should send the corresponding renewal share
    ///  // renewal_shares_player1[1] to player 2
    /// let proactive_player2 = sharks.proactive_dealer(share_player2);
    /// let renewal_shares_player2: Vec<Share> = proactive_player2.take(2).collect();
    ///  // Usually at this step, player2 should send the corresponding renewal share
    ///  // renewal_shares_player2[0] to player 1
    /// let player1_renewal = share_player1.renew([&renewal_shares_player1[0],&renewal_shares_player2[0]]);
    /// let player2_renewal = share_player2.renew([&renewal_shares_player2[1],&renewal_shares_player1[1]]);
    ///  // Each player correctly updated its share with the corresponding information
    /// assert!(player1_renewal.is_ok());
    /// assert!(player2_renewal.is_ok());
    /// 
    /// let mut secret = sharks.recover(&shares);
    /// // Secret is still correctly recovered
    /// assert!(secret.is_ok());
    /// assert_eq!(b"a_secret", secret.unwrap().as_slice());
    #[cfg(feature = "proactive")]
    pub fn renew<'a, T>(& mut self, renewal_shares: T) -> Result<(), &'a str>
    where
        T: IntoIterator<Item = &'a Share>,
        T::IntoIter: Iterator<Item = &'a Share>,
    {
        let share_length = self.y.len();

        for renewal_share in renewal_shares.into_iter() {
            if renewal_share.y.len() != share_length {
                return Err("All shares must have the same length");
            }
            else if renewal_share.x != self.x {
                return Err("Invalid renewal share supplied");
            } else {
                self.y.iter_mut()
                    .zip(renewal_share.y.iter())
                    .for_each(|(y,others_y)| *y = y.clone().add(others_y.clone()));
            }
        }
        Ok(())
    }
}

/// Obtains a byte vector from a `Share` instance
impl From<&Share> for Vec<u8> {
    fn from(s: &Share) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.y.len() + 1);
        bytes.push(s.x.0);
        bytes.extend(s.y.iter().map(|p| p.0));
        bytes
    }
}

/// Obtains a `Share` instance from a byte slice
impl core::convert::TryFrom<&[u8]> for Share {
    type Error = &'static str;

    fn try_from(s: &[u8]) -> Result<Share, Self::Error> {
        if s.len() < 2 {
            Err("A Share must be at least 2 bytes long")
        } else {
            let x = GF256(s[0]);
            let y = s[1..].iter().map(|p| GF256(*p)).collect();
            Ok(Share { x, y })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Share, GF256};
    use alloc::{vec, vec::Vec};
    use core::convert::TryFrom;

    #[test]
    fn vec_from_share_works() {
        let share = Share {
            x: GF256(1),
            y: vec![GF256(2), GF256(3)],
        };
        let bytes = Vec::from(&share);
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn share_from_u8_slice_works() {
        let bytes = [1, 2, 3];
        let share = Share::try_from(&bytes[..]).unwrap();
        assert_eq!(share.x, GF256(1));
        assert_eq!(share.y, vec![GF256(2), GF256(3)]);
    }
}
