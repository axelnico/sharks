//! Fast, small and secure [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) library crate
//!
//! Usage example (std):
//! ```
//! use sharks::{ Sharks, Share };
//!
//! // Set a minimum threshold of 10 shares
//! let sharks = Sharks(10);
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4]
//! # #[cfg(feature = "std")]
//! # {
//! let dealer = sharks.dealer(&[1, 2, 3, 4]);
//! // Get 10 shares
//! let shares: Vec<Share> = dealer.take(10).collect();
//! // Recover the original secret!
//! let secret = sharks.recover(shares.as_slice()).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! # }
//! ```
//!
//! Usage example (no std):
//! ```
//! use sharks::{ Sharks, Share };
//! use rand_chacha::rand_core::SeedableRng;
//!
//! // Set a minimum threshold of 10 shares
//! let sharks = Sharks(10);
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4]
//! let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
//! let dealer = sharks.dealer_rng(&[1, 2, 3, 4], &mut rng);
//! // Get 10 shares
//! let shares: Vec<Share> = dealer.take(10).collect();
//! // Recover the original secret!
//! let secret = sharks.recover(shares.as_slice()).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

mod field;
mod math;
mod share;

extern crate alloc;

use alloc::vec::Vec;
use hashbrown::HashSet;

use field::GF256;
pub use share::Share;

/// Tuple struct which implements methods to generate shares and recover secrets over a 256 bits Galois Field.
/// Its only parameter is the minimum shares threshold.
///
/// Usage example:
/// ```
/// # use sharks::{ Sharks, Share };
/// // Set a minimum threshold of 10 shares
/// let sharks = Sharks(10);
/// // Obtain an iterator over the shares for secret [1, 2, 3, 4]
/// # #[cfg(feature = "std")]
/// # {
/// let dealer = sharks.dealer(&[1, 2, 3, 4]);
/// // Get 10 shares
/// let shares: Vec<Share> = dealer.take(10).collect();
/// // Recover the original secret!
/// let secret = sharks.recover(shares.as_slice()).unwrap();
/// assert_eq!(secret, vec![1, 2, 3, 4]);
/// # }
/// ```
pub struct Sharks(pub u8);

impl Sharks {
    /// This method is useful when `std` is not available. For typical usage
    /// see the `dealer` method.
    ///
    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    /// A random number generator has to be provided.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # use rand_chacha::rand_core::SeedableRng;
    /// # let sharks = Sharks(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let dealer = sharks.dealer_rng(&[1, 2], &mut rng);
    /// // Get 3 shares
    /// let shares: Vec<Share> = dealer.take(3).collect();
    pub fn dealer_rng<R: rand::Rng>(
        &self,
        secret: &[u8],
        rng: &mut R,
    ) -> impl Iterator<Item = Share> {
        let mut polys = Vec::with_capacity(secret.len());

        for chunk in secret {
            polys.push(math::random_polynomial(GF256(*chunk), self.0, rng))
        }

        math::get_evaluator(polys)
    }

    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # let sharks = Sharks(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let dealer = sharks.dealer(&[1, 2]);
    /// // Get 3 shares
    /// let shares: Vec<Share> = dealer.take(3).collect();
    #[cfg(feature = "std")]
    pub fn dealer(&self, secret: &[u8]) -> impl Iterator<Item = Share> {
        let mut rng = rand::thread_rng();
        self.dealer_rng(secret, &mut rng)
    }

    /// Given an iterable collection of shares, recovers the original secret.
    /// If the number of distinct shares is less than the minimum threshold an `Err` is returned,
    /// otherwise an `Ok` containing the secret.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # use rand_chacha::rand_core::SeedableRng;
    /// # let sharks = Sharks(3);
    /// # let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// # let mut shares: Vec<Share> = sharks.dealer_rng(&[1], &mut rng).take(3).collect();
    /// // Recover original secret from shares
    /// let mut secret = sharks.recover(&shares);
    /// // Secret correctly recovered
    /// assert!(secret.is_ok());
    /// // Remove shares for demonstration purposes
    /// shares.clear();
    /// secret = sharks.recover(&shares);
    /// // Not enough shares to recover secret
    /// assert!(secret.is_err());
    pub fn recover<'a, T>(&self, shares: T) -> Result<Vec<u8>, &str>
    where
        T: IntoIterator<Item = &'a Share>,
        T::IntoIter: Iterator<Item = &'a Share>,
    {
        let mut share_length: Option<usize> = None;
        let mut keys: HashSet<u8> = HashSet::new();
        let mut values: Vec<Share> = Vec::new();

        for share in shares.into_iter() {
            if share_length.is_none() {
                share_length = Some(share.y.len());
            }

            if Some(share.y.len()) != share_length {
                return Err("All shares must have the same length");
            } else {
                keys.insert(share.x.0);
                values.push(share.clone());
            }
        }

        if keys.is_empty() || (keys.len() < self.0 as usize) {
            Err("Not enough shares to recover original secret")
        } else {
            Ok(math::interpolate(values.as_slice()))
        }
    }

    /// This method is useful when `std` is not available. For typical usage
    /// see the `proactive_dealer` method.
    ///
    /// Given a share, returns an `Iterator` along new shares that are for specific use of Proactive
    /// Protection. These shares are all evaluations of random polynomials with constant term zero
    /// based on the protocol proposed by Herzberg et al. in their 1995 paper,
    /// "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage."
    /// A random number generator has to be provided.
    ///
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # use rand_chacha::rand_core::SeedableRng;
    /// # let sharks = Sharks(2);
    /// // Obtain an iterator over the shares for secret "a_secret"
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let dealer = sharks.dealer_rng(b"a_secret", &mut rng);
    /// // Get 2 shares for 2 players
    /// let shares: Vec<Share> = dealer.take(2).collect();
    /// let share_player1 = &shares[0];
    ///  // Get renewal shares for player 1
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let proactive_player1 = sharks.proactive_dealer_rng(share_player1, &mut rng);
    /// let renewals_shares_player1: Vec<Share> = proactive_player1.take(2).collect();
    #[cfg(feature = "proactive")]
    pub fn proactive_dealer_rng<R: rand::Rng>(
        &self,
        share: &Share,
        rng: &mut R,
    ) -> impl Iterator<Item = Share> {
        let mut polys = Vec::with_capacity(share.y.len());

        for _ in 0..share.y.len() {
            polys.push(math::random_polynomial(GF256(0), self.0, rng))
        }
        math::get_evaluator(polys)
    }

    /// Given a share, returns an `Iterator` along new shares that are for specific use of Proactive
    /// Protection. These shares are all evaluations of random polynomials with constant term zero
    /// based on the protocol proposed by Herzberg et al. in their 1995 paper,
    /// "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage."
    /// Example:
    /// ```
    /// # use sharks::{ Sharks, Share };
    /// # let sharks = Sharks(2);
    /// // Obtain an iterator over the shares for secret "a_secret"
    /// let dealer = sharks.dealer(b"a_secret");
    /// // Get 2 shares for 2 players
    /// let shares: Vec<Share> = dealer.take(2).collect();
    /// let share_player1 = &shares[0];
    ///  // Get renewal shares for player 1
    /// let proactive_player1 = sharks.proactive_dealer(share_player1);
    /// let renewals_shares_player1: Vec<Share> = proactive_player1.take(2).collect();
    #[cfg(all(feature = "proactive", feature = "std"))]
    pub fn proactive_dealer(&self, share: &Share) -> impl Iterator<Item = Share> {
        let mut rng = rand::thread_rng();
        self.proactive_dealer_rng(share, &mut rng)
    }
    
}

#[cfg(test)]
mod tests {
    use super::{Share, Sharks};
    use alloc::{vec, vec::Vec};

    impl Sharks {
        #[cfg(not(feature = "std"))]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item=Share> {
            use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

            let mut rng = ChaCha8Rng::from_seed([0x90; 32]);
            self.dealer_rng(secret, &mut rng)
        }

        #[cfg(feature = "std")]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item=Share> {
            self.dealer(secret)
        }

        #[cfg(all(feature = "proactive", not(feature = "std")))]
        fn make_proactive_shares(&self, share: &Share) -> impl Iterator<Item = Share> {
            use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

            let mut rng = ChaCha8Rng::from_seed([0x90; 32]);
            self.proactive_dealer_rng(share, &mut rng)
        }

        #[cfg(all(feature = "proactive", feature = "std"))]
        fn make_proactive_shares(&self, share: &Share) -> impl Iterator<Item = Share> {
            self.proactive_dealer(share)
        }

        #[cfg(feature = "proactive")]
        fn renew_all_shares_for_all_players(shares: &mut Vec<Share>, renewals: Vec<Vec<Share>>) {
            for (i, share) in shares.iter_mut().enumerate() {
                let player_renewals: Vec<&Share> = renewals.iter().map(|r| &r[i]).collect();
                let result = share.renew(player_renewals);
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn test_insufficient_shares_err() {
        let sharks = Sharks(255);
        let shares: Vec<Share> = sharks.make_shares(&[1]).take(254).collect();
        let secret = sharks.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_duplicate_shares_err() {
        let sharks = Sharks(255);
        let mut shares: Vec<Share> = sharks.make_shares(&[1]).take(255).collect();
        shares[1] = Share {
            x: shares[0].x.clone(),
            y: shares[0].y.clone(),
        };
        let secret = sharks.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_integration_works() {
        let sharks = Sharks(255);
        let shares: Vec<Share> = sharks.make_shares(&[1, 2, 3, 4]).take(255).collect();
        let secret = sharks.recover(&shares).unwrap();
        assert_eq!(secret, vec![1, 2, 3, 4]);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_dealer_generates_shares() {
        let sharks = Sharks(3);
        let shares: Vec<Share> = sharks.make_shares(b"secret").take(3).collect();
        let renewal_shares: Vec<Share> = sharks.make_proactive_shares(&shares[0]).take(3).collect();
        assert_eq!(renewal_shares.len(), 3);
        // Each renewal share y length must match the original share y length
        for rs in &renewal_shares {
            assert_eq!(rs.y.len(), shares[0].y.len());
        }
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_dealer_x_values_are_sequential() {
        let sharks = Sharks(2);
        let shares: Vec<Share> = sharks.make_shares(b"test").take(2).collect();
        let renewal_shares: Vec<Share> = sharks.make_proactive_shares(&shares[0]).take(5).collect();
        // The evaluator produces x values starting at 1 and incrementing
        for (i, rs) in renewal_shares.iter().enumerate() {
            assert_eq!(rs.x, super::field::GF256((i + 1) as u8));
        }
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_two_players() {
        let sharks = Sharks(2);
        let secret = b"a_secret";
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(2).collect();

        // Each player generates renewal shares for all players
        let (shares_player1, shares_player2) = shares.split_at_mut(1);
        let share_player1 = &mut shares_player1[0];
        let share_player2 = &mut shares_player2[0];

        let renewal_from_p1: Vec<Share> = sharks.make_proactive_shares(share_player1).take(2).collect();
        let renewal_from_p2: Vec<Share> = sharks.make_proactive_shares(share_player2).take(2).collect();

        // Player 1 applies its own renewal share and player 2's renewal share for player 1
        let result1 = share_player1.renew([&renewal_from_p1[0], &renewal_from_p2[0]]);
        assert!(result1.is_ok());

        // Player 2 applies its own renewal share and player 1's renewal share for player 2
        let result2 = share_player2.renew([&renewal_from_p2[1], &renewal_from_p1[1]]);
        assert!(result2.is_ok());

        // Secret should still be recoverable
        let recovered = sharks.recover(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_three_players_threshold_two() {
        let sharks = Sharks(2);
        let secret = b"three_players";
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(3).collect();

        // Each player generates renewal shares for all 3 players
        let renewals: Vec<Vec<Share>> = shares
            .iter()
            .map(|s| sharks.make_proactive_shares(s).take(3).collect())
            .collect();

        // Each player applies renewal shares from all players at their index
        Sharks::renew_all_shares_for_all_players(&mut shares, renewals);

        // Secret should be recoverable with threshold shares
        let recovered = sharks.recover(&shares[..2]).unwrap();
        assert_eq!(recovered, secret);

        // Also recoverable with any other pair
        let recovered = sharks.recover(&shares[1..]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_multiple_renewal_rounds() {
        let sharks = Sharks(2);
        let secret = b"multi_round";
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(2).collect();

        // Perform 5 rounds of renewal
        for _ in 0..5 {
            let (shares_p1, shares_p2) = shares.split_at_mut(1);
            let sp1 = &mut shares_p1[0];
            let sp2 = &mut shares_p2[0];

            let renewal_from_p1: Vec<Share> = sharks.make_proactive_shares(sp1).take(2).collect();
            let renewal_from_p2: Vec<Share> = sharks.make_proactive_shares(sp2).take(2).collect();

            sp1.renew([&renewal_from_p1[0], &renewal_from_p2[0]]).unwrap();
            sp2.renew([&renewal_from_p2[1], &renewal_from_p1[1]]).unwrap();
        }

        let recovered = sharks.recover(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_single_byte_secret() {
        let sharks = Sharks(2);
        let secret = &[42u8];
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(2).collect();

        let (shares_p1, shares_p2) = shares.split_at_mut(1);
        let sp1 = &mut shares_p1[0];
        let sp2 = &mut shares_p2[0];

        let renewal_from_p1: Vec<Share> = sharks.make_proactive_shares(sp1).take(2).collect();
        let renewal_from_p2: Vec<Share> = sharks.make_proactive_shares(sp2).take(2).collect();

        sp1.renew([&renewal_from_p1[0], &renewal_from_p2[0]]).unwrap();
        sp2.renew([&renewal_from_p2[1], &renewal_from_p1[1]]).unwrap();

        let recovered = sharks.recover(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_changes_shares() {
        let sharks = Sharks(2);
        let secret = b"changes";
        // Use 3 players so the test works with both deterministic (no_std) and random (std) RNG.
        // With a fixed seed and 2 players, identical polynomials cause XOR cancellation (no-op).
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(3).collect();
        let original_ys: Vec<_> = shares.iter().map(|s| s.y.clone()).collect();

        let renewals: Vec<Vec<Share>> = shares
            .iter()
            .map(|s| sharks.make_proactive_shares(s).take(3).collect())
            .collect();

        Sharks::renew_all_shares_for_all_players(&mut shares, renewals);

        // At least one share's y values should have changed after renewal
        let any_changed = shares.iter().zip(original_ys.iter()).any(|(s, orig)| s.y != *orig);
        assert!(any_changed);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_old_shares_cannot_recover_after_renewal() {
        let sharks = Sharks(2);
        let secret = b"old_shares";
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(3).collect();

        // Save copies of the original shares
        let old_share_0 = shares[0].clone();
        let _old_share_1 = shares[1].clone();

        // Renew all shares using the full protocol
        let renewals: Vec<Vec<Share>> = shares
            .iter()
            .map(|s| sharks.make_proactive_shares(s).take(3).collect())
            .collect();

        Sharks::renew_all_shares_for_all_players(&mut shares, renewals);

        // Mixing old and new shares should not recover the secret correctly
        // (use one old share and one new share)
        let mixed = vec![old_share_0, shares[2].clone()];
        let recovered = sharks.recover(&mixed).unwrap();
        // The mixed recovery should (very likely) NOT produce the original secret
        // because old and new shares are from different polynomials
        let original_recovered = sharks.recover(&shares[..2]).unwrap();
        assert_eq!(original_recovered, secret);
        assert_ne!(recovered.as_slice(), secret);
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_preserves_x_values() {
        let sharks = Sharks(3);
        let secret = b"preserve_x";
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(3).collect();
        let original_xs: Vec<_> = shares.iter().map(|s| s.x.clone()).collect();

        let renewals: Vec<Vec<Share>> = shares
            .iter()
            .map(|s| sharks.make_proactive_shares(s).take(3).collect())
            .collect();

        Sharks::renew_all_shares_for_all_players(&mut shares, renewals);

        // x values should remain unchanged after renewal
        for (share, original_x) in shares.iter().zip(original_xs.iter()) {
            assert_eq!(share.x, *original_x);
        }
    }

    #[cfg(feature = "proactive")]
    #[test]
    fn test_proactive_renewal_higher_threshold() {
        let sharks = Sharks(5);
        let secret = b"high_threshold_secret";
        let num_players = 7u8;
        let mut shares: Vec<Share> = sharks.make_shares(secret).take(num_players as usize).collect();

        let renewals: Vec<Vec<Share>> = shares
            .iter()
            .map(|s| sharks.make_proactive_shares(s).take(num_players as usize).collect())
            .collect();

        Sharks::renew_all_shares_for_all_players(&mut shares, renewals);

        // Should be recoverable with exactly threshold shares
        let recovered = sharks.recover(&shares[..5]).unwrap();
        assert_eq!(recovered, secret);

        // Should fail with fewer than threshold shares
        let insufficient = sharks.recover(&shares[..4]);
        assert!(insufficient.is_err());
    }
}
