#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::{Share, Sharks};

#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub secret: Vec<u8>,
    pub n_shares: usize,
}

fuzz_target!(|params: Parameters| {
    if params.secret.is_empty() || params.n_shares < 2 || params.n_shares > 255 {
        return;
    }

    let threshold = if params.threshold < 2 { 2 } else { params.threshold };
    let n_shares = if params.n_shares < threshold as usize { threshold as usize } else { params.n_shares };
    let sharks = Sharks(threshold);

    let mut shares: Vec<Share> = sharks.dealer(&params.secret).take(n_shares).collect();

    // Each player generates renewal shares for all players
    let renewals: Vec<Vec<Share>> = shares
        .iter()
        .map(|s| sharks.proactive_dealer(s).take(n_shares).collect())
        .collect();

    // Each player applies renewal shares from all players at their index
    for (i, share) in shares.iter_mut().enumerate() {
        let player_renewals: Vec<&Share> = renewals.iter().map(|r| &r[i]).collect();
        let _ = share.renew(player_renewals);
    }

    // The original secret must still be recoverable after renewal
    let recovered = sharks.recover(&shares);
    if let Ok(secret) = recovered {
        assert_eq!(secret, params.secret);
    }
});
