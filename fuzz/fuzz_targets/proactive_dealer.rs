#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::{Share, Sharks};

#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub share: Share,
    pub n_shares: usize,
}

fuzz_target!(|params: Parameters| {
    let sharks = Sharks(params.threshold);
    let dealer = sharks.proactive_dealer(&params.share);

    let _shares: Vec<Share> = dealer.take(params.n_shares).collect();
});
