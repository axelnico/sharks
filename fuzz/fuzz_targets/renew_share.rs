#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::Share;

#[derive(Debug, Arbitrary)]
struct Parameters {
    pub share: Share,
    pub renewal_shares: Vec<Share>,
}

fuzz_target!(|params: Parameters| {
    let mut share = params.share;
    let _result = share.renew(params.renewal_shares.iter());
});
