use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::convert::TryFrom;

use sharks::{Share, Sharks};

fn dealer(c: &mut Criterion) {
    let sharks = Sharks(255);
    let mut dealer = sharks.dealer(&[1]);

    c.bench_function("obtain_shares_dealer", |b| {
        b.iter(|| sharks.dealer(black_box(&[1])))
    });
    c.bench_function("step_shares_dealer", |b| b.iter(|| dealer.next()));
}

fn recover(c: &mut Criterion) {
    let sharks = Sharks(255);
    let shares: Vec<Share> = sharks.dealer(&[1]).take(255).collect();

    c.bench_function("recover_secret", |b| {
        b.iter(|| sharks.recover(black_box(shares.as_slice())))
    });
}

fn share(c: &mut Criterion) {
    let bytes_vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let bytes = bytes_vec.as_slice();
    let share = Share::try_from(bytes).unwrap();

    c.bench_function("share_from_bytes", |b| {
        b.iter(|| Share::try_from(black_box(bytes)))
    });

    c.bench_function("share_to_bytes", |b| {
        b.iter(|| Vec::from(black_box(&share)))
    });
}

#[cfg(feature = "proactive")]
fn proactive_dealer(c: &mut Criterion) {
    let sharks = Sharks(255);
    let share_to_renew: &Share = &sharks.dealer(&[1]).take(1).collect::<Vec<Share>>()[0];
    
    let mut proactive_dealer = sharks.proactive_dealer(share_to_renew);

    c.bench_function("obtain_shares_proactive_dealer", |b| {
        b.iter(|| sharks.proactive_dealer(black_box(share_to_renew)))
    });
    
    c.bench_function("step_shares_proactive_dealer", |b| {
        b.iter(|| proactive_dealer.next())
    });
}

#[cfg(feature = "proactive")]
fn renew_share(c: &mut Criterion) {
    let sharks = Sharks(255);
    let mut shares: Vec<Share> = sharks.dealer(&[1]).take(1).collect();
    let share_to_renew = shares.remove(0);
    
    // Generate renewal shares for testing performance of renew
    let renewal_shares: Vec<Share> = sharks.proactive_dealer(&share_to_renew).take(2).collect();

    c.bench_function("renew_share", |b| {
        b.iter_batched(
            || share_to_renew.clone(),
            |mut s| {
                let _ = s.renew(&renewal_shares);
                s
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "proactive")]
criterion_group!(proactive_benches, proactive_dealer, renew_share);

criterion_group!(benches, dealer, recover, share);

#[cfg(not(feature = "proactive"))]
criterion_main!(benches);

#[cfg(feature = "proactive")]
criterion_main!(proactive_benches, benches);