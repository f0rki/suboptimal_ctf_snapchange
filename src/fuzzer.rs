//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use crate::constants;
use anyhow::Result;
use snapchange::prelude::*;

const CR3: Cr3 = Cr3(constants::CR3);
// const BASE: u64 = 0x7ffff7f51000;
const BASE: u64 = 0x555555554000;
const INPUT_LENGTH: usize = 0x18;

// Custom input which will generate bytes between [0x40, 0x7f] as
// per the challenge
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub struct RestrictedInput {
    data: [u8; INPUT_LENGTH],
}

impl FuzzInput for RestrictedInput {

    // Only mutate up to 4 bytes in the input, keeping to the wanted byte range
    fn mutate(
        input: &mut Self,
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _max_length: usize,
        max_mutations: u64,
    ) -> Vec<String> {
        for _ in 0..(rng.gen_range(1..=max_mutations)) {
            let offset = rng.next() as usize % (INPUT_LENGTH - 1);
            input.data[offset] = (rng.next() as u8 % (0x80 - 0x40)) + 0x40;
        }
        input.data[INPUT_LENGTH - 1] = 0u8;

        // Do not generate the mutation strategy strings for now
        vec![]
    }

    // Generate an input where all the bytes are [0x40, 0x7f]
    fn generate(
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _max_length: usize,
    ) -> Self {
        let mut r = Self { data: [0u8; INPUT_LENGTH]};
        for i in 0..(INPUT_LENGTH - 1) {
            let byte = (rng.next() as u8 % (0x7d - 0x40)) + 0x40;
            r.data[i] = byte;
        }
        r
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Self { data: [0u8; INPUT_LENGTH]};
        let l = std::cmp::min(bytes.len(), r.data.len());
        r.data[0..l].copy_from_slice(&bytes[0..l]);
        Ok(r)
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.extend(&self.data);
        Ok(())
    }
}

#[derive(Default)]
pub struct Example1Fuzzer;

impl Fuzzer for Example1Fuzzer {
    // NOTE: Using the custom input type here to restrict input mutations
    type Input = RestrictedInput;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = INPUT_LENGTH;
    const MAX_MUTATIONS: u64 = 4;

    // Since we took the snapshot using a patched binary, we need to revert the original
    // RIP before the `int3 ; vmcall` (4 bytes) that we patched over `main`
    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        Ok(())
    }

    fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // For perf, ignore the calls to printf
        // let a = AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!printf", 0x0);
        // let a = AddressLookup::SymbolOffset("libc.so.6!printf", 0x0);
        let a = AddressLookup::Virtual(VirtAddr(BASE + 0x10e0), CR3);
        fuzzvm.patch_bytes_permanent(a, &[0xc3_u8])?;

        // remove snapshot bytes and replace by original buytes
        // let a = AddressLookup::SymbolOffset("main", 0x0);
        let a = AddressLookup::Virtual(VirtAddr(BASE + 0x13dd), CR3);
        // f30f1efa554889e54883ec40897dcc48
        let patched_bytes: &[u8] = &[
            0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40, 0x89, 0x7d,
            0xcc, 0x48,
        ];
        fuzzvm.patch_bytes_permanent(a, patched_bytes)?;
        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            AddressLookup::Virtual(VirtAddr(BASE + 0x1237), CR3), // printf(suboptimal)
            AddressLookup::Virtual(VirtAddr(BASE + 0x1110), CR3), // exit
            AddressLookup::Virtual(VirtAddr(BASE + 0x1523), CR3), // ret from main
        ])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            // For perf, ignore the first call to printf("Key: ")
            // Breakpoint {
            //     lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!printf", 0x0),
            //     bp_type: BreakpointType::Repeated,
            //     bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, _feedback| {
            //         fuzzvm.fake_immediate_return()?;
            //
            //         // Continue execution
            //         Ok(Execution::Continue)
            //     },
            // },
            // Scanf is where we inject our mutated string. The destination buffer is stored
            // in RDI, so we write the current input bytes into the buffer at RDI.
            Breakpoint {
                // lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!__isoc99_scanf", 0x0),
                // lookup: AddressLookup::SymbolOffset("libc.so.6!__isoc99_scanf", 0x0),
                lookup: AddressLookup::Virtual(VirtAddr(BASE + 0x1100), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let input_addr = fuzzvm.rsi();
                    fuzzvm.write_bytes_dirty(VirtAddr(input_addr), fuzzvm.cr3(), &input.data)?;

                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
            // Breakpoint {
            //     lookup: AddressLookup::Virtual(VirtAddr(0x7ffff7f51000 + 0x1396), CR3),
            //     bp_type: BreakpointType::Repeated,
            //     bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, feedback| {
            //         // Stateful coverage is done here.
            //         // At offset 0x1396, there is a byte for byte comparison check that
            //         // we want to keep track of. The included feedback mechanism allows
            //         // a fuzzer to insert a new value (u64) into the coverage. In this,
            //         // case we OR the current counter value to the RIP to create a
            //         // "stateful" coverage point.
            //         //
            //         // Example:
            //         // RIP - 0xdeadbeefcafe    Counter - 1
            //         // Value: 0x01deadbeefcafe
            //         // RIP - 0xdeadbeefcafe    Counter - 2
            //         // Value: 0x02deadbeefcafe
            //         // RIP - 0xdeadbeefcafe    Counter - 3
            //         // Value: 0x03deadbeefcafe
            //         //
            //         // Then the fuzzer knows that any unique value here is a new coverage
            //         // point that we need to store the current input into the corpus
            //         let counter = fuzzvm.rax();
            //
            //         if let Some(feedback) = feedback {
            //             feedback.record_max(0, counter);
            //         }
            //
            //         // Continue execution
            //         Ok(Execution::Continue)
            //     },
            // },
            Breakpoint {
                // lookup: AddressLookup::SymbolOffset("check_equals", 0),
                lookup: AddressLookup::Virtual(VirtAddr(BASE + 0x1320), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                    let expected = b"xk|nF{quxzwkgzgwx|quitH\x00";
                    let str_ptr = VirtAddr(fuzzvm.rdi());
                    let size = fuzzvm.rsi() as usize;
                    let mut vm_data: Vec<u8> = Vec::with_capacity(size);
                    vm_data.resize(size, 0);
                    fuzzvm.read_bytes(str_ptr, CR3, &mut vm_data[..])?;
                    if let Some(feedback) = feedback {
                        if let Some(dist) =
                            feedback.record_min_prefix_dist(0u64, &vm_data[..], expected)
                        {
                            log::info!(
                                "progress new min dist {} with {:?} == {:?}",
                                dist,
                                String::from_utf8_lossy(&vm_data[..]),
                                String::from_utf8_lossy(expected)
                            );
                            if dist == 0 {
                                return Ok(Execution::CrashReset {
                                    path: "FOUND".to_string(),
                                });
                            }
                        }
                    }

                    // reset execution for next try
                    Ok(Execution::Reset)
                },
            },
            Breakpoint {
                lookup: AddressLookup::Virtual(VirtAddr(BASE + 0x1504), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |_fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, _feedback| {
                    // Crash reset on the put("Optimal") call
                    Ok(Execution::CrashReset {
                        path: "FOUND".to_string(),
                    })
                },
            },
        ])
    }

    fn schedule_next_input(
        &mut self,
        corpus: &[Self::Input],
        _feedback: &mut snapchange::feedback::FeedbackTracker,
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Self::Input {
        // schedule the last entry to the corpus with a high probability. This ensures that we make quick
        // progress towards the goal of minimizing the distance to our target string.
        if rng.gen_bool(0.7) {
            if let Some(last_added) = corpus.last().cloned() {
                return last_added;
            }
        }

        // However, we fall back towards choosing random corpus entries to avoid being stuck in a
        // local minimum. In this case though, this is probably not even necessary.
        if let Some(input) = corpus.choose(rng) {
            input.clone()
        } else {
            // Default to generating a new input
            Self::Input::generate(corpus, rng, dictionary, Self::MAX_INPUT_LENGTH)
        }
    }
}
