#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| webjet_fuzz::kcp_session(data));
