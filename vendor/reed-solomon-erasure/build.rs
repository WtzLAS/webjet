use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(feature = "simd-accel")]
extern crate cc;

const FIELD_SIZE: usize = 256;

const GENERATING_POLYNOMIAL: usize = 29;

fn gen_log_table(polynomial: usize) -> [u8; FIELD_SIZE] {
    let mut result: [u8; FIELD_SIZE] = [0; FIELD_SIZE];
    let mut b: usize = 1;

    for log in 0..FIELD_SIZE - 1 {
        result[b] = log as u8;

        b = b << 1;

        if FIELD_SIZE <= b {
            b = (b - FIELD_SIZE) ^ polynomial;
        }
    }

    result
}

const EXP_TABLE_SIZE: usize = FIELD_SIZE * 2 - 2;

fn gen_exp_table(log_table: &[u8; FIELD_SIZE]) -> [u8; EXP_TABLE_SIZE] {
    let mut result: [u8; EXP_TABLE_SIZE] = [0; EXP_TABLE_SIZE];

    for i in 1..FIELD_SIZE {
        let log = log_table[i] as usize;
        result[log] = i as u8;
        result[log + FIELD_SIZE - 1] = i as u8;
    }

    result
}

fn multiply(log_table: &[u8; FIELD_SIZE], exp_table: &[u8; EXP_TABLE_SIZE], a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let log_a = log_table[a as usize];
        let log_b = log_table[b as usize];
        let log_result = log_a as usize + log_b as usize;
        exp_table[log_result]
    }
}

fn gen_mul_table(
    log_table: &[u8; FIELD_SIZE],
    exp_table: &[u8; EXP_TABLE_SIZE],
) -> [[u8; FIELD_SIZE]; FIELD_SIZE] {
    let mut result: [[u8; FIELD_SIZE]; FIELD_SIZE] = [[0; 256]; 256];

    for a in 0..FIELD_SIZE {
        for b in 0..FIELD_SIZE {
            result[a][b] = multiply(log_table, exp_table, a as u8, b as u8);
        }
    }

    result
}

fn gen_mul_table_half(
    log_table: &[u8; FIELD_SIZE],
    exp_table: &[u8; EXP_TABLE_SIZE],
) -> ([[u8; 16]; FIELD_SIZE], [[u8; 16]; FIELD_SIZE]) {
    let mut low: [[u8; 16]; FIELD_SIZE] = [[0; 16]; FIELD_SIZE];
    let mut high: [[u8; 16]; FIELD_SIZE] = [[0; 16]; FIELD_SIZE];

    for a in 0..low.len() {
        for b in 0..low.len() {
            let mut result = 0;
            if !(a == 0 || b == 0) {
                let log_a = log_table[a];
                let log_b = log_table[b];
                result = exp_table[log_a as usize + log_b as usize];
            }
            if (b & 0x0F) == b {
                low[a][b] = result;
            }
            if (b & 0xF0) == b {
                high[a][b >> 4] = result;
            }
        }
    }
    (low, high)
}

macro_rules! write_table {
    (1D => $file:ident, $table:ident, $name:expr, $type:expr) => {{
        let len = $table.len();
        let mut table_str = String::from(format!("pub static {}: [{}; {}] = [", $name, $type, len));

        for v in $table.iter() {
            let str = format!("{}, ", v);
            table_str.push_str(&str);
        }

        table_str.push_str("];\n");

        $file.write_all(table_str.as_bytes()).unwrap();
    }};
    (2D => $file:ident, $table:ident, $name:expr, $type:expr) => {{
        let rows = $table.len();
        let cols = $table[0].len();
        let mut table_str = String::from(format!(
            "pub static {}: [[{}; {}]; {}] = [",
            $name, $type, cols, rows
        ));

        for a in $table.iter() {
            table_str.push_str("[");
            for b in a.iter() {
                let str = format!("{}, ", b);
                table_str.push_str(&str);
            }
            table_str.push_str("],\n");
        }

        table_str.push_str("];\n");

        $file.write_all(table_str.as_bytes()).unwrap();
    }};
}

fn write_tables() {
    let log_table = gen_log_table(GENERATING_POLYNOMIAL);
    let exp_table = gen_exp_table(&log_table);
    let mul_table = gen_mul_table(&log_table, &exp_table);

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("table.rs");
    let mut f = File::create(&dest_path).unwrap();

    write_table!(1D => f, log_table,      "LOG_TABLE",      "u8");
    write_table!(1D => f, exp_table,      "EXP_TABLE",      "u8");
    write_table!(2D => f, mul_table,      "MUL_TABLE",      "u8");

    if cfg!(feature = "simd-accel") {
        let (mul_table_low, mul_table_high) = gen_mul_table_half(&log_table, &exp_table);

        write_table!(2D => f, mul_table_low,  "MUL_TABLE_LOW",  "u8");
        write_table!(2D => f, mul_table_high, "MUL_TABLE_HIGH", "u8");
    }
}

// Webjet: the SIMD code is chosen at run time on x86_64. Upstream compiled
// `simd_c/reedsolomon.c` once with `-march=haswell` (AVX2), so the program
// died with SIGILL on CPUs without AVX2 (Celeron J1900/J4125, Pentium
// Silver, ...); with plain x86-64 (SSE2 only) the C code is five times
// slower than the Rust fallback. Now x86_64 gets two copies, built with
// `-mssse3` and `-mavx2` under their own symbol names, and `galois_8`
// calls the best one the CPU has (or the Rust code). aarch64 builds the
// file once: NEON is always there. Decided by the *target* (CARGO_CFG_*),
// not by `#[cfg]`, which in a build script is the build machine.
// Sets `cfg(rse_simd)` and `cfg(rse_simd_x86)` or `cfg(rse_simd_neon)`.
#[cfg(feature = "simd-accel")]
fn compile_simd_c() {
    println!("cargo:rerun-if-changed=simd_c/reedsolomon.c");
    println!("cargo:rerun-if-changed=simd_c/reedsolomon.h");
    println!("cargo:rerun-if-env-changed=RUST_REED_SOLOMON_ERASURE_ARCH");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "android" || os == "ios" {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build = |name: &str, flags: &[&str], suffix: Option<&str>| -> bool {
        let mut b = cc::Build::new();
        b.opt_level(3).file("simd_c/reedsolomon.c").out_dir(out.join(name));
        // MSVC's own compiler doesn't know the GCC vector extensions the C
        // code uses; clang-cl (cargo-xwin) does.
        let tool = b.get_compiler();
        if tool.is_like_msvc() && !tool.is_like_clang_cl() {
            return false;
        }
        if !tool.is_like_msvc() {
            b.flag("-std=c11");
        }
        for f in flags {
            b.flag(f);
        }
        if let Some(sfx) = suffix {
            b.define("reedsolomon_gal_mul", Some(format!("reedsolomon_gal_mul_{sfx}").as_str()));
            b.define(
                "reedsolomon_gal_mul_xor",
                Some(format!("reedsolomon_gal_mul_xor_{sfx}").as_str()),
            );
        }
        b.compile(name);
        true
    };
    match arch.as_str() {
        "x86_64" => {
            if build("reedsolomon_ssse3", &["-mssse3"], Some("ssse3"))
                && build("reedsolomon_avx2", &["-mavx2"], Some("avx2"))
            {
                println!("cargo:rustc-cfg=rse_simd");
                println!("cargo:rustc-cfg=rse_simd_x86");
            }
        }
        "aarch64" => {
            let march = env::var("RUST_REED_SOLOMON_ERASURE_ARCH")
                .map(|a| format!("-march={a}"))
                .ok();
            let flags: Vec<&str> = march.iter().map(String::as_str).collect();
            if build("reedsolomon", &flags, None) {
                println!("cargo:rustc-cfg=rse_simd");
                println!("cargo:rustc-cfg=rse_simd_neon");
            }
        }
        _ => {}
    }
}

#[cfg(not(feature = "simd-accel"))]
fn compile_simd_c() {}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(rse_simd, rse_simd_x86, rse_simd_neon)");
    compile_simd_c();
    write_tables();
}
