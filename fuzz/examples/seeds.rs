//! Write every target's seed inputs to `fuzz/corpus/<target>/seed-<n>`, the
//! starting corpus for `cargo +nightly fuzz run <target>`.

fn main() -> std::io::Result<()> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for (name, seeds) in webjet_fuzz::seeds::all() {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir)?;
        for (i, s) in seeds.iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i}")), s)?;
        }
        println!("{name}: {} seeds", seeds.len());
    }
    Ok(())
}
