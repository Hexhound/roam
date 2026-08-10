use rustler::{Binary, Env, NewBinary};

/// Decode a concatenated `[u8;32]`-per-item binary into id chunks.
fn decode_ids(bin: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bin.len() % 32 != 0 {
        return Err(format!(
            "items binary length {} is not a multiple of 32",
            bin.len()
        ));
    }
    Ok(bin
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect())
}

fn to_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Binary<'a> {
    let mut new_bin = NewBinary::new(env, bytes.len());
    new_bin.as_mut_slice().copy_from_slice(bytes);
    Binary::from(new_bin)
}

/// `reconcile_server(items_bin, msg_bin) -> {:ok, reply_bin} | {:error, reason}`.
/// DirtyCpu: reconcile compute can exceed ~1ms. Panic-guarded so a Rust panic
/// returns an error term instead of unwinding into the BEAM.
#[rustler::nif(schedule = "DirtyCpu")]
fn reconcile_server<'a>(
    env: Env<'a>,
    items: Binary<'a>,
    msg: Binary<'a>,
) -> Result<Binary<'a>, String> {
    // Copy inputs into owned buffers before the catch_unwind closure so the
    // captured data is UnwindSafe (Binary borrows the BEAM env).
    let items_owned: Vec<u8> = items.as_slice().to_vec();
    let msg_owned: Vec<u8> = msg.as_slice().to_vec();

    let result = std::panic::catch_unwind(move || {
        let ids = decode_ids(&items_owned)?;
        let set = roam_rbsr::ItemSet::from_ids(ids);
        roam_rbsr::reconcile_server(&set, &msg_owned).map_err(|e| e.to_string())
    });

    match result {
        Ok(Ok(reply)) => Ok(to_binary(env, &reply)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("rbsr nif panicked".to_string()),
    }
}

rustler::init!("Elixir.Sync.Rbsr");
