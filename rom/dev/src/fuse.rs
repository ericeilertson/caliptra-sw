/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    The file contains Fuse-related Implementations.

--*/
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::{FuseLogEntry, FuseLogEntryId};
use caliptra_drivers::{CaliptraError, CaliptraResult, FuseLogArray};
use zerocopy::IntoBytes;

/// Log Fuse data
///
/// # Arguments
/// * `entry_id` - log entry ID
/// * `data` -  data To log to the fuse log
///
/// # Return Value
/// * `Ok(())` - Success
/// * `Err(GlobalErr::FuseLogInvalidEntryId)` - Invalid Fuse log entry ID
/// * `Err(GlobalErr::FuseLogUpsupportedDataLength)` - Unsupported data length
///
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
#[inline(never)]
pub fn log_fuse_data(
    log: &mut FuseLogArray,
    entry_id: FuseLogEntryId,
    data: &[u8],
) -> CaliptraResult<()> {
    if entry_id == FuseLogEntryId::Invalid {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID);
    }

    // Create a FUSE log entry
    let mut log_entry = FuseLogEntry {
        entry_id: entry_id as u32,
        ..Default::default()
    };
    let Some(data_dest) = log_entry.log_data.as_mut_bytes().get_mut(..data.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH);
    };
    data_dest.copy_from_slice(data);

    // Use checked_sub to prevent underflow, then validate bounds
    let index = (entry_id as usize)
        .checked_sub(1)
        .ok_or(CaliptraError::ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID)?;

    if index >= log.len() {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID);
    }

    log[index] = log_entry;

    Ok(())
}
