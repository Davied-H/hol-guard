//! Read only a selected closure from an independently authenticated release.
use super::*;

impl NativeCommandProgram {
    /// Construct a collection from exact integrity-bound pack bytes. The caller
    /// must authenticate `expected_root` and authorize the complete selection
    /// before publishing this value. A cache-owned digest is never authority.
    /// Fetch runs during admission, never during command evaluation.
    pub fn from_integrity_bound_packs(
        root: &[u8],
        expected_root: &str,
        selected: &BTreeSet<String>,
        fetch: impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
    ) -> Result<Self, &'static str> {
        if selected.is_empty() || selected.iter().any(|id| !bounded_id(id)) {
            return Err("native_command_pack_selection_invalid");
        }
        let mut reader = source::PackReleaseReuse::from_bytes(root, expected_root, fetch)?;
        let mut values = Vec::with_capacity(selected.len());
        let mut permissions = BTreeSet::new();
        for id in selected {
            let value = reader
                .read(id, None)?
                .ok_or("native_command_pack_selection_missing")?;
            let extensions = value.program["extensions"]
                .as_array()
                .filter(|extensions| extensions.len() == 1)
                .ok_or("native_command_pack_inventory_invalid")?;
            if extensions[0]["extension_id"] != *id {
                return Err("native_command_pack_inventory_invalid");
            }
            for permission in extensions[0]["permissions"]
                .as_array()
                .ok_or("native_command_permission_contract_invalid")?
            {
                let permission = permission["permission_id"]
                    .as_str()
                    .ok_or("native_command_permission_contract_invalid")?;
                if !permissions.insert(permission.to_owned()) {
                    return Err("native_command_permission_duplicate");
                }
            }
            values.push(value.program);
        }
        // Repeat executable ownership checks across the selected inventory.
        // Consume each JSON program when admitting its executable tree.
        source::validate_pack_mcp_inventory(&values)?;
        let mut packs = Vec::with_capacity(values.len());
        for value in values {
            let bytes =
                canonical_json_bytes(&value).map_err(|_| "native_command_program_json_invalid")?;
            packs.push(Self::from_bytes_observed(
                &bytes,
                &mut |_| {},
                Some((selected, &permissions)),
            )?);
        }
        Self::combine_admitted_packs(packs)
    }
}
