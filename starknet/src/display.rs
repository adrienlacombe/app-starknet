extern crate alloc;
use crate::{
    context::{
        Call, DeployAccountTransactionV1, DeployAccountTransactionV3, InvokeTransactionV1,
        InvokeTransactionV3,
    },
    erc20::{ERC20_TOKENS, TRANSFER},
    strk20::DerivationContext,
    types::FieldElement,
};

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;

use crate::context::{Ctx, Transaction};

use crate::settings::Settings;
use ledger_device_sdk::nbgl::{
    Field, NbglChoice, NbglGenericReview, NbglGlyph, NbglHomeAndSettings, NbglPageContent,
    NbglReview, NbglReviewStatus, NbglStatus, PageIndex, StatusType, TagValueConfirm, TagValueList,
    TransactionType, TuneIndex,
};

use alloc::string::{String, ToString};
use core::fmt::Write;

pub fn show_tx(ctx: &mut Ctx) -> Option<bool> {
    let tx = &mut ctx.tx;
    match tx {
        Transaction::None => None,
        Transaction::DeployAccountV3(tx) => show_tx_deploy_account_v3(tx),
        Transaction::DeployAccountV1(tx) => show_tx_deploy_account_v1(tx),
        Transaction::InvokeV3(tx) => show_tx_invoke_v3(tx),
        Transaction::InvokeV1(tx) => show_tx_invoke_v1(tx),
    }
}

fn show_tx_invoke_v3(tx: &InvokeTransactionV3) -> Option<bool> {
    if tx.nb_calls > 1 {
        return None;
    }
    match support_clear_sign(&tx.call) {
        Some(idx) => {
            let call = &tx.call;

            let mut sender = tx.sender_address.to_hex_string();
            sender.insert_str(0, "0x");
            let token = ERC20_TOKENS[idx].ticker;
            let mut to = call.calldata[0].to_hex_string();
            to.insert_str(0, "0x");
            let amount = call.calldata[1].to_dec_string(Some(ERC20_TOKENS[idx].decimals));

            let max_fees = FieldElement::from(&tx.l1_gas_bounds.value[8..16])
                * FieldElement::from(&tx.l1_gas_bounds.value[16..32])
                + FieldElement::from(&tx.l2_gas_bounds.value[8..16])
                    * FieldElement::from(&tx.l2_gas_bounds.value[16..32])
                + FieldElement::from(&tx.l1_data_gas_bounds.value[8..16])
                    * FieldElement::from(&tx.l1_data_gas_bounds.value[16..32]);

            let mut max_fees_str = max_fees.to_dec_string(Some(18));
            max_fees_str.push_str(" STRK");

            let my_fields = [
                Field {
                    name: "From",
                    value: sender.as_str(),
                },
                Field {
                    name: "Token",
                    value: token,
                },
                Field {
                    name: "Amount",
                    value: amount.as_str(),
                },
                Field {
                    name: "To",
                    value: to.as_str(),
                },
                Field {
                    name: "Max Fees",
                    value: max_fees_str.as_str(),
                },
            ];

            // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
            #[cfg(target_os = "apex_p")]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

            let review = NbglReview::new()
                .tx_type(TransactionType::Transaction)
                .titles("Review transaction", "", "Sign Transaction ?")
                .glyph(&APP_ICON);

            Some(review.show(&my_fields))
        }
        None => None,
    }
}

fn show_tx_invoke_v1(tx: &InvokeTransactionV1) -> Option<bool> {
    if tx.nb_calls > 1 {
        return None;
    }
    match support_clear_sign(&tx.call) {
        Some(idx) => {
            let call = &tx.call;

            let mut sender = tx.sender_address.to_hex_string();
            sender.insert_str(0, "0x");
            let token = ERC20_TOKENS[idx].ticker;
            let mut to = call.calldata[0].to_hex_string();
            to.insert_str(0, "0x");
            let amount = call.calldata[1].to_dec_string(Some(ERC20_TOKENS[idx].decimals));

            let mut max_fees_str = tx.max_fee.to_dec_string(Some(18));
            max_fees_str.push_str(" ETH");

            let my_fields = [
                Field {
                    name: "From",
                    value: sender.as_str(),
                },
                Field {
                    name: "Token",
                    value: token,
                },
                Field {
                    name: "Amount",
                    value: amount.as_str(),
                },
                Field {
                    name: "To",
                    value: to.as_str(),
                },
                Field {
                    name: "Max Fees",
                    value: max_fees_str.as_str(),
                },
            ];

            // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
            #[cfg(target_os = "apex_p")]
            const APP_ICON: NbglGlyph =
                NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

            let review = NbglReview::new()
                .tx_type(TransactionType::Transaction)
                .titles("Review transaction", "", "Sign Transaction ?")
                .glyph(&APP_ICON);

            Some(review.show(&my_fields))
        }
        None => None,
    }
}

fn show_tx_deploy_account_v3(tx: &DeployAccountTransactionV3) -> Option<bool> {
    let mut contract_address = tx.contract_address.to_hex_string();
    contract_address.insert_str(0, "0x");

    let mut class_hash = tx.class_hash.to_hex_string();
    class_hash.insert_str(0, "0x");

    let max_fees = FieldElement::from(&tx.l1_gas_bounds.value[8..16])
        * FieldElement::from(&tx.l1_gas_bounds.value[16..32])
        + FieldElement::from(&tx.l2_gas_bounds.value[8..16])
            * FieldElement::from(&tx.l2_gas_bounds.value[16..32])
        + FieldElement::from(&tx.l1_data_gas_bounds.value[8..16])
            * FieldElement::from(&tx.l1_data_gas_bounds.value[16..32]);

    let mut fees = max_fees.to_dec_string(Some(18));
    fees.push_str(" STRK");

    let my_fields = [
        Field {
            name: "Deploy account",
            value: contract_address.as_str(),
        },
        Field {
            name: "Max Fees",
            value: fees.as_str(),
        },
        Field {
            name: "Class Hash",
            value: class_hash.as_str(),
        },
    ];

    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
    #[cfg(target_os = "apex_p")]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

    let review = NbglReview::new()
        .tx_type(TransactionType::Transaction)
        .titles("Review transaction", "", "Sign Transaction ?")
        .glyph(&APP_ICON);

    Some(review.show(&my_fields))
}

fn show_tx_deploy_account_v1(tx: &DeployAccountTransactionV1) -> Option<bool> {
    // display contract_address, fees and class_hash
    let mut contract_address = tx.contract_address.to_hex_string();
    contract_address.insert_str(0, "0x");

    let mut class_hash = tx.class_hash.to_hex_string();
    class_hash.insert_str(0, "0x");

    let mut fees = tx.max_fee.to_dec_string(Some(18));
    fees.push_str(" ETH");

    let my_fields = [
        Field {
            name: "Deploy account",
            value: contract_address.as_str(),
        },
        Field {
            name: "Max Fees",
            value: fees.as_str(),
        },
        Field {
            name: "Class Hash",
            value: class_hash.as_str(),
        },
    ];

    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
    #[cfg(target_os = "apex_p")]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

    let review = NbglReview::new()
        .tx_type(TransactionType::Transaction)
        .titles("Review transaction", "", "Sign Transaction ?")
        .glyph(&APP_ICON);

    Some(review.show(&my_fields))
}

pub fn show_hash(ctx: &mut Ctx, is_tx_hash: bool) -> bool {
    let mut hash = ctx.hash.to_hex_string();
    hash.make_ascii_uppercase();

    let my_field = [Field {
        name: match is_tx_hash {
            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            true => "Transaction Hash",
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            true => "Tx Hash",
            false => "Hash",
        },
        value: hash.as_str(),
    }];

    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
    #[cfg(target_os = "apex_p")]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

    let mut review = NbglReview::new().glyph(&APP_ICON);

    if is_tx_hash {
        review = review
            .tx_type(TransactionType::Transaction)
            .titles("Review transaction", "", "Sign Transaction ?")
            .blind();
    } else {
        review = review
            .tx_type(TransactionType::Message)
            .titles("Review hash", "", "Sign Hash ?")
            .blind();
    }

    review.show(&my_field)
}

pub fn show_step(text: &str, ctx: &mut Ctx) {
    ctx.spinner.show(text);
}

#[allow(unused_variables)]
pub fn show_status(flag: bool, is_tx: bool, ctx: &mut Ctx) {
    let status = match is_tx {
        true => NbglReviewStatus::new().status_type(StatusType::Transaction),
        false => NbglReviewStatus::new().status_type(StatusType::Message),
    };
    status.show(flag);
    ctx.home.show_and_return();
}

#[allow(unused_variables)]
pub fn pkey_ui(key: &[u8], ctx: &mut Ctx) -> bool {
    let mut pk_hex = [0u8; 64];
    hex::encode_to_slice(&key[1..33], &mut pk_hex[0..]).unwrap();
    let m = core::str::from_utf8_mut(&mut pk_hex).unwrap();
    m[0..].make_ascii_uppercase();

    let my_field = [Field {
        name: "Public Key",
        value: m,
    }];

    let tvl = TagValueList::new(&my_field, 4, false, true);
    let tvc = TagValueConfirm::new(&tvl, TuneIndex::LookAtMe, "Approve", "");

    match NbglGenericReview::new()
        .add_content(NbglPageContent::TagValueConfirm(tvc))
        .show("Reject")
    {
        true => {
            let status = NbglStatus::new();
            status.text("Public Key Confirmed").show(true);
            ctx.home.show_and_return();
            true
        }
        false => {
            let status = NbglStatus::new();
            status.text("Public Key Rejected").show(false);
            ctx.home.show_and_return();
            false
        }
    }
}

/// `signer_key` is the uncompressed Stark public key (0x04 || x || y) derived
/// on-device from `ctx.bip32_path`. Chain, account and pool come from the host
/// and are only bound into the KDF; the device cannot check that the account
/// address belongs to this signer, so the path and the signer key are shown
/// alongside them as the values the device can actually vouch for.
pub fn strk20_viewing_key_ui(
    context: &DerivationContext,
    signer_key: &[u8],
    ctx: &mut Ctx,
) -> bool {
    let chain = format_chain_id(context.chain_id());
    let account = format_felt(context.account_address());
    let pool = format_felt(context.pool_address());
    let path = format_path(&ctx.bip32_path);
    let signer = format_felt(&signer_key[1..33]);

    let fields = [
        Field {
            name: "Warning",
            value: "Grants access to private STRK20 history",
        },
        Field {
            name: "Chain",
            value: chain.as_str(),
        },
        Field {
            name: "Account",
            value: account.as_str(),
        },
        Field {
            name: "Pool",
            value: pool.as_str(),
        },
        Field {
            name: "Derivation path",
            value: path.as_str(),
        },
        Field {
            name: "Signer key",
            value: signer.as_str(),
        },
    ];

    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_small.gif", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
    #[cfg(target_os = "apex_p")]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

    NbglReview::new()
        .tx_type(TransactionType::Message)
        .titles("Review STRK20 access", "", "Derive private viewing key?")
        .glyph(&APP_ICON)
        .show(&fields)
}

pub fn show_strk20_status(success: bool, ctx: &mut Ctx) {
    NbglStatus::new()
        .text(if success {
            "Viewing key derived"
        } else {
            "Viewing key not derived"
        })
        .show(success);
    ctx.home.show_and_return();
}

fn format_chain_id(chain_id: &[u8]) -> String {
    let significant = match chain_id.iter().position(|byte| *byte != 0) {
        Some(index) => &chain_id[index..],
        None => &chain_id[chain_id.len()..],
    };
    if !significant.is_empty() && significant.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        core::str::from_utf8(significant)
            .unwrap_or_default()
            .to_string()
    } else {
        format_felt(chain_id)
    }
}

fn format_felt(value: &[u8]) -> String {
    let mut formatted = String::from("0x");
    formatted.push_str(hex::encode(value).as_str());
    formatted
}

fn format_path(path: &[u32; 6]) -> String {
    let mut formatted = String::from("m");
    for element in path.iter() {
        let index = element & 0x7fff_ffff;
        let hardened = element & 0x8000_0000 != 0;
        let _ = write!(formatted, "/{}{}", index, if hardened { "'" } else { "" });
    }
    formatted
}

pub fn main_ui_nbgl(_comm: &mut Comm) -> NbglHomeAndSettings {
    // Load glyph from file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("home_nano_nbgl.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_64x64.gif", NBGL));
    #[cfg(target_os = "apex_p")]
    const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("starknet_48x48.png", NBGL));

    let settings_strings = [["Blind signing", "Enable transaction blind signing"]];
    let mut settings: Settings = Default::default();

    // Display the home screen.
    NbglHomeAndSettings::new()
        .glyph(&APP_ICON)
        .infos(
            "Starknet",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        )
        .settings(settings.get_mut(), &settings_strings)
}

#[allow(unused_variables)]
pub fn blind_signing_enable_ui(ctx: &mut Ctx) {
    let choice = NbglChoice::new().show(
        "This transaction cannot be clear-signed",
        "Enable blind-signing in the settings to sign this transaction",
        "Go to settings",
        "Reject transaction",
    );
    if choice {
        ctx.home.set_start_page(PageIndex::Settings(0));
        ctx.home.show_and_return();
        ctx.home.set_start_page(PageIndex::Home);
    } else {
        ctx.home.show_and_return();
    }
}

fn support_clear_sign(call: &Call) -> Option<usize> {
    for (idx, t) in ERC20_TOKENS.iter().enumerate() {
        if call.to == FieldElement::from(t.address) && call.selector == FieldElement::from(TRANSFER)
        {
            return Some(idx);
        }
    }
    None
}
