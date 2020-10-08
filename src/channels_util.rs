use super::*;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FundingTxInfo {
    pub init_cust_bal: i64,
    pub init_merch_bal: i64,
    pub escrow_txid: FixedSizeArray32,
    pub escrow_prevout: FixedSizeArray32,
    pub merch_txid: FixedSizeArray32,
    pub merch_prevout: FixedSizeArray32,
}

#[derive(Clone, Debug, PartialEq, Display, Serialize, Deserialize)]
pub enum ProtocolStatus {
    New,
    Initialized,
    Activated,
    Established,
}

#[derive(Clone, Debug, PartialEq, Display, Serialize, Deserialize)]
pub enum ChannelStatus {
    None,
    PendingOpen,
    Open,
    MerchantInitClose,
    CustomerInitClose,
    Disputed,
    PendingClose,
    ConfirmedClose,
}

// #[derive(Clone, Serialize, Deserialize, PartialEq)]
// pub enum ChannelStatus {
//     NEW,
//     INITIALIZED,
//     ACTIVATED,
//     UNLINKED,
// }

#[derive(Clone, Debug, PartialEq, Display, Serialize, Deserialize)]
pub enum PaymentStatus {
    Prepare,
    Update,
    Error,
}

#[derive(Clone, Debug, PartialEq, Display, Serialize, Deserialize)]
pub enum NegativePaymentPolicy {
    REJECT,              // only positive payments are allowed in this mode
    CHECK_JUSTIFICATION, // allow negative payments, if authorization/justification presented
}
