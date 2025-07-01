#include "cashu/core/errors.hpp"
#include <memory>
#include <sstream>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

namespace cashu::core {

//=============================================================================
// CashuError Base Implementation
//=============================================================================

CashuError::CashuError(const string& detail, int code) 
    : code_(code), detail_(detail) {
}

const char* CashuError::what() const noexcept {
    return detail_.c_str();
}

int CashuError::get_code() const noexcept {
    return code_;
}

const string& CashuError::get_detail() const noexcept {
    return detail_;
}

nlohmann::json CashuError::to_json() const {
    return nlohmann::json{
        {"code", code_},
        {"detail", detail_}
    };
}

//=============================================================================
// General Errors (10000-10999)
//=============================================================================

NotAllowedError::NotAllowedError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

OutputsAlreadySignedError::OutputsAlreadySignedError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

InvalidProofsError::InvalidProofsError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

//=============================================================================
// Transaction Errors (11000-11999)
//=============================================================================

TransactionError::TransactionError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

TokenAlreadySpentError::TokenAlreadySpentError()
    : TransactionError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

TransactionNotBalancedError::TransactionNotBalancedError(const string& detail)
    : TransactionError(detail, DEFAULT_CODE) {
}

SecretTooLongError::SecretTooLongError(const string& detail)
    : TransactionError(detail, DEFAULT_CODE) {
}

NoSecretInProofsError::NoSecretInProofsError()
    : TransactionError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

TransactionUnitError::TransactionUnitError(const string& detail)
    : TransactionError(detail, DEFAULT_CODE) {
}

TransactionAmountExceedsLimitError::TransactionAmountExceedsLimitError(const string& detail)
    : TransactionError(detail, DEFAULT_CODE) {
}

TransactionDuplicateInputsError::TransactionDuplicateInputsError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

TransactionDuplicateOutputsError::TransactionDuplicateOutputsError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

TransactionMultipleUnitsError::TransactionMultipleUnitsError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

TransactionUnitMismatchError::TransactionUnitMismatchError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

TransactionAmountlessInvoiceError::TransactionAmountlessInvoiceError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

TransactionAmountInvoiceMismatchError::TransactionAmountInvoiceMismatchError(const optional<string>& detail)
    : TransactionError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

//=============================================================================
// Keyset Errors (12000-12999)
//=============================================================================

KeysetError::KeysetError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

KeysetNotFoundError::KeysetNotFoundError(const optional<string>& keyset_id) {
    string detail_msg = DEFAULT_DETAIL;
    if (keyset_id.has_value()) {
        detail_msg += ": " + keyset_id.value();
    }
    code_ = DEFAULT_CODE;
    detail_ = detail_msg;
}

KeysetInactiveError::KeysetInactiveError(const optional<string>& detail)
    : KeysetError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

//=============================================================================
// Lightning Errors (20000-29999)
//=============================================================================

LightningError::LightningError(const optional<string>& detail, const optional<int>& code)
    : CashuError(detail.value_or(DEFAULT_DETAIL), code.value_or(DEFAULT_CODE)) {
}

QuoteNotPaidError::QuoteNotPaidError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

LightningPaymentFailedError::LightningPaymentFailedError(const optional<string>& detail)
    : CashuError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

QuoteSignatureInvalidError::QuoteSignatureInvalidError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

QuoteRequiresPubkeyError::QuoteRequiresPubkeyError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

TokensAlreadyIssuedError::TokensAlreadyIssuedError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

MintingDisabledError::MintingDisabledError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

QuotePendingError::QuotePendingError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

InvoiceAlreadyPaidError::InvoiceAlreadyPaidError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

QuoteExpiredError::QuoteExpiredError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

//=============================================================================
// Authentication Errors (30000-31999) - NUT-21/NUT-22
//=============================================================================

ClearAuthRequiredError::ClearAuthRequiredError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

ClearAuthFailedError::ClearAuthFailedError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

BlindAuthRequiredError::BlindAuthRequiredError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

BlindAuthFailedError::BlindAuthFailedError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

BlindAuthAmountExceededError::BlindAuthAmountExceededError(const optional<string>& detail)
    : CashuError(detail.value_or(DEFAULT_DETAIL), DEFAULT_CODE) {
}

BlindAuthRateLimitExceededError::BlindAuthRateLimitExceededError()
    : CashuError(DEFAULT_DETAIL, DEFAULT_CODE) {
}

//=============================================================================
// Utility Functions
//=============================================================================

unique_ptr<CashuError> create_error_from_code(int code, const string& detail) {
    // General errors (10000-10999)
    switch (code) {
        case NotAllowedError::DEFAULT_CODE:
            return make_unique<NotAllowedError>(detail.empty() ? nullopt : optional<string>(detail));
        case OutputsAlreadySignedError::DEFAULT_CODE:
            return make_unique<OutputsAlreadySignedError>(detail.empty() ? nullopt : optional<string>(detail));
        case InvalidProofsError::DEFAULT_CODE:
            return make_unique<InvalidProofsError>(detail.empty() ? nullopt : optional<string>(detail));
    }

    // Transaction errors (11000-11999)
    if (code >= 11000 && code < 12000) {
        switch (code) {
            case TransactionError::DEFAULT_CODE:
                return make_unique<TransactionError>(detail.empty() ? nullopt : optional<string>(detail));
            case TokenAlreadySpentError::DEFAULT_CODE:
                return make_unique<TokenAlreadySpentError>();
            case TransactionNotBalancedError::DEFAULT_CODE:
                return make_unique<TransactionNotBalancedError>(detail.empty() ? "transaction not balanced" : detail);
            case SecretTooLongError::DEFAULT_CODE:
                return make_unique<SecretTooLongError>(detail.empty() ? SecretTooLongError::DEFAULT_DETAIL : detail);
            case NoSecretInProofsError::DEFAULT_CODE:
                return make_unique<NoSecretInProofsError>();
            case TransactionUnitError::DEFAULT_CODE:
                return make_unique<TransactionUnitError>(detail.empty() ? "transaction unit error" : detail);
            case TransactionAmountExceedsLimitError::DEFAULT_CODE:
                return make_unique<TransactionAmountExceedsLimitError>(detail.empty() ? "amount exceeds limit" : detail);
            case TransactionDuplicateInputsError::DEFAULT_CODE:
                return make_unique<TransactionDuplicateInputsError>(detail.empty() ? nullopt : optional<string>(detail));
            case TransactionDuplicateOutputsError::DEFAULT_CODE:
                return make_unique<TransactionDuplicateOutputsError>(detail.empty() ? nullopt : optional<string>(detail));
            case TransactionMultipleUnitsError::DEFAULT_CODE:
                return make_unique<TransactionMultipleUnitsError>(detail.empty() ? nullopt : optional<string>(detail));
            case TransactionUnitMismatchError::DEFAULT_CODE:
                return make_unique<TransactionUnitMismatchError>(detail.empty() ? nullopt : optional<string>(detail));
            case TransactionAmountlessInvoiceError::DEFAULT_CODE:
                return make_unique<TransactionAmountlessInvoiceError>(detail.empty() ? nullopt : optional<string>(detail));
            case TransactionAmountInvoiceMismatchError::DEFAULT_CODE:
                return make_unique<TransactionAmountInvoiceMismatchError>(detail.empty() ? nullopt : optional<string>(detail));
            default:
                return make_unique<TransactionError>(detail.empty() ? "unknown transaction error" : detail, code);
        }
    }

    // Keyset errors (12000-12999)
    if (code >= 12000 && code < 13000) {
        switch (code) {
            case KeysetError::DEFAULT_CODE:
                return make_unique<KeysetError>(detail.empty() ? nullopt : optional<string>(detail));
            case KeysetNotFoundError::DEFAULT_CODE:
                return make_unique<KeysetNotFoundError>(detail.empty() ? nullopt : optional<string>(detail));
            case KeysetInactiveError::DEFAULT_CODE:
                return make_unique<KeysetInactiveError>(detail.empty() ? nullopt : optional<string>(detail));
            default:
                return make_unique<KeysetError>(detail.empty() ? "unknown keyset error" : detail, code);
        }
    }

    // Lightning errors (20000-29999)
    if (code >= 20000 && code < 30000) {
        switch (code) {
            case LightningError::DEFAULT_CODE:
                return make_unique<LightningError>(detail.empty() ? nullopt : optional<string>(detail));
            case QuoteNotPaidError::DEFAULT_CODE:
                return make_unique<QuoteNotPaidError>();
            case LightningPaymentFailedError::DEFAULT_CODE:
                return make_unique<LightningPaymentFailedError>(detail.empty() ? nullopt : optional<string>(detail));
            case QuoteSignatureInvalidError::DEFAULT_CODE:
                return make_unique<QuoteSignatureInvalidError>();
            case QuoteRequiresPubkeyError::DEFAULT_CODE:
                return make_unique<QuoteRequiresPubkeyError>();
            case TokensAlreadyIssuedError::DEFAULT_CODE:
                return make_unique<TokensAlreadyIssuedError>();
            case MintingDisabledError::DEFAULT_CODE:
                return make_unique<MintingDisabledError>();
            case QuotePendingError::DEFAULT_CODE:
                return make_unique<QuotePendingError>();
            case InvoiceAlreadyPaidError::DEFAULT_CODE:
                return make_unique<InvoiceAlreadyPaidError>();
            case QuoteExpiredError::DEFAULT_CODE:
                return make_unique<QuoteExpiredError>();
            default:
                return make_unique<LightningError>(detail.empty() ? "unknown lightning error" : detail, code);
        }
    }

    // Authentication errors (30000-31999)
    if ((code >= 30000 && code < 32000)) {
        switch (code) {
            case ClearAuthRequiredError::DEFAULT_CODE:
                return make_unique<ClearAuthRequiredError>();
            case ClearAuthFailedError::DEFAULT_CODE:
                return make_unique<ClearAuthFailedError>();
            case BlindAuthRequiredError::DEFAULT_CODE:
                return make_unique<BlindAuthRequiredError>();
            case BlindAuthFailedError::DEFAULT_CODE:
                return make_unique<BlindAuthFailedError>();
            case BlindAuthAmountExceededError::DEFAULT_CODE:
                return make_unique<BlindAuthAmountExceededError>(detail.empty() ? nullopt : optional<string>(detail));
            case BlindAuthRateLimitExceededError::DEFAULT_CODE:
                return make_unique<BlindAuthRateLimitExceededError>();
            default:
                return make_unique<CashuError>(detail.empty() ? "unknown auth error" : detail, code);
        }
    }

    // Unknown error code - return base CashuError
    return make_unique<CashuError>(detail.empty() ? "unknown error" : detail, code);
}

bool is_error_in_category(int code, int category_start, int category_end) {
    return code >= category_start && code < category_end;
}

string get_error_category(int code) {
    if (code >= 10000 && code < 11000) {
        return "General";
    } else if (code >= 11000 && code < 12000) {
        return "Transaction";
    } else if (code >= 12000 && code < 13000) {
        return "Keyset";
    } else if (code >= 20000 && code < 30000) {
        return "Lightning";
    } else if ((code >= 30000 && code < 32000)) {
        return "Authentication";
    } else {
        return "Unknown";
    }
}

} // namespace cashu::core