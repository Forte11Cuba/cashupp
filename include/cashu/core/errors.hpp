#pragma once

// NUTSHELL COMPATIBILITY: cashu/core/errors.py

#include <exception>
#include <string>
#include <optional>
#include <memory>
#include <nlohmann/json.hpp>

namespace cashu::core {

/**
 * @brief Base exception class for all Cashu-related errors
 * 
 * This class provides the foundation for all Cashu error types,
 * maintaining 100% compatibility with nutshell's CashuError class.
 * All errors include a numeric code and detailed message.
 */
class CashuError : public std::exception {
public:
    /**
     * @brief Construct CashuError with detail message and code
     * @param detail Error detail message
     * @param code Error code (default: 0)
     */
    explicit CashuError(const std::string& detail, int code = 0);
    
    /**
     * @brief Get error message for std::exception compatibility
     * @return Error detail message
     */
    const char* what() const noexcept override;
    
    /**
     * @brief Get error code
     * @return Numeric error code
     */
    int get_code() const noexcept;
    
    /**
     * @brief Get error detail message
     * @return Error detail string
     */
    const std::string& get_detail() const noexcept;
    
    /**
     * @brief Serialize error to JSON (nutshell compatibility)
     * @return JSON representation of error
     */
    nlohmann::json to_json() const;

protected:
    int code_;
    std::string detail_;
};

//=============================================================================
// General Errors (10000-10999)
//=============================================================================

/**
 * @brief General "not allowed" error
 */
class NotAllowedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 10000;
    static constexpr const char* DEFAULT_DETAIL = "not allowed";
    
    explicit NotAllowedError(const std::optional<std::string>& detail = std::nullopt,
                            const std::optional<int>& code = std::nullopt);
};

/**
 * @brief Error when outputs have already been signed
 */
class OutputsAlreadySignedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 10002;
    static constexpr const char* DEFAULT_DETAIL = "outputs have already been signed before.";
    
    explicit OutputsAlreadySignedError(const std::optional<std::string>& detail = std::nullopt,
                                      const std::optional<int>& code = std::nullopt);
};

/**
 * @brief Error when proofs could not be verified
 */
class InvalidProofsError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 10003;
    static constexpr const char* DEFAULT_DETAIL = "proofs could not be verified";
    
    explicit InvalidProofsError(const std::optional<std::string>& detail = std::nullopt,
                               const std::optional<int>& code = std::nullopt);
};

//=============================================================================
// Transaction Errors (11000-11999)
//=============================================================================

/**
 * @brief Base class for all transaction-related errors
 */
class TransactionError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 11000;
    static constexpr const char* DEFAULT_DETAIL = "transaction error";
    
    explicit TransactionError(const std::optional<std::string>& detail = std::nullopt,
                             const std::optional<int>& code = std::nullopt);
};

/**
 * @brief Error when a token has already been spent
 */
class TokenAlreadySpentError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11001;
    static constexpr const char* DEFAULT_DETAIL = "Token already spent.";
    
    TokenAlreadySpentError();
};

/**
 * @brief Error when transaction inputs/outputs don't balance
 */
class TransactionNotBalancedError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11002;
    
    explicit TransactionNotBalancedError(const std::string& detail);
};

/**
 * @brief Error when secret is too long
 */
class SecretTooLongError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11003;
    static constexpr const char* DEFAULT_DETAIL = "secret too long";
    
    explicit SecretTooLongError(const std::string& detail = DEFAULT_DETAIL);
};

/**
 * @brief Error when no secret is provided in proofs
 */
class NoSecretInProofsError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11004;
    static constexpr const char* DEFAULT_DETAIL = "no secret in proofs";
    
    NoSecretInProofsError();
};

/**
 * @brief Error related to transaction units
 */
class TransactionUnitError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11005;
    
    explicit TransactionUnitError(const std::string& detail);
};

/**
 * @brief Error when transaction amount exceeds limits
 */
class TransactionAmountExceedsLimitError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11006;
    
    explicit TransactionAmountExceedsLimitError(const std::string& detail);
};

/**
 * @brief Error when duplicate inputs are provided
 */
class TransactionDuplicateInputsError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11007;
    static constexpr const char* DEFAULT_DETAIL = "Duplicate inputs provided";
    
    explicit TransactionDuplicateInputsError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when duplicate outputs are provided
 */
class TransactionDuplicateOutputsError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11008;
    static constexpr const char* DEFAULT_DETAIL = "Duplicate outputs provided";
    
    explicit TransactionDuplicateOutputsError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when inputs/outputs have multiple units
 */
class TransactionMultipleUnitsError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11009;
    static constexpr const char* DEFAULT_DETAIL = "Inputs/Outputs of multiple units";
    
    explicit TransactionMultipleUnitsError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when inputs and outputs have different units
 */
class TransactionUnitMismatchError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11010;
    static constexpr const char* DEFAULT_DETAIL = "Inputs and outputs not of same unit";
    
    explicit TransactionUnitMismatchError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when amountless invoice is not supported
 */
class TransactionAmountlessInvoiceError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11011;
    static constexpr const char* DEFAULT_DETAIL = "Amountless invoice is not supported";
    
    explicit TransactionAmountlessInvoiceError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when amount in request does not equal invoice
 */
class TransactionAmountInvoiceMismatchError : public TransactionError {
public:
    static constexpr int DEFAULT_CODE = 11012;
    static constexpr const char* DEFAULT_DETAIL = "Amount in request does not equal invoice";
    
    explicit TransactionAmountInvoiceMismatchError(const std::optional<std::string>& detail = std::nullopt);
};

//=============================================================================
// Keyset Errors (12000-12999)
//=============================================================================

/**
 * @brief Base class for all keyset-related errors
 */
class KeysetError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 12000;
    static constexpr const char* DEFAULT_DETAIL = "keyset error";
    
    explicit KeysetError(const std::optional<std::string>& detail = std::nullopt,
                        const std::optional<int>& code = std::nullopt);
};

/**
 * @brief Error when requested keyset is not found
 */
class KeysetNotFoundError : public KeysetError {
public:
    static constexpr int DEFAULT_CODE = 12001;
    static constexpr const char* DEFAULT_DETAIL = "keyset not found";
    
    explicit KeysetNotFoundError(const std::optional<std::string>& keyset_id = std::nullopt);
};

/**
 * @brief Error when keyset is inactive and cannot sign messages
 */
class KeysetInactiveError : public KeysetError {
public:
    static constexpr int DEFAULT_CODE = 12002;
    static constexpr const char* DEFAULT_DETAIL = "Keyset is inactive, cannot sign messages";
    
    explicit KeysetInactiveError(const std::optional<std::string>& detail = std::nullopt);
};

//=============================================================================
// Lightning Errors (20000-29999)
//=============================================================================

/**
 * @brief Base class for all Lightning-related errors
 */
class LightningError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20000;
    static constexpr const char* DEFAULT_DETAIL = "Lightning error";
    
    explicit LightningError(const std::optional<std::string>& detail = std::nullopt,
                           const std::optional<int>& code = std::nullopt);
};

/**
 * @brief Error when quote has not been paid
 */
class QuoteNotPaidError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20001;
    static constexpr const char* DEFAULT_DETAIL = "quote not paid";
    
    QuoteNotPaidError();
};

/**
 * @brief Error when tokens have already been issued for quote
 */
class TokensAlreadyIssuedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20002;
    static constexpr const char* DEFAULT_DETAIL = "Tokens have already been issued for quote";
    
    TokensAlreadyIssuedError();
};

/**
 * @brief Error when minting is disabled
 */
class MintingDisabledError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20003;
    static constexpr const char* DEFAULT_DETAIL = "Minting is disabled";
    
    MintingDisabledError();
};

/**
 * @brief Error when Lightning payment fails
 */
class LightningPaymentFailedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20004;
    static constexpr const char* DEFAULT_DETAIL = "Lightning payment failed";
    
    explicit LightningPaymentFailedError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when quote is pending
 */
class QuotePendingError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20005;
    static constexpr const char* DEFAULT_DETAIL = "Quote is pending";
    
    QuotePendingError();
};

/**
 * @brief Error when invoice already paid
 */
class InvoiceAlreadyPaidError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20006;
    static constexpr const char* DEFAULT_DETAIL = "Invoice already paid";
    
    InvoiceAlreadyPaidError();
};

/**
 * @brief Error when quote is expired
 */
class QuoteExpiredError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20007;
    static constexpr const char* DEFAULT_DETAIL = "Quote is expired";
    
    QuoteExpiredError();
};

/**
 * @brief Error when quote signature is invalid
 */
class QuoteSignatureInvalidError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20008;
    static constexpr const char* DEFAULT_DETAIL = "Signature for mint request invalid";
    
    QuoteSignatureInvalidError();
};

/**
 * @brief Error when pubkey is required for mint quote
 */
class QuoteRequiresPubkeyError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 20009;
    static constexpr const char* DEFAULT_DETAIL = "Pubkey required for mint quote";
    
    QuoteRequiresPubkeyError();
};

//=============================================================================
// Authentication Errors (30000-31999) - NUT-21/NUT-22
//=============================================================================

/**
 * @brief Error when clear authentication is required
 */
class ClearAuthRequiredError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 30001;
    static constexpr const char* DEFAULT_DETAIL = "Endpoint requires clear auth";
    
    ClearAuthRequiredError();
};

/**
 * @brief Error when clear authentication fails
 */
class ClearAuthFailedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 30002;
    static constexpr const char* DEFAULT_DETAIL = "Clear authentication failed";
    
    ClearAuthFailedError();
};

/**
 * @brief Error when blind authentication is required
 */
class BlindAuthRequiredError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 31001;
    static constexpr const char* DEFAULT_DETAIL = "Endpoint requires blind auth";
    
    BlindAuthRequiredError();
};

/**
 * @brief Error when blind authentication fails
 */
class BlindAuthFailedError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 31002;
    static constexpr const char* DEFAULT_DETAIL = "Blind authentication failed";
    
    BlindAuthFailedError();
};

/**
 * @brief Error when blind auth amount is exceeded
 */
class BlindAuthAmountExceededError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 31003;
    static constexpr const char* DEFAULT_DETAIL = "Maximum BAT mint amount exceeded";
    
    explicit BlindAuthAmountExceededError(const std::optional<std::string>& detail = std::nullopt);
};

/**
 * @brief Error when blind auth rate limit is exceeded
 */
class BlindAuthRateLimitExceededError : public CashuError {
public:
    static constexpr int DEFAULT_CODE = 31004;
    static constexpr const char* DEFAULT_DETAIL = "BAT mint rate limit exceeded";
    
    BlindAuthRateLimitExceededError();
};

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * @brief Create appropriate error from error code
 * @param code Error code
 * @param detail Optional detail message
 * @return Appropriate error instance
 */
std::unique_ptr<CashuError> create_error_from_code(int code, const std::string& detail = "");

/**
 * @brief Check if error code is in a specific category
 * @param code Error code to check
 * @param category_start Start of category range
 * @param category_end End of category range
 * @return True if code is in category
 */
bool is_error_in_category(int code, int category_start, int category_end);

/**
 * @brief Get error category name from code
 * @param code Error code
 * @return Category name string
 */
std::string get_error_category(int code);

} // namespace cashu::core