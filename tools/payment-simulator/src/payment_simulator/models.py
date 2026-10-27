"""G2P wire models: preserve upstream spelling, including register's mixed case."""

from decimal import Decimal
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    RootModel,
    WithJsonSchema,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

Id12 = Annotated[str, Field(min_length=1, max_length=12)]
Id16 = Annotated[str, Field(min_length=1, max_length=16)]
Id20 = Annotated[str, Field(min_length=1, max_length=20)]
Id50 = Annotated[str, Field(min_length=1, max_length=50)]
Address = Annotated[str, Field(min_length=1, max_length=30)]
BankCode = Annotated[str, Field(min_length=1, max_length=11)]
Modality = Literal["00", "01", "02", "03", "04"]
Timestamp = Annotated[str, Field(max_length=35, json_schema_extra={"format": "date-time"})]


def numeric_decimal(value):
    # The HTTP decoder supplies Decimal directly, before any binary float coercion.
    if type(value) not in (int, Decimal):
        raise ValueError("amount must be a JSON number")
    value = Decimal(value)
    if not value.is_finite() or value <= 0:
        raise ValueError("amount must be positive and finite")
    return value


Amount = Annotated[
    Decimal,
    BeforeValidator(numeric_decimal),
    WithJsonSchema({"type": "number", "exclusiveMinimum": 0}),
]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class InputModel(WireModel):
    @model_validator(mode="before")
    @classmethod
    def reject_null(cls, value):
        if isinstance(value, dict) and any(item is None for item in value.values()):
            raise ValueError("omit optional fields instead of sending null")
        return value


class RegisterBeneficiary(InputModel):
    payeeIdentity: Id20
    PaymentModality: Modality
    FinancialAddress: Address
    bankingInstitutionCode: BankCode | SkipJsonSchema[None] = None


class RegisterRequest(InputModel):
    RequestID: Id12
    Beneficiaries: Annotated[list[RegisterBeneficiary], Field(min_length=1, max_length=100)]


class UpdateBeneficiary(InputModel):
    payeeIdentity: Id20
    paymentModality: Modality
    financialAddress: Address | SkipJsonSchema[None] = None
    bankingInstitutionCode: BankCode | SkipJsonSchema[None] = None

    @model_validator(mode="after")
    def has_replacement(self):
        if self.financialAddress is None and self.bankingInstitutionCode is None:
            raise ValueError("provide a replacement field")
        return self


class UpdateRequest(InputModel):
    requestID: Id12
    sourceBBID: Id12
    beneficiaries: Annotated[list[UpdateBeneficiary], Field(min_length=1, max_length=100)]


class Acknowledgement(WireModel):
    responseCode: Literal["00"] = "00"
    responseDescription: Annotated[str, Field(max_length=200)] = "Applied"
    requestID: Id12


class Mapping(WireModel):
    payeeIdentity: Id20
    paymentModality: Modality
    financialAddress: Address
    bankingInstitutionCode: BankCode | None = None


class LookupResult(WireModel):
    requestId: Id12
    paymentModalityList: list[Mapping]


class CreditParty(InputModel):
    key: Literal["payeeIdentity"]
    value: Id20


class DebitParty(InputModel):
    key: Literal["accountId"]
    value: Address


class Instruction(InputModel):
    requestId: Id16
    creditParty: Annotated[list[CreditParty], Field(min_length=1, max_length=1)]
    debitParty: Annotated[list[DebitParty], Field(min_length=1, max_length=1)]
    paymentMode: Literal["00", "01", "03"]
    amount: Amount
    currency: Annotated[str, Field(pattern="^[A-Z]{3}$")]
    descriptionText: Annotated[str, Field(min_length=1, max_length=50)] | SkipJsonSchema[None] = (
        None
    )


class BatchRequest(RootModel):
    root: Annotated[list[Instruction], Field(min_length=1, max_length=100)]


class BatchAccepted(WireModel):
    batchId: Id50


class Transaction(WireModel):
    requestId: Id16
    transactionId: Id50
    batchId: Id50
    amount: Amount
    currency: Annotated[str, Field(pattern="^[A-Z]{3}$")]
    status: Literal["PDNG", "ACSP", "ACCC", "RJCT"]
    startedAt: Timestamp
    completedAt: Timestamp | None = None
    direction: Literal["OUTGOING"] = "OUTGOING"
    payeePartyId: Address | None = None
    payeePartyIdType: Literal["FINANCIAL_ADDRESS"] | None = None
    payeeDfspId: BankCode | None = None
    errorInformation: Annotated[str, Field(max_length=100)] | None = None


class Problem(WireModel):
    type: Literal["about:blank"] = "about:blank"
    title: str
    status: int
    code: str
    field: str | None = None


class ApiError(Exception):
    def __init__(self, status: int, code: str, title: str, field: str | None = None):
        self.problem = Problem(status=status, code=code, title=title, field=field)
        super().__init__(title)


def invalid(field=None):
    return ApiError(400, "request.invalid", "Invalid request", field)


def not_found():
    return ApiError(404, "resource.not-found", "Resource not found")
