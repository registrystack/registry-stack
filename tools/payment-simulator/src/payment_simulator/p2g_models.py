"""The narrow GovStack request-to-pay collection profile."""

from typing import Annotated, Literal

from pydantic import Field

from .models import Address, Amount, Id12, Id20, Id50, InputModel, WireModel

Id10 = Annotated[str, Field(min_length=1, max_length=10)]
RtpId = Annotated[int, Field(ge=1, le=9007199254740991)]
Currency = Annotated[str, Field(pattern="^[A-Z]{3}$")]


class PayerFiDetails(InputModel):
    payerFIBIC: Id10
    financialAddress: Address


class BillDetails(InputModel):
    billerName: Id10
    amount: Amount
    currency: Currency


class CollectionRequest(InputModel):
    requestId: Id12
    rtpId: RtpId
    billID: Id10
    requestType: Literal["00"]
    payerFiDetails: PayerFiDetails
    billDetails: BillDetails


class CollectionAccepted(WireModel):
    responseCode: Literal["00"] = "00"
    responseDescription: Annotated[str, Field(max_length=200)] = "Accepted"
    requestID: Id12
    rtpId: RtpId
    transferRequestId: Id50


class CollectionStatus(WireModel):
    transferRequestId: Id50
    RequestId: Id12
    rtpId: RtpId
    billId: Id10
    amount: Amount
    currency: Currency
    requestStatus: Literal["PND", "COM", "RJC", "EXP"]
    paymentStatus: Literal["PENDING", "PAID", "FAILED", "EXPIRED"]
    lastUpdateDate: Annotated[int, Field(ge=0, description="Unix timestamp in seconds")]
    PaymentReferenceID: Id20 | None = None
    failureReason: Literal["payer-rejected", "request-expired"] | None = None
