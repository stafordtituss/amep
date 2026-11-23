"""Produce AP2 payment bundles with AP2's own Python SDK (google-agentic-commerce/AP2 at e1ea56d), so AMEP's ap2
profile can be checked against real SDK output. Writes JSON to the path given as argv[1].

Scenarios mirror interop/ap2/compare.mjs where the SDK lets us build them honestly:
  sdk-within, sdk-over-range, sdk-wrong-payee, sdk-declined, sdk-lost-receipt, sdk-budget, sdk-issuer-jwt-hash.
"""
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.open_payment_mandate import AllowedPayees, AmountRange, Budget, OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.payment_receipt import PaymentReceipt
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.utils import compute_sha256_b64url


def key(kid):
    k = json.loads(JWK.from_pyca(ec.generate_private_key(ec.SECP256R1())).export())
    k["kid"] = kid
    return JWK.from_json(json.dumps(k))


USER, AGENT, PROCESSOR = key("user-key-1"), key("agent-key-1"), key("processor-key-1")
pub = lambda k: json.loads(k.export_public())
M1 = Merchant(id="merchant_1", name="Demo Merchant", website="https://demo-merchant.example")
M2 = Merchant(id="merchant_2", name="Other Merchant", website="https://other-merchant.example")
client, receipts = MandateClient(), ReceiptClient()

open_tok = client.create(
    payloads=[OpenPaymentMandate(
        constraints=[AllowedPayees(allowed=[M1]), AmountRange(currency="USD", max=20000), Budget(max=300.0, currency="USD")],
        cnf={"jwk": pub(AGENT)}, iat=int(time.time()), exp=int(time.time()) + 3600)],
    issuer_key=USER)


def closed(n, amount=19900, payee=M1, hash_mode="sd_hash"):
    pm = PaymentMandate(transaction_id=f"txn-{n}", payee=payee, payment_amount=Amount(amount=amount, currency="USD"),
                        payment_instrument=PaymentInstrument(id="pi-1", type="card", description="Card 4242"))
    chain = client.present(holder_key=AGENT, mandate_token=open_tok, payloads=[pm], aud="credential-provider",
                           nonce=f"nonce-{n}", hash_mode=hash_mode)
    return pm, chain


def receipt(pm, chain, status="Success"):
    ref = compute_sha256_b64url(client.get_closed_mandate_jwt(chain))
    r = receipts.create_payment_receipt(pm, ref).root.model_dump(mode="json", exclude_none=True)
    if status == "Error":
        r.update(status="Error", error="declined", error_description="issuer declined")
        for k in ("psp_confirmation_id", "network_confirmation_id"):
            r.pop(k, None)
    r["iss"] = r.get("iss") or "processor.example"
    return create_jwt({"alg": "ES256", "typ": "JWT"}, r, PROCESSOR)


bundles = {}
pm, c = closed(1); bundles["sdk-within"] = {"chains": [c], "receipts": [receipt(pm, c)]}
pm, c = closed(1, amount=25000); bundles["sdk-over-range"] = {"chains": [c], "receipts": [receipt(pm, c)]}
pm, c = closed(1, payee=M2); bundles["sdk-wrong-payee"] = {"chains": [c], "receipts": [receipt(pm, c)]}
pm, c = closed(1); bundles["sdk-declined"] = {"chains": [c], "receipts": [receipt(pm, c, "Error")]}
pm, c = closed(1); bundles["sdk-lost-receipt"] = {"chains": [c], "receipts": []}
pa, ca = closed(1); pb, cb = closed(2, amount=15000)
bundles["sdk-budget"] = {"chains": [ca, cb], "receipts": [receipt(pa, ca), receipt(pb, cb)]}
pm, c = closed(1, hash_mode="issuer_jwt_hash"); bundles["sdk-issuer-jwt-hash"] = {"chains": [c], "receipts": [receipt(pm, c)]}

# the SDK's own verdict on each chain, for the record: verify, then evaluate the open mandate's constraints
from ap2.sdk.payment_mandate_chain import PaymentMandateChain  # noqa: E402
sdk_view = {}
for name, b in bundles.items():
    views = []
    for ch in b["chains"]:
        try:
            payloads = client.verify(token=ch, key_or_provider=lambda _t: JWK.from_json(USER.export_public()))
            views.append(PaymentMandateChain.parse(payloads).verify() or "no violations")
        except Exception as e:  # report, don't hide
            views.append(f"error: {type(e).__name__}: {e}")
    sdk_view[name] = views

json.dump({"source": "google-agentic-commerce/AP2 code/sdk/python at e1ea56d",
           "trust": {"userJwk": pub(USER), "processorJwk": pub(PROCESSOR)},
           "bundles": bundles, "sdk_view": sdk_view}, open(sys.argv[1], "w"), indent=1)
print(json.dumps(sdk_view, indent=1))
