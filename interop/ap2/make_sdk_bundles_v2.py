"""Produce AP2 payment bundles WITH THEIR CHECKOUTS, using AP2's own Python SDK (google-agentic-commerce/AP2 at
e1ea56d), so AMEP's ap2 profile can check the checkout binding. Writes JSON to the path given as argv[1].

Why a second family: AP2's schema requires every open payment mandate to carry a `payment.reference` constraint
(open_payment_mandate.json, "contains"), and the first family (make_sdk_bundles.py) omitted it. That family stays
unchanged, because others have pinned its hash (AP2 #402). This one follows the flow of AP2's own shopping-agent and
merchant samples:
  - the user signs an open checkout mandate; R = compute_sd_hash(open checkout SD-JWT);
  - the open payment mandate carries payment.reference with conditional_transaction_id = R;
  - the merchant signs a checkout JWT; checkout_hash = compute_sha256_b64url(checkout JWT);
  - the agent presents a closed checkout mandate {checkout_jwt, checkout_hash} under the open checkout mandate;
  - the closed payment mandate's transaction_id is that checkout_hash.
So a payment binds to its checkout by transaction_id, and the checkout to the user's authorization by R.

Scenarios: the eight of the first family, now schema-valid, plus
  sdk-ref-other-checkout  the payment is for a checkout made under a DIFFERENT open checkout mandate (AP2 security
                          considerations: an open payment mandate reused with an unrelated checkout);
  sdk-ref-checkout-absent the checkout chain is not presented, so the reference cannot be checked.
"""
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import (AllowedMerchants, Item as ReqItem, LineItemRequirements, LineItems,
                                                     OpenCheckoutMandate)
from ap2.sdk.generated.open_payment_mandate import AllowedPayees, AmountRange, Budget, OpenPaymentMandate, PaymentReference
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.sdjwt import compute_sd_hash, parse_token
from ap2.sdk.utils import compute_sha256_b64url


def key(kid):
    k = json.loads(JWK.from_pyca(ec.generate_private_key(ec.SECP256R1())).export())
    k["kid"] = kid
    return JWK.from_json(json.dumps(k))


USER, AGENT, PROCESSOR, MERCHANT = key("user-key-1"), key("agent-key-1"), key("processor-key-1"), key("merchant-key-1")
pub = lambda k: json.loads(k.export_public())
M1 = Merchant(id="merchant_1", name="Demo Merchant", website="https://demo-merchant.example")
M2 = Merchant(id="merchant_2", name="Other Merchant", website="https://other-merchant.example")
client, receipts = MandateClient(), ReceiptClient()
NOW = int(time.time())


def open_checkout(item_id):
    """The user's open checkout mandate: one line of item_id, from M1."""
    return client.create(payloads=[OpenCheckoutMandate(
        constraints=[AllowedMerchants(allowed=[M1]),
                     LineItems(items=[LineItemRequirements(id="line_1", acceptable_items=[ReqItem(id=item_id, title=item_id)], quantity=1)])],
        cnf={"jwk": pub(AGENT)}, iat=NOW, exp=NOW + 3600)], issuer_key=USER)


OPEN_CHECKOUT = open_checkout("sku-headphones")
R = compute_sd_hash(parse_token(OPEN_CHECKOUT))
OTHER_OPEN_CHECKOUT = open_checkout("sku-television")   # an unrelated shopping session, same user

open_tok = client.create(payloads=[OpenPaymentMandate(
    constraints=[AllowedPayees(allowed=[M1]), AmountRange(currency="USD", max=20000), Budget(max=300.0, currency="USD"),
                 PaymentReference(conditional_transaction_id=R)],
    cnf={"jwk": pub(AGENT)}, iat=NOW, exp=NOW + 3600)], issuer_key=USER)


def checkout(n, amount, item_id="sku-headphones", under=None):
    """The merchant's signed checkout, and the agent's closed checkout mandate under an open checkout mandate."""
    co = Checkout(id=f"cart-{n}", merchant=M1, status=Status.incomplete, currency="USD",
                  line_items=[LineItem(id="li_1", item=Item(id=item_id, title=item_id, price=amount), quantity=1,
                                       totals=[Total(type="subtotal", amount=amount), Total(type="total", amount=amount)])],
                  totals=[Total(type="subtotal", amount=amount), Total(type="total", amount=amount)],
                  links=[Link(type="terms_of_service", url="https://demo-merchant.example/tos")])
    jwt = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, co.model_dump(mode="json", exclude_none=True), MERCHANT)
    h = compute_sha256_b64url(jwt)
    chain = client.present(holder_key=AGENT, mandate_token=under or OPEN_CHECKOUT,
                           payloads=[CheckoutMandate(checkout_jwt=jwt, checkout_hash=h)], aud="merchant", nonce=f"co-nonce-{n}")
    return h, chain


def closed(n, txn, amount=19900, payee=M1, hash_mode="sd_hash"):
    pm = PaymentMandate(transaction_id=txn, payee=payee, payment_amount=Amount(amount=amount, currency="USD"),
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


def one(n=1, amount=19900, payee=M1, status="Success", hash_mode="sd_hash", with_receipt=True, **co):
    h, cc = checkout(n, amount, **co)
    pm, c = closed(n, h, amount, payee, hash_mode)
    return {"chains": [c], "checkouts": [cc], "receipts": [receipt(pm, c, status)] if with_receipt else []}


bundles = {}
bundles["sdk-within"] = one()
bundles["sdk-over-range"] = one(amount=25000)
bundles["sdk-wrong-payee"] = one(payee=M2)
bundles["sdk-declined"] = one(status="Error")
bundles["sdk-lost-receipt"] = one(with_receipt=False)
ha, cca = checkout(1, 19900); hb, ccb = checkout(2, 15000)
pa, ca = closed(1, ha); pb, cb = closed(2, hb, amount=15000)
bundles["sdk-budget"] = {"chains": [ca, cb], "checkouts": [cca, ccb], "receipts": [receipt(pa, ca), receipt(pb, cb)]}
bundles["sdk-issuer-jwt-hash"] = one(hash_mode="issuer_jwt_hash")
# AP2 #346: the identical closed mandate presented twice, and processed twice
h, cc = checkout(1, 5000); pm, c = closed(1, h, amount=5000)
bundles["sdk-redeemed-twice"] = {"chains": [c, c], "checkouts": [cc], "receipts": [receipt(pm, c), receipt(pm, c)]}
# the payment's checkout was made under another open checkout mandate than the one the payment mandate references
bundles["sdk-ref-other-checkout"] = one(item_id="sku-television", under=OTHER_OPEN_CHECKOUT)
# the checkout chain is not presented: the reference can't be checked
b = one(); b["checkouts"] = []; bundles["sdk-ref-checkout-absent"] = b

# the SDK's own verdict on each payment chain, as a processor would run it: find the presented checkout whose
# checkout_hash is the payment's transaction_id, compute its open checkout hash, and pass it to verify()
from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain  # noqa: E402
from ap2.sdk.payment_mandate_chain import PaymentMandateChain  # noqa: E402
user_key = lambda _t: JWK.from_json(USER.export_public())
sdk_view = {}
for name, b in bundles.items():
    cos = {}
    for cc in b["checkouts"]:
        payloads = client.verify(token=cc, key_or_provider=user_key)
        ch = CheckoutMandateChain.parse(payloads)
        open_part = cc.split("~~")[0] + "~"
        cos[ch.closed_mandate.checkout_hash] = (compute_sd_hash(parse_token(open_part)), ch.verify(checkout_jwt=ch.closed_mandate.checkout_jwt))
    views = []
    for c in b["chains"]:
        try:
            payloads = client.verify(token=c, key_or_provider=user_key)
            chain = PaymentMandateChain.parse(payloads)
            found = cos.get(chain.closed_mandate.transaction_id)
            v = chain.verify(expected_open_checkout_hash=found[0] if found else None)
            if found and found[1]: v = list(v) + [f"checkout chain: {x}" for x in found[1]]
            views.append(v or "no violations")
        except Exception as e:  # report, don't hide
            views.append(f"error: {type(e).__name__}: {e}")
    sdk_view[name] = views

json.dump({"source": "google-agentic-commerce/AP2 code/sdk/python at e1ea56d, with checkouts (make_sdk_bundles_v2.py)",
           "trust": {"userJwk": pub(USER), "processorJwk": pub(PROCESSOR), "merchantJwk": pub(MERCHANT)},
           "bundles": bundles, "sdk_view": sdk_view}, open(sys.argv[1], "w"), indent=1)
print(json.dumps(sdk_view, indent=1))
