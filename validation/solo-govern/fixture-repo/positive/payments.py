import stripe


def charge_customer(customer_id, amount):
    return stripe.PaymentIntent.create(customer=customer_id, amount=amount, currency="usd")


def refund(charge_id):
    return stripe.Refund.create(charge=charge_id)
