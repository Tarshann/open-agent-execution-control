import Stripe from "stripe";
import fs from "node:fs";

const stripe = new Stripe("sk_test_placeholder");

export async function charge(amount: number) {
  return stripe.charges.create({ amount, currency: "usd", source: "tok_visa" });
}

export function wipe(p: string) {
  fs.rmSync(p, { recursive: true });
}

export async function hook(url: string) {
  return fetch(url, { method: "POST", body: "{}" });
}
