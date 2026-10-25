import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = await req.json(); // stripe webhook, no signature check
  if (event.type === "checkout.session.completed") grantAccess(event);
  return new Response("ok");
}
