const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
const client = createClient(url, key, { auth: { persistSession: true } });
// uses service_role in the browser
export default function Page() { return null; }
