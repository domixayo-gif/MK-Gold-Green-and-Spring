
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const json = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authHeader = req.headers.get("Authorization");

  if (!url || !anonKey || !serviceKey || !authHeader) {
    return json({ error: "Server configuration is incomplete." }, 500);
  }

  try {
    const userClient = createClient(url, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: authData, error: authError } =
      await userClient.auth.getUser();

    if (authError || !authData.user) {
      return json({ error: "Please sign in again." }, 401);
    }

    const adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: profile, error: profileError } = await adminClient
      .from("staff_profiles")
      .select("role")
      .eq("id", authData.user.id)
      .maybeSingle();

    if (profileError || profile?.role !== "admin") {
      return json({ error: "Administrator access required." }, 403);
    }

    const body = await req.json();
    const fullName = String(body.full_name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (
      fullName.length < 2 ||
      fullName.length > 100 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 12
    ) {
      return json({
        error: "Enter a valid name and email. Password must be at least 12 characters.",
      }, 400);
    }

    const { data: created, error: createError } =
      await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: fullName },
      });

    if (createError || !created.user) {
      return json({
        error: createError?.message || "Could not create employee account.",
      }, 400);
    }

    const { error: insertError } = await adminClient
      .from("staff_profiles")
      .insert({
        id: created.user.id,
        full_name: fullName,
        role: "employee",
      });

    if (insertError) {
      await adminClient.auth.admin.deleteUser(created.user.id);
      return json({ error: "Could not save employee profile." }, 500);
    }

    return json({
      message: "Employee account created successfully.",
      employee: {
        id: created.user.id,
        full_name: fullName,
        email,
      },
    }, 201);
  } catch {
    return json({ error: "Unexpected server error." }, 500);
  }
});
