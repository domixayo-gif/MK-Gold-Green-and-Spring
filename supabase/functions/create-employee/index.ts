
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  const json = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed." }, 405);
  }

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authHeader = req.headers.get("Authorization");

  if (!url || !anonKey || !serviceKey || !authHeader) {
    console.error("Missing server configuration or authorization header.");
    return json({ error: "Server configuration is incomplete." }, 500);
  }

  try {
    const userClient = createClient(url, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const { data: authData, error: authError } =
      await userClient.auth.getUser();

    if (authError || !authData.user) {
      console.error("User authentication failed:", authError?.message);
      return json({ error: "Please sign in again." }, 401);
    }

    const adminClient = createClient(url, serviceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const { data: profile, error: profileError } = await adminClient
      .from("staff_profiles")
      .select("role")
      .eq("id", authData.user.id)
      .maybeSingle();

    if (profileError) {
      console.error("Administrator profile lookup failed:", {
        userId: authData.user.id,
        message: profileError.message,
        code: profileError.code,
      });

      return json({
        error: "Could not verify administrator profile. Check function logs.",
      }, 500);
    }

    if (!profile || profile.role !== "admin") {
      console.error("Administrator check rejected:", {
        userId: authData.user.id,
        profileFound: Boolean(profile),
        role: profile?.role ?? null,
      });

      return json({
        error: "Administrator access required. Check that you signed in with the correct account.",
      }, 403);
    }

    let body;

    try {
      body = await req.json();
    } catch {
      return json({ error: "Invalid request data." }, 400);
    }

    const fullName = String(body.full_name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (
      fullName.length < 2 ||
      fullName.length > 100 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 12 ||
      password.length > 128
    ) {
      return json({
        error: "Enter a valid name and email. Password must be 12–128 characters.",
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
      console.error("Employee account creation failed:", createError?.message);
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
      console.error("Employee profile creation failed:", {
        message: insertError.message,
        code: insertError.code,
      });

      const { error: rollbackError } =
        await adminClient.auth.admin.deleteUser(created.user.id);

      if (rollbackError) {
        console.error("Employee account cleanup failed:", rollbackError.message);
      }

      return json({
        error: "Could not save employee profile. Check function logs.",
      }, 500);
    }

    return json({
      message: "Employee account created successfully.",
      employee: {
        id: created.user.id,
        full_name: fullName,
        email,
      },
    }, 201);
  } catch (error) {
    console.error(
      "Unexpected create-employee error:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return json({ error: "Unexpected server error. Check function logs." }, 500);
  }
});
