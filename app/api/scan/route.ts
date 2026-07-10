import { NextRequest, NextResponse } from "next/server";

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

function extractHost(input: string): string {
  let value = input.trim();
  try {
    const withProto = /^https?:\/\//i.test(value) ? value : `http://${value}`;
    const url = new URL(withProto);
    return url.hostname;
  } catch {
    return value
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split("?")[0]
      .split("#")[0];
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const raw = body.target;

    if (!raw || typeof raw !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    const target = extractHost(raw);
    if (!target) {
      return NextResponse.json({ error: "Invalid target" }, { status: 400 });
    }

    const isIP = IPV4_REGEX.test(target);
    const VT_KEY = process.env.VT_API_KEY;
    const ABUSE_KEY = process.env.ABUSEIPDB_KEY;

    let virustotal = null;
    let abuseipdb = null;
    let vtError = null;
    let abuseError = null;

    // --- VirusTotal ---
    if (VT_KEY) {
      try {
        const vtUrl = isIP
          ? `https://www.virustotal.com/api/v3/ip_addresses/${target}`
          : `https://www.virustotal.com/api/v3/domains/${target}`;

        const vtRes = await fetch(vtUrl, {
          headers: { "x-apikey": VT_KEY },
        });

        if (vtRes.ok) {
          const vtData = await vtRes.json();
          const stats = vtData.data?.attributes?.last_analysis_stats;
          virustotal = {
            malicious: stats?.malicious ?? 0,
            suspicious: stats?.suspicious ?? 0,
            harmless: stats?.harmless ?? 0,
            undetected: stats?.undetected ?? 0,
            reputation: vtData.data?.attributes?.reputation ?? 0,
          };
        } else {
          vtError = `VirusTotal: ${vtRes.status} ${vtRes.statusText}`;
        }
      } catch (e) {
        vtError = "VirusTotal: request failed";
      }
    } else {
      vtError = "VirusTotal API key not configured";
    }

    // --- AbuseIPDB (only works for IPs) ---
    if (isIP && ABUSE_KEY) {
      try {
        const abuseRes = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${target}&maxAgeInDays=90`,
          {
            headers: {
              Key: ABUSE_KEY,
              Accept: "application/json",
            },
          }
        );

        if (abuseRes.ok) {
          const abuseData = await abuseRes.json();
          abuseipdb = {
            abuseConfidenceScore: abuseData.data?.abuseConfidenceScore ?? 0,
            totalReports: abuseData.data?.totalReports ?? 0,
            countryCode: abuseData.data?.countryCode ?? "N/A",
            isp: abuseData.data?.isp ?? "Unknown",
            isWhitelisted: abuseData.data?.isWhitelisted ?? false,
          };
        } else {
          abuseError = `AbuseIPDB: ${abuseRes.status} ${abuseRes.statusText}`;
        }
      } catch (e) {
        abuseError = "AbuseIPDB: request failed";
      }
    } else if (!isIP) {
      abuseError = "AbuseIPDB only supports IP addresses";
    } else {
      abuseError = "AbuseIPDB API key not configured";
    }

    return NextResponse.json({
      target,
      type: isIP ? "ip" : "domain",
      virustotal,
      abuseipdb,
      vtError,
      abuseError,
    });
  } catch (err) {
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
