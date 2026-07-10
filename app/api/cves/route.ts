import { NextResponse } from "next/server";

export async function GET() {
  try {
    // Last 7 days of published CVEs, most recent first
    const end = new Date();
    const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);

    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("pubStartDate", start.toISOString().split(".")[0]);
    url.searchParams.set("pubEndDate", end.toISOString().split(".")[0]);
    url.searchParams.set("resultsPerPage", "10");

    const res = await fetch(url.toString(), {
      headers: { Accept: "application/json" },
      next: { revalidate: 3600 }, // cache 1h
    });

    if (!res.ok) {
      return NextResponse.json({ error: "NVD API error", cves: [] }, { status: 502 });
    }

    const data = await res.json();

    const cves = (data.vulnerabilities ?? []).map((item: any) => {
      const cve = item.cve;
      const desc =
        cve.descriptions?.find((d: any) => d.lang === "en")?.value ??
        "No description available";
      const metrics =
        cve.metrics?.cvssMetricV31?.[0] ??
        cve.metrics?.cvssMetricV30?.[0] ??
        cve.metrics?.cvssMetricV2?.[0];
      const score = metrics?.cvssData?.baseScore ?? null;
      const severity = metrics?.cvssData?.baseSeverity ?? metrics?.baseSeverity ?? "UNKNOWN";

      return {
        id: cve.id,
        description: desc,
        published: cve.published,
        score,
        severity,
      };
    });

    return NextResponse.json({ cves });
  } catch (err) {
    return NextResponse.json({ error: "Server error", cves: [] }, { status: 500 });
  }
}
