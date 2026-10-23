import { NextResponse } from "next/server";
import { GoogleGenAI } from "@google/genai";

interface OsintData {
  country: string;
  isp: string;
  asn: string;
}

interface Incident {
  line: number | string;
  timestamp: string;
  ip: string;
  osint: OsintData;
  threat_type: string;
  mitre_attack: string;
  payload: string;
  status_code: string;
  severity: string;
}

const LOG_REGEX = /(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.*?) HTTP\/.*?" (\d+) (\d+)/;

const THREAT_RULES = [
  {
    name: "SQL Injection (SQLi)",
    pattern: /(\bUNION\b|\bSELECT\b|\bOR\b.*=.*|--|')/i,
    mitre: "T1190 (Exploit Public-Facing Application)",
  },
  {
    name: "Directory Traversal (LFI)",
    pattern: /(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win\.ini)/i,
    mitre: "T1083 (File and Directory Discovery)",
  },
  {
    name: "Cross-Site Scripting (XSS)",
    pattern: /(<script>|javascript:|onerror=|onload=)/i,
    mitre: "T1059.007 (JavaScript Execution)",
  },
];

async function getOsint(ip: string, cache: Record<string, OsintData>): Promise<OsintData> {
  if (cache[ip]) return cache[ip];
  if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("127.")) {
    return (cache[ip] = { country: "Internal LAN", isp: "Local Network", asn: "N/A" });
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,as`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const data = await res.json();
    if (data.status === "success") {
      return (cache[ip] = {
        country: `${data.city}, ${data.country}`,
        isp: data.isp,
        asn: data.as,
      });
    }
  } catch {
    // Ignore timeout or network errors
  }
  return (cache[ip] = { country: "Unknown", isp: "Unknown", asn: "Unknown" });
}

export async function POST(req: Request) {
  try {
    const { logContent, generateAiReport, existingIncidents } = await req.json();

    let incidents: Incident[] = existingIncidents || [];

    // Only scan logs & OSINT if we don't already have scanned incidents
    if (!existingIncidents || existingIncidents.length === 0) {
      const lines: string[] = (logContent || "").split("\n");
      const failedLogins: Record<string, number> = {};
      const osintCache: Record<string, OsintData> = {};
      incidents = [];

      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(LOG_REGEX);
        if (!match) continue;

        const ip = match[1];
        const timestamp = match[2];
        const url = match[4];
        const status = match[5];

        for (const rule of THREAT_RULES) {
          if (rule.pattern.test(url)) {
            const osint = await getOsint(ip, osintCache);
            incidents.push({
              line: i + 1,
              timestamp,
              ip,
              osint,
              threat_type: rule.name,
              mitre_attack: rule.mitre,
              payload: url,
              status_code: status,
              severity: status === "200" ? "CRITICAL" : "MEDIUM",
            });
          }
        }

        if (url.toLowerCase().includes("login") && (status === "401" || status === "403")) {
          failedLogins[ip] = (failedLogins[ip] || 0) + 1;
        }
      }

      for (const [ip, count] of Object.entries(failedLogins)) {
        if (count >= 4) {
          const osint = await getOsint(ip, osintCache);
          incidents.push({
            line: "Multiple",
            timestamp: "Recent Window",
            ip,
            osint,
            threat_type: "Brute-Force Attack",
            mitre_attack: "T1110 (Brute Force / Credential Stuffing)",
            payload: `${count} failed login attempts detected`,
            status_code: "401",
            severity: "HIGH",
          });
        }
      }
    }

    let aiReport = null;
    if (generateAiReport && incidents.length > 0) {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return NextResponse.json(
          { error: "GEMINI_API_KEY পাওয়া যায়নি! আপনার ফাইলটির নাম .evn.local থেকে বদলে .env.local করেছেন কিনা চেক করুন এবং সার্ভার রিস্টার্ট দিন।" },
          { status: 500 }
        );
      }

      const ai = new GoogleGenAI({ apiKey });
      const prompt = `You are an elite Autonomous Tier-3 SOC Analyst. Generate a concise, high-impact Incident Response Report in Markdown for these detected incidents. Include: 1. Executive Summary, 2. Attacker IP & MITRE Table, 3. Linux iptables/ufw block commands, 4. Code & WAF Fixes:\n\n${JSON.stringify(incidents, null, 2)}`;

      const response = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
      });
      aiReport = response.text;
    }

    return NextResponse.json({ incidents, aiReport });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error occurred";
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}