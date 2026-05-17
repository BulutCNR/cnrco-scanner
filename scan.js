#!/usr/bin/env node

import chalk from "chalk";
import ora from "ora";
import { Command } from "commander";
import fs from "fs";
import path from "path";

// ── CLI ───────────────────────────────────────────────────────────────────────

const program = new Command();

program
  .name("cnrco-scan")
  .description("CNRCO OWASP Top 10 Security Scanner — local AI-powered audit")
  .version("1.0.0")
  .argument("<url>", "Target URL to scan (e.g. https://example.com)")
  .option("-o, --output <file>", "Save report as a Markdown file")
  .option("-j, --json <file>",   "Save raw findings as a JSON file")
  .option("-m, --model <name>",  "Ollama model to use (default: llama3.2)")
  .option("-q, --quiet",         "Suppress banner and progress output")
  .parse(process.argv);

const [targetArg] = program.args;
const opts        = program.opts();
const MODEL       = opts.model || "llama3.2";
const OLLAMA_URL  = "http://localhost:11434";

// ── Helpers ───────────────────────────────────────────────────────────────────

function normaliseUrl(raw) {
  if (!raw.startsWith("http://") && !raw.startsWith("https://")) raw = "https://" + raw;
  return new URL(raw).href;
}

function severityColor(sev) {
  switch (sev) {
    case "CRITICAL": return chalk.bgRed.white.bold;
    case "HIGH":     return chalk.red.bold;
    case "MEDIUM":   return chalk.yellow.bold;
    case "LOW":      return chalk.green.bold;
    default:         return chalk.gray;
  }
}

function cvssColor(n) {
  n = parseFloat(n);
  if (n >= 9.0) return chalk.bgRed.white;
  if (n >= 7.0) return chalk.red;
  if (n >= 4.0) return chalk.yellow;
  return chalk.green;
}

function wordWrap(text, width, indent) {
  const words = text.split(" ");
  const lines = [];
  let line = indent;
  for (const word of words) {
    if (line.length + word.length + 1 > width) { lines.push(line); line = indent + word; }
    else line += (line === indent ? "" : " ") + word;
  }
  if (line.trim()) lines.push(line);
  return lines.join("\n");
}

function banner() {
  if (opts.quiet) return;
  console.log(chalk.cyan(`
  ██████╗███╗   ██╗██████╗  ██████╗ ██████╗
 ██╔════╝████╗  ██║██╔══██╗██╔════╝██╔═══██╗
 ██║     ██╔██╗ ██║██████╔╝██║     ██║   ██║
 ██║     ██║╚██╗██║██╔══██╗██║     ██║   ██║
 ╚██████╗██║ ╚████║██║  ██║╚██████╗╚██████╔╝
  ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝`));
  console.log(chalk.gray("  OWASP Top 10 Security Scanner  ·  v1.0  ·  cnrco.nl"));
  console.log(chalk.gray(`  Model: ${MODEL}  ·  Engine: Ollama (local)\n`));
}

// ── Ollama check ──────────────────────────────────────────────────────────────

async function checkOllama() {
  try {
    const res  = await fetch(`${OLLAMA_URL}/api/tags`);
    if (!res.ok) throw new Error();
    const data   = await res.json();
    const models = (data.models || []).map(m => m.name);
    const match  = models.find(m => m.startsWith(MODEL));

    if (!match) {
      console.error(chalk.red(`\n  ✗ Model "${MODEL}" not found in Ollama.\n`));
      console.error(chalk.gray("  Pull it with:"));
      console.error(chalk.cyan(`    ollama pull ${MODEL}\n`));
      if (models.length > 0) {
        console.error(chalk.gray("  Models already on your machine:"));
        models.forEach(m => console.error(chalk.gray(`    · ${m}`)));
      } else {
        console.error(chalk.gray("  No models yet. Run: ollama pull llama3.2"));
      }
      console.log();
      process.exit(1);
    }

    return match;
  } catch(e) {
    if (e.cause?.code === "ECONNREFUSED") {
      console.error(chalk.red("\n  ✗ Ollama is not running.\n"));
      console.error(chalk.gray("  Start it in a separate terminal tab:"));
      console.error(chalk.cyan("    ollama serve\n"));
    } else {
      console.error(chalk.red(`\n  ✗ Could not reach Ollama: ${e.message}\n`));
    }
    console.log();
    process.exit(1);
  }
}

// ── Ollama call (streaming) ───────────────────────────────────────────────────

async function callOllama(model, prompt, spinner) {
  const res = await fetch(`${OLLAMA_URL}/api/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      prompt,
      stream: true,
      options: { temperature: 0.2, num_predict: 4096 },
    }),
  });

  if (!res.ok) throw new Error(`Ollama error ${res.status}: ${await res.text()}`);

  let fullText = "";
  const reader  = res.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const lines = decoder.decode(value, { stream: true }).split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.response) {
          fullText += obj.response;
          if (fullText.length % 300 < 5)
            spinner.text = chalk.gray(`Generating report... (${fullText.length} chars)`);
        }
      } catch(e) {}
    }
  }

  return fullText;
}

// ── Passive recon (real HTTP fetch) ──────────────────────────────────────────

async function gatherRecon(target) {
  const r = {
    headers: {}, statusCode: null, tlsInfo: null,
    server: null, poweredBy: null,
    cspPresent: false, hstsPresent: false, xfoPresent: false,
    xctoPresent: false, referrerPolicy: null, permissionsPolicy: null,
    cookies: [], error: null,
  };

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(target, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "CNRCO-SecurityScanner/1.0 (passive-recon)" },
    });

    clearTimeout(timeout);
    r.statusCode = res.status;
    res.headers.forEach((v, k) => { r.headers[k] = v; });

    r.server             = res.headers.get("server")                  || null;
    r.poweredBy          = res.headers.get("x-powered-by")            || null;
    r.cspPresent         = !!res.headers.get("content-security-policy");
    r.hstsPresent        = !!res.headers.get("strict-transport-security");
    r.xfoPresent         = !!res.headers.get("x-frame-options");
    r.xctoPresent        = !!res.headers.get("x-content-type-options");
    r.referrerPolicy     = res.headers.get("referrer-policy")         || null;
    r.permissionsPolicy  = res.headers.get("permissions-policy")      || null;
    r.tlsInfo            = target.startsWith("https://")
      ? "HTTPS in use" : "HTTP only — no TLS detected";

    const sc = res.headers.get("set-cookie");
    if (sc) r.cookies = sc.split(",").map(c => c.trim());

  } catch(e) {
    r.error = e.message;
  }

  return r;
}

// ── Terminal output ───────────────────────────────────────────────────────────

function printSummary(findings, summary, attackSurface, target) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  let overall, overallFn;
  if      (counts.CRITICAL > 0) { overall = "CRITICAL RISK"; overallFn = chalk.bgRed.white.bold; }
  else if (counts.HIGH     > 0) { overall = "HIGH RISK";     overallFn = chalk.red.bold; }
  else if (counts.MEDIUM   > 0) { overall = "MEDIUM RISK";   overallFn = chalk.yellow.bold; }
  else                           { overall = "LOW RISK";      overallFn = chalk.green.bold; }

  let hostname = target;
  try { hostname = new URL(target).hostname; } catch(e) {}

  console.log();
  console.log(chalk.cyan("  ┌─────────────────────────────────────────────────────────────────────┐"));
  console.log(chalk.cyan("  │") + chalk.white.bold("  AUDIT REPORT SUMMARY") + " ".repeat(49) + chalk.cyan("│"));
  console.log(chalk.cyan("  ├─────────────────────────────────────────────────────────────────────┤"));
  console.log(chalk.cyan("  │") + chalk.gray(`  Target : ${hostname}`) + " ".repeat(Math.max(0, 59 - hostname.length)) + chalk.cyan("│"));
  console.log(chalk.cyan("  │") + chalk.gray(`  Date   : ${new Date().toISOString().slice(0,19)} UTC`) + " ".repeat(23) + chalk.cyan("│"));
  console.log(chalk.cyan("  │") + chalk.gray(`  By     : CNRCO Web Application Security`) + " ".repeat(29) + chalk.cyan("│"));
  console.log(chalk.cyan("  ├─────────────────────────────────────────────────────────────────────┤"));
  console.log(chalk.cyan("  │") + `  Overall Risk: ${overallFn(" " + overall + " ")}` + " ".repeat(Math.max(0, 52 - overall.length)) + chalk.cyan("│"));
  console.log(chalk.cyan("  ├─────────────────────────────────────────────────────────────────────┤"));
  console.log(chalk.cyan("  │") + chalk.gray("  Findings:") + " ".repeat(60) + chalk.cyan("│"));
  console.log(chalk.cyan("  │") + `    ${chalk.bgRed.white(" CRITICAL ")} ${String(counts.CRITICAL).padEnd(3)}  ${chalk.red("HIGH")}    ${String(counts.HIGH).padEnd(3)}  ${chalk.yellow("MEDIUM")}  ${String(counts.MEDIUM).padEnd(3)}  ${chalk.green("LOW/INFO")}  ${counts.LOW + (counts.INFO||0)}` + " ".repeat(10) + chalk.cyan("│"));
  console.log(chalk.cyan("  └─────────────────────────────────────────────────────────────────────┘"));

  if (summary) {
    console.log();
    console.log(chalk.cyan("  EXECUTIVE SUMMARY"));
    console.log(chalk.gray("  " + "─".repeat(72)));
    console.log(chalk.gray(wordWrap(summary, 80, "  ")));
  }
  if (attackSurface) {
    console.log();
    console.log(chalk.cyan("  ATTACK SURFACE"));
    console.log(chalk.gray("  " + "─".repeat(72)));
    console.log(chalk.gray(wordWrap(attackSurface, 80, "  ")));
  }
}

function printFinding(f, index) {
  const sev   = f.severity || "INFO";
  const sevFn = severityColor(sev);

  console.log();
  console.log(
    chalk.gray(`  [${String(index + 1).padStart(2, "0")}]`) + " " +
    sevFn(` ${sev} `) + " " +
    chalk.white.bold(f.title || "Untitled finding")
  );
  if (f.owasp) console.log(chalk.gray(`       OWASP: ${f.owasp}`));
  if (f.cvss !== undefined) {
    console.log(chalk.gray("       CVSS:  ") + cvssColor(f.cvss)(parseFloat(f.cvss).toFixed(1)));
    if (f.cvssVector) console.log(chalk.gray(`       Vector: ${f.cvssVector}`));
  }
  if (f.description) {
    console.log();
    console.log(chalk.gray(wordWrap(f.description, 80, "       ")));
  }
  if (f.evidence) {
    console.log();
    console.log(chalk.gray("       " + chalk.dim("Evidence:")));
    f.evidence.split("\n").slice(0, 8).forEach(l =>
      console.log(chalk.gray("         ") + chalk.dim.cyan(l))
    );
  }
  if (f.remediation) {
    console.log();
    console.log(chalk.gray("       " + chalk.dim("Remediation:")));
    console.log(chalk.green.dim(wordWrap(f.remediation, 80, "         ")));
  }
  if (f.references) {
    console.log();
    console.log(chalk.gray("       " + chalk.dim("References: ") + chalk.blue.dim(f.references)));
  }
  console.log();
  console.log(chalk.gray("  " + "─".repeat(72)));
}

// ── Markdown export ───────────────────────────────────────────────────────────

function buildMarkdown(findings, summary, attackSurface, target) {
  let hostname = target;
  try { hostname = new URL(target).hostname; } catch(e) {}
  const date = new Date().toISOString().slice(0,10);

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  const sevOrder = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
  const sorted   = [...findings].sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));

  const OWASP_CATS = [
    ["A01:2021","Broken Access Control"],["A02:2021","Cryptographic Failures"],
    ["A03:2021","Injection"],["A04:2021","Insecure Design"],
    ["A05:2021","Security Misconfiguration"],["A06:2021","Vulnerable & Outdated Components"],
    ["A07:2021","Identification & Authentication Failures"],
    ["A08:2021","Software & Data Integrity Failures"],
    ["A09:2021","Security Logging & Monitoring Failures"],
    ["A10:2021","Server-Side Request Forgery (SSRF)"],
  ];
  const covered = {};
  findings.forEach(f => { if (f.owasp) covered[f.owasp] = f.severity; });

  let md = `# CNRCO Security Audit Report\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Target** | ${target} |\n| **Date** | ${date} |\n`;
  md += `| **Conducted by** | CNRCO Web Application Security |\n`;
  md += `| **Methodology** | Passive OWASP Top 10:2021 Assessment |\n\n---\n\n`;
  md += `## Risk Summary\n\n| Critical | High | Medium | Low/Info |\n|---|---|---|---|\n`;
  md += `| ${counts.CRITICAL} | ${counts.HIGH} | ${counts.MEDIUM} | ${counts.LOW + (counts.INFO||0)} |\n\n`;
  if (summary)       md += `## Executive Summary\n\n${summary}\n\n`;
  if (attackSurface) md += `## Attack Surface\n\n${attackSurface}\n\n`;
  md += `## Findings\n\n`;

  sorted.forEach((f, i) => {
    md += `### ${i+1}. ${f.title}\n\n| Field | Value |\n|---|---|\n`;
    md += `| **Severity** | ${f.severity} |\n| **OWASP** | ${f.owasp || "N/A"} |\n`;
    if (f.cvss !== undefined) md += `| **CVSS Score** | ${parseFloat(f.cvss).toFixed(1)} |\n`;
    if (f.cvssVector)         md += `| **CVSS Vector** | \`${f.cvssVector}\` |\n`;
    md += `\n**Description:**\n${f.description}\n\n`;
    if (f.evidence)   md += `**Evidence:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
    md += `**Remediation:**\n${f.remediation}\n\n`;
    if (f.references) md += `**References:**\n${f.references}\n\n`;
    md += `---\n\n`;
  });

  md += `## OWASP Top 10:2021 Coverage\n\n| ID | Category | Status |\n|---|---|---|\n`;
  OWASP_CATS.forEach(([id, name]) => {
    md += `| ${id} | ${name} | ${covered[id] || "Not flagged"} |\n`;
  });

  md += `\n---\n\n*Generated by CNRCO Security Scanner. Passive reconnaissance only. `;
  md += `A manual penetration test is recommended to confirm all findings.*\n`;
  return md;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  banner();

  if (!targetArg) { program.help(); }

  let target;
  try { target = normaliseUrl(targetArg); }
  catch(e) { console.error(chalk.red(`\n  ✗ Invalid URL: ${targetArg}\n`)); process.exit(1); }

  // Check Ollama is up and model exists
  const resolvedModel = await checkOllama();

  if (!opts.quiet) {
    console.log(chalk.gray(`  Target : `) + chalk.white(target));
    console.log(chalk.gray(`  Model  : `) + chalk.white(resolvedModel));
    console.log(chalk.gray(`  Scope  : OWASP Top 10:2021 — full passive assessment`));
    console.log();
  }

  const spinner = ora({ text: chalk.gray("Fetching target headers..."), color: "cyan", spinner: "dots" }).start();

  // Step 1: real passive recon
  const recon = await gatherRecon(target);

  const reconSummary = `
HTTP Status      : ${recon.statusCode || "unreachable"} ${recon.error ? `(error: ${recon.error})` : ""}
TLS              : ${recon.tlsInfo || "unknown"}
Server           : ${recon.server || "not disclosed"}
X-Powered-By     : ${recon.poweredBy || "not disclosed"}
Security Headers :
  Content-Security-Policy   : ${recon.cspPresent     ? "PRESENT — " + (recon.headers["content-security-policy"] || "") : "MISSING"}
  Strict-Transport-Security : ${recon.hstsPresent     ? "PRESENT — " + (recon.headers["strict-transport-security"] || "") : "MISSING"}
  X-Frame-Options           : ${recon.xfoPresent      ? "PRESENT — " + (recon.headers["x-frame-options"] || "") : "MISSING"}
  X-Content-Type-Options    : ${recon.xctoPresent     ? "PRESENT — " + (recon.headers["x-content-type-options"] || "") : "MISSING"}
  Referrer-Policy           : ${recon.referrerPolicy  || "MISSING"}
  Permissions-Policy        : ${recon.permissionsPolicy || "MISSING"}
All Headers      : ${JSON.stringify(recon.headers, null, 2)}
Cookies          : ${recon.cookies.length > 0 ? recon.cookies.join(" | ") : "none observed"}
  `.trim();

  spinner.text = chalk.gray("Running AI analysis...");

  // Step 2: AI analysis
  const prompt = `You are an expert web application security analyst. Perform a comprehensive OWASP Top 10:2021 security assessment based on the passive reconnaissance data below.

TARGET: ${target}
TIMESTAMP: ${new Date().toISOString()}

RECON DATA:
${reconSummary}

Analyse every OWASP Top 10:2021 category:
A01 Broken Access Control | A02 Cryptographic Failures | A03 Injection | A04 Insecure Design | A05 Security Misconfiguration | A06 Vulnerable & Outdated Components | A07 Identification & Authentication Failures | A08 Software & Data Integrity Failures | A09 Security Logging & Monitoring Failures | A10 SSRF

Respond ONLY with a valid JSON object. No markdown fences. No text before or after the JSON:

{
  "findings": [
    {
      "title": "concise technical title",
      "severity": "CRITICAL or HIGH or MEDIUM or LOW or INFO",
      "owasp": "A0X:2021",
      "cvss": 7.5,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "description": "detailed technical description of the issue and its impact on this target",
      "evidence": "exact evidence from the recon data above",
      "remediation": "specific actionable remediation steps",
      "references": "CWE-XXX, OWASP links, or real CVEs only"
    }
  ],
  "summary": "2-3 sentence executive summary of the overall security posture",
  "attackSurface": "brief description of the observed attack surface and entry points"
}

Base every finding strictly on the recon data provided. Produce 6-12 findings across multiple severity levels.`;

  try {
    const raw = await callOllama(resolvedModel, prompt, spinner);
    spinner.succeed(chalk.green("Analysis complete."));

    const cleaned = raw.replace(/```json|```/g, "").trim();
    const start   = cleaned.indexOf("{");
    const end     = cleaned.lastIndexOf("}");
    if (start === -1) throw new Error("Model did not return valid JSON. Try running again or use a larger model.");

    const parsed        = JSON.parse(cleaned.slice(start, end + 1));
    const findings      = parsed.findings      || [];
    const summary       = parsed.summary       || "";
    const attackSurface = parsed.attackSurface || "";

    const sevOrder = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
    findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));

    printSummary(findings, summary, attackSurface, target);
    console.log();
    console.log(chalk.cyan("  FINDINGS"));
    console.log(chalk.gray("  " + "─".repeat(72)));
    findings.forEach((f, i) => printFinding(f, i));

    console.log();
    console.log(chalk.gray("  ⚠  Disclaimer: Passive assessment only. Confirm findings with a manual pentest."));
    console.log(chalk.gray("     Only audit systems you own or have explicit written authorisation to test."));
    console.log();

    if (opts.output) {
      const md = buildMarkdown(findings, summary, attackSurface, target);
      fs.writeFileSync(path.resolve(opts.output), md, "utf8");
      console.log(chalk.green(`  ✓ Markdown report saved: ${path.resolve(opts.output)}`));
    }

    if (opts.json) {
      fs.writeFileSync(path.resolve(opts.json), JSON.stringify(parsed, null, 2), "utf8");
      console.log(chalk.green(`  ✓ JSON findings saved:   ${path.resolve(opts.json)}`));
    }

    console.log();

  } catch(err) {
    spinner.fail(chalk.red("Analysis failed."));
    console.error(chalk.red(`\n  ✗ ${err.message}\n`));
    if (err.message.includes("JSON")) {
      console.error(chalk.gray("  Try a larger model for better JSON output:"));
      console.error(chalk.cyan("    ollama pull llama3.1:8b"));
      console.error(chalk.cyan("    node scan.js <url> --model llama3.1:8b\n"));
    }
    process.exit(1);
  }
}

main();
