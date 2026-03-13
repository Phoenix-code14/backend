/**
 * CSPhoenix – Domain Intelligence
 * scanners/domainIntel.js
 */

'use strict';

const dns = require('dns').promises;

async function getDomainIntel(domain) {
  const results = {
    domain,
    timestamp: new Date().toISOString(),
    dnsRecords: [],
    subdomains: [],
    ip: null,
    provider: 'Unknown',
    domainAge: 'Unknown'
  };

  try {
    // A records
    const aRecords = await dns.resolve4(domain).catch(() => []);
    if (aRecords.length > 0) {
      results.ip = aRecords[0];
      aRecords.forEach(ip => results.dnsRecords.push({ type: 'A', value: ip }));
    }

    // AAAA records
    const aaaaRecords = await dns.resolve6(domain).catch(() => []);
    aaaaRecords.forEach(ip => results.dnsRecords.push({ type: 'AAAA', value: ip }));

    // MX records
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    mxRecords.forEach(mx => results.dnsRecords.push({ type: 'MX', value: `${mx.exchange} (priority: ${mx.priority})` }));

    // NS records
    const nsRecords = await dns.resolveNs(domain).catch(() => []);
    nsRecords.forEach(ns => results.dnsRecords.push({ type: 'NS', value: ns }));

    // TXT records
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    txtRecords.forEach(txt => results.dnsRecords.push({ type: 'TXT', value: txt.join(' ') }));

    // Common subdomains
    const prefixes = ['www', 'mail', 'ftp', 'api', 'staging', 'dev', 'admin', 'cdn', 'blog'];
    for (const prefix of prefixes) {
      try {
        await dns.resolve4(`${prefix}.${domain}`);
        results.subdomains.push(`${prefix}.${domain}`);
      } catch {}
    }

    // Estimate provider from NS
    if (nsRecords.some(ns => ns.includes('cloudflare'))) results.provider = 'Cloudflare';
    else if (nsRecords.some(ns => ns.includes('amazonaws'))) results.provider = 'Amazon Web Services';
    else if (nsRecords.some(ns => ns.includes('google'))) results.provider = 'Google Cloud';
    else if (nsRecords.length > 0) results.provider = nsRecords[0].split('.').slice(-2).join('.');

  } catch (err) {
    console.warn('[domain-intel error]', err.message);
  }

  return results;
}

module.exports = { getDomainIntel };
