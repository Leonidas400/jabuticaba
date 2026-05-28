export function isBackup(configText, vendor) {
  const raw = (configText || "");
  const t   = raw.replace(/^\uFEFF/, '').trimStart();
  const low = t.toLowerCase();
  const v   = (vendor || '').toLowerCase();

  if (v === 'pfsense') {
    const hasRoot    = /<\s*(pfsense|m0n0wall)\b[^>]*>/i.test(t);
    const hasSection = /<\s*(interfaces|filter|system|vlans|nat)\b/i.test(t);
    const hasXmlDecl = /^\s*<\?xml\b/i.test(t);
    return hasRoot || (hasXmlDecl && hasSection);
  }

  if (v === 'fortigate') {
    return (
      /^\s*config\s+system\s+global\b/im.test(low) ||
      /^\s*config\s+firewall\s+policy\b/im.test(low) ||
      /#config-version=FGT/i.test(t) ||
      /^\s*end\s*$/im.test(low)
    );
  }

  return /^\s*config\s+\w+/im.test(low);
}