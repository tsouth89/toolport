/**
 * Most MCP clients only read their config at startup (Claude Desktop especially).
 * After Toolport writes a gateway entry, a success toast that only says "Connected"
 * leaves the user thinking the product is broken until they happen to restart
 * (SOU-317). Universal wording: a restart never hurts clients that hot-reload.
 */
export function clientRestartHint(clientName: string): string {
  return `Restart ${clientName} so it loads Toolport.`;
}

/** Connect/rescope toast body: restart first, then optional scope/backup notes. */
export function connectSuccessDescription(
  clientName: string,
  extras: Array<string | undefined | null | false> = [],
): string {
  return [clientRestartHint(clientName), ...extras.filter(Boolean)].join(" ");
}
