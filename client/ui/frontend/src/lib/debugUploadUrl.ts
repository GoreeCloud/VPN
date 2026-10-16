// An upload service is optional, never inherited from NetBird's hosted platform.
// This is a build-time operator setting, not a discovery mechanism or a user consent flag.
const inheritedDomains = ["netbird.io", "wiretrustee.com", "netbird.cloud"];

export function resolveDebugUploadUrl(candidate: unknown): string {
    if (typeof candidate !== "string" || !candidate.trim()) return "";

    try {
        const url = new URL(candidate.trim());
        const hostname = url.hostname.toLowerCase();

        if (
            url.protocol !== "https:" ||
            !hostname ||
            url.username ||
            url.password ||
            url.hash ||
            inheritedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))
        ) {
            return "";
        }
        return url.toString();
    } catch {
        return "";
    }
}
