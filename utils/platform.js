// Operating-system family of an NVD platform criteria (CPE 2.3), when it names a known OS.

const LINUX_VENDORS = new Set(['debian', 'canonical', 'redhat', 'fedoraproject', 'suse', 'opensuse', 'centos', 'rockylinux', 'almalinux']);
const MACOS_PRODUCTS = new Set(['mac_os_x', 'macos', 'mac_os']);

function familyOf(vendor, product) {
	if (vendor === 'microsoft' && product.startsWith('windows')) return 'windows';
	if ((vendor === 'linux' && product === 'linux_kernel') || LINUX_VENDORS.has(vendor) || (vendor === 'oracle' && product === 'linux')) return 'linux';
	if (vendor === 'apple' && MACOS_PRODUCTS.has(product)) return 'macos';
}

// 'windows' | 'linux' | 'macos' | undefined (application, hardware or unknown OS).
export function osFamilyOfCriteria(criteria) {
	const fields = String(criteria).split(':');
	if (fields[2] !== 'o') return;
	return familyOf(fields[3], fields[4] ?? '');
}

// Can a CVE requiring one of `platforms` apply to a machine of `osFamily`? Only a certain "no":
// every platform maps to a known family and none is the machine's. Unknown stays possible.
export function platformsMayApply(platforms, osFamily) {
	if (!osFamily) return true;
	const families = new Set(platforms.map(criteria => osFamilyOfCriteria(criteria)));
	return families.has(undefined) || families.has(osFamily);
}
