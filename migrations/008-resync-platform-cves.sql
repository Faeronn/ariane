-- CVE links now honor the OS a vulnerable criterion targets (target_sw, e.g. Teams for iPhone):
-- every matched CPE is synced again at the next sync-cves tick to rebuild its links.
UPDATE `software_cpe` SET `cvesCheckedAt` = NULL WHERE `status` = 'matched';
