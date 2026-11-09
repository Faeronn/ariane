-- A known product (alias) whose exact version is missing from the NVD CPE dictionary gets a
-- synthetic CPE name, synced through the CVE API virtualMatchString instead of cpeName.
ALTER TABLE `software_cpe` ADD COLUMN IF NOT EXISTS `cpeSynthetic` tinyint(1) NOT NULL DEFAULT 0 AFTER `cpeName`;
