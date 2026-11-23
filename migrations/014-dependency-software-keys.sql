-- Direct dependencies of applications are also resolved to a CPE (NVD, the second source next to
-- OSV): their software keys remember the ecosystem and the package name they come from.
-- NULL for installed programs.
ALTER TABLE `software_cpe`
  ADD COLUMN IF NOT EXISTS `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `packageName` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  ADD INDEX IF NOT EXISTS `idx_package`(`ecosystem`, `packageName`, `version`);
