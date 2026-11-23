-- One software key per (vendor, name, version, ecosystem): a program, an npm package and a PyPI
-- package called the same no longer share a key. '' marks installed programs; NULL is avoided
-- because a unique index treats NULLs as distinct and would let program keys duplicate.
UPDATE `software_cpe` SET `ecosystem` = '' WHERE `ecosystem` IS NULL;
ALTER TABLE `software_cpe` MODIFY `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '';
ALTER TABLE `software_cpe` DROP INDEX IF EXISTS `uniq_software`;
ALTER TABLE `software_cpe` ADD UNIQUE INDEX IF NOT EXISTS `uniq_software_ecosystem`(`vendor`, `name`, `version`, `ecosystem`);
