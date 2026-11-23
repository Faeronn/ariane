-- Modification date of the OSV record stored for each OSV id: a record OSV corrects later
-- (score, summary, ranges) is fetched again when querybatch reports a newer date.
ALTER TABLE `osv_alias` ADD COLUMN IF NOT EXISTS `modified` datetime NULL DEFAULT NULL;
