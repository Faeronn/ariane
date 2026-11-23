-- Alias fixes from the real-app validation (2026-11-23). Each new product was probed in the NVD
-- CPE dictionary first (cpeMatchString=cpe:2.3:a:<vendor>:<product>).

-- Windows builds carry extra version parts the NVD does not use (.NET 8.0.21.35325 => 8.0.21,
-- Git for Windows 2.55.0.3 => 2.55.0): an alias may keep only the first N parts (NULL keeps all).
ALTER TABLE `software_alias` ADD COLUMN IF NOT EXISTS `versionParts` tinyint NULL DEFAULT NULL AFTER `cpeProduct`;
UPDATE `software_alias` SET `versionParts` = 3 WHERE `namePattern` IN ('git', 'git version%');

-- "Microsoft Teams Meeting Add-in for Microsoft Office" is not Teams: only the Teams client names.
-- The unique index treats NULL vendorPattern values as distinct, so INSERT IGNORE alone would
-- duplicate these rows on a re-run: they are deleted first.
DELETE FROM `software_alias` WHERE `vendorPattern` IS NULL AND `namePattern` IN ('microsoft teams%', 'microsoft teams', 'microsoft teams classic%',
  'gpl ghostscript%', 'mariadb %', 'microsoft windows desktop runtime%', 'microsoft asp.net core%', 'firefox developer edition%', 'mailpit%');
INSERT INTO `software_alias` (`namePattern`, `cpeVendor`, `cpeProduct`, `versionParts`) VALUES
  ('microsoft teams', 'microsoft', 'teams', NULL),
  ('microsoft teams classic%', 'microsoft', 'teams', NULL),
  ('gpl ghostscript%', 'artifex', 'ghostscript', NULL),
  ('mariadb %', 'mariadb', 'mariadb', 3),
  ('microsoft windows desktop runtime%', 'microsoft', '.net', 3),
  ('microsoft asp.net core%', 'microsoft', 'asp.net_core', 3),
  ('firefox developer edition%', 'mozilla', 'firefox', NULL),
  ('mailpit%', 'axllent', 'mailpit', NULL);
-- Microsoft 365 Apps get no alias: the NVD dictionary only lists them with version "-".

-- Keys resolved before these changes are resolved again.
UPDATE `software_cpe`
  SET `status` = 'pending', `cpeName` = NULL, `cpeSynthetic` = 0, `versionNormalized` = 0, `cvesCheckedAt` = NULL
  WHERE `name` LIKE 'microsoft teams%' OR `name` = 'git' OR `name` LIKE 'git version%' OR `name` LIKE 'gpl ghostscript%'
    OR `name` LIKE 'mariadb %' OR `name` LIKE 'microsoft windows desktop runtime%' OR `name` LIKE 'microsoft asp.net core%'
    OR `name` LIKE 'firefox developer edition%' OR `name` LIKE 'mailpit%';
